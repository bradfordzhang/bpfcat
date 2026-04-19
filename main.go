package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

var (
	nextIndex       uint32
	activeEbpfConns int32
	activeUserConns int32
	manualBytes     uint64
)

// parseAddr parses a string and returns the network type and formatted address.
func parseAddr(s string) (network, addr string) {
	if strings.HasPrefix(s, "unix:") {
		return "unix", strings.TrimPrefix(s, "unix:")
	}
	if strings.HasPrefix(s, "tcp:") {
		return "tcp", strings.TrimPrefix(s, "tcp:")
	}
	if strings.HasPrefix(s, "udp:") {
		return "udp", strings.TrimPrefix(s, "udp:")
	}
	if !strings.Contains(s, ":") && !strings.Contains(s, "/") {
		return "tcp", ":" + s
	}
	if strings.Contains(s, "/") {
		return "unix", s
	}
	return "tcp", s
}

func main() {
	var ifaceName string
	var blocklistStr string
	flag.StringVar(&ifaceName, "i", "", "Network interface for XDP attachment (e.g., eth0)")
	flag.StringVar(&blocklistStr, "b", "", "Comma-separated list of IPv4 CIDRs to blacklist (e.g., 1.2.3.4/32,10.0.0.0/8)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Printf("Usage: %s [flags] <listen-addr> <dial-addr>\n", os.Args[0])
		fmt.Printf("Flags:\n")
		flag.PrintDefaults()
		fmt.Printf("\nExamples:\n")
		fmt.Printf("  %s 8888 127.0.0.1:8080\n", os.Args[0])
		fmt.Printf("  %s -i eth0 -b 10.0.0.0/8 8888 127.0.0.1:8080\n", os.Args[0])
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	listenStr := args[0]
	dialStr := args[1]

	listenNet, listenAddr := parseAddr(listenStr)
	dialNet, dialAddr := parseAddr(dialStr)

	if listenNet == "unix" {
		os.Remove(listenAddr)
	}

	objs := bpfcatObjects{}
	if err := loadBpfcatObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	if listenNet == "tcp" || listenNet == "udp" {
		_, portStr, err := net.SplitHostPort(listenAddr)
		if err == nil {
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err == nil {
				var key uint32 = 0
				val := uint16(port)
				if err := objs.BpfcatConfig.Update(key, val, ebpf.UpdateAny); err != nil {
					log.Printf("Warning: failed to set listening port in eBPF config map: %v", err)
				} else {
					fmt.Printf("XDP ACL configured to protect port %d\n", val)
				}
			}
		} else {
			// Try to parse just the port directly if SplitHostPort fails (e.g. if listenAddr is just "8888")
			port, err := strconv.ParseUint(listenAddr, 10, 16)
			if err == nil {
				var key uint32 = 0
				val := uint16(port)
				if err := objs.BpfcatConfig.Update(key, val, ebpf.UpdateAny); err != nil {
					log.Printf("Warning: failed to set listening port in eBPF config map: %v", err)
				} else {
					fmt.Printf("XDP ACL configured to protect port %d\n", val)
				}
			}
		}
	}

	if blocklistStr != "" {
		cidrs := strings.Split(blocklistStr, ",")
		for _, cidrStr := range cidrs {
			cidrStr = strings.TrimSpace(cidrStr)
			if cidrStr == "" {
				continue
			}
			if !strings.Contains(cidrStr, "/") {
				cidrStr += "/32"
			}
			_, ipNet, err := net.ParseCIDR(cidrStr)
			if err != nil {
				log.Fatalf("Invalid CIDR %q: %v", cidrStr, err)
			}

			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				log.Fatalf("Only IPv4 blocklists are supported currently: %q", cidrStr)
			}

			ones, _ := ipNet.Mask.Size()

			ipData := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24

			key := bpfcatIpv4LpmKey{
				Prefixlen: uint32(ones),
				Data:      ipData,
			}

			var dropVal uint8 = 1
			if err := objs.AclMap.Update(key, dropVal, ebpf.UpdateAny); err != nil {
				log.Fatalf("Failed to add %q to ACL map: %v", cidrStr, err)
			}
			fmt.Printf("Added %s to XDP drop list\n", cidrStr)
		}
	}

	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("Interface %q not found: %v", ifaceName, err)
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.BpfcatXdp,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("Attaching XDP program: %v", err)
		}
		defer l.Close()
		fmt.Printf("Attached XDP ACL program to %s\n", ifaceName)
	}

	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockMap.FD(),
		Program: objs.BpfcatVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	}); err != nil {
		log.Fatalf("Attaching program to map: %v", err)
	}

	go statsLoop(&objs)

	// Setup graceful shutdown to trigger defers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nReceived termination signal, shutting down gracefully...")
		cancel()
	}()

	if listenNet == "udp" {
		listenUDP(ctx, listenAddr, dialNet, dialAddr, &objs)
	} else {
		ln, err := net.Listen(listenNet, listenAddr)
		if err != nil {
			log.Fatalf("Listen (%s): %v", listenNet, err)
		}

		go func() {
			<-ctx.Done()
			ln.Close()
		}()

		fmt.Printf("bpfcat (Multi-Protocol) listening on %s://%s, forwarding to %s://%s\n", listenNet, listenAddr, dialNet, dialAddr)

		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					// Expected error on shutdown
					break
				}
				log.Printf("Accept error: %v", err)
				continue
			}
			go handleConn(conn, dialNet, dialAddr, &objs)
		}
	}
}

func listenUDP(ctx context.Context, listenAddr, dialNet, dialAddr string, objs *bpfcatObjects) {
	if !strings.Contains(listenAddr, ":") {
		listenAddr = ":" + listenAddr
	}
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("Resolve UDP addr: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Listen UDP: %v", err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	fmt.Printf("bpfcat (UDP) listening on udp://%s, forwarding to %s://%s\n", listenAddr, dialNet, dialAddr)

	type session struct {
		remoteConn net.Conn
	}
	sessions := make(map[string]*session)
	var mu sync.Mutex

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("Read from UDP error: %v", err)
			continue
		}

		mu.Lock()
		s, ok := sessions[srcAddr.String()]
		if !ok {
			remoteConn, err := net.Dial(dialNet, dialAddr)
			if err != nil {
				log.Printf("Dial remote error: %v", err)
				mu.Unlock()
				continue
			}
			s = &session{remoteConn: remoteConn}
			sessions[srcAddr.String()] = s

			go func(src *net.UDPAddr, rConn net.Conn) {
				defer func() {
					mu.Lock()
					delete(sessions, src.String())
					mu.Unlock()
					rConn.Close()
				}()

				rBuf := make([]byte, 65535)
				for {
					rn, err := rConn.Read(rBuf)
					if err != nil {
						return
					}
					conn.WriteToUDP(rBuf[:rn], src)
					atomic.AddUint64(&manualBytes, uint64(rn))
				}
			}(srcAddr, remoteConn)
		}
		mu.Unlock()

		_, err = s.remoteConn.Write(buf[:n])
		if err != nil {
			log.Printf("Write to remote error: %v", err)
		}
		atomic.AddUint64(&manualBytes, uint64(n))
	}
}

func statsLoop(objs *bpfcatObjects) {
	var prevBytes, prevPackets uint64
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	fmt.Println("Stats: Monitoring throughput and QPS...")
	for range ticker.C {
		var bytesValues []uint64
		var packetsValues []uint64
		var aclDropValues []uint64

		if err := objs.Stats.Lookup(uint32(0), &bytesValues); err != nil {
			continue
		}
		if err := objs.Stats.Lookup(uint32(1), &packetsValues); err != nil {
			continue
		}

		// It's ok if this fails, ACL map might be empty or not attached if not using -b
		objs.AclStats.Lookup(uint32(0), &aclDropValues)

		var currentBytes, currentPackets, currentAclDrops uint64
		for _, v := range bytesValues {
			currentBytes += v
		}
		for _, v := range packetsValues {
			currentPackets += v
		}
		for _, v := range aclDropValues {
			currentAclDrops += v
		}
		currentBytes += atomic.LoadUint64(&manualBytes)

		diffBytes := currentBytes - prevBytes
		diffPackets := currentPackets - prevPackets
		mbps := float64(diffBytes) * 8 / 1024 / 1024

		fmt.Printf("\r[Stats] Throughput: %.2f Mbps | QPS: %d | Active: %d (eBPF: %d, User: %d) | ACL Drops: %d | Total: %s", 
			mbps, diffPackets, atomic.LoadInt32(&activeEbpfConns)+atomic.LoadInt32(&activeUserConns), 
			atomic.LoadInt32(&activeEbpfConns), atomic.LoadInt32(&activeUserConns), currentAclDrops, formatBytes(currentBytes))

		prevBytes = currentBytes
		prevPackets = currentPackets
	}
}
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

type closeWriter interface {
	CloseWrite() error
}

func handleConn(clientConn net.Conn, dialNet, dialAddr string, objs *bpfcatObjects) {
	defer clientConn.Close()

	destConn, err := net.Dial(dialNet, dialAddr)
	if err != nil {
		log.Printf("Dial error: %v", err)
		return
	}
	defer destConn.Close()

	listenNet := clientConn.LocalAddr().Network()
	if listenNet == "tcp" && dialNet == "tcp" {
		clientFD, err := getFD(clientConn)
		if err != nil {
			return
		}
		destFD, err := getFD(destConn)
		if err != nil {
			return
		}
		clientCookie, err := unix.GetsockoptUint64(clientFD, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			return
		}
		destCookie, err := unix.GetsockoptUint64(destFD, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			return
		}

		atomic.AddInt32(&activeEbpfConns, 1)
		defer atomic.AddInt32(&activeEbpfConns, -1)

		idxA := atomic.AddUint32(&nextIndex, 1) % 65535
		idxB := atomic.AddUint32(&nextIndex, 1) % 65535

		// Update SockMap FIRST, then lookup map. Order matters for race conditions.
		objs.SockMap.Update(idxA, uint32(clientFD), ebpf.UpdateAny)
		objs.SockMap.Update(idxB, uint32(destFD), ebpf.UpdateAny)
		objs.CookieToPeerIndex.Update(clientCookie, idxB, ebpf.UpdateAny)
		objs.CookieToPeerIndex.Update(destCookie, idxA, ebpf.UpdateAny)

		defer func() {
			objs.CookieToPeerIndex.Delete(clientCookie)
			objs.CookieToPeerIndex.Delete(destCookie)
			objs.SockMap.Delete(idxA)
			objs.SockMap.Delete(idxB)
		}()

		errChan := make(chan error, 1)
		go func() {
			buf := make([]byte, 1)
			_, err := clientConn.Read(buf)
			errChan <- err
		}()
		<-errChan
	} else {
		atomic.AddInt32(&activeUserConns, 1)
		defer atomic.AddInt32(&activeUserConns, -1)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			n, _ := io.Copy(destConn, clientConn)
			atomic.AddUint64(&manualBytes, uint64(n))
			if cw, ok := destConn.(closeWriter); ok {
				cw.CloseWrite()
			}
		}()
		go func() {
			defer wg.Done()
			n, _ := io.Copy(clientConn, destConn)
			atomic.AddUint64(&manualBytes, uint64(n))
			if cw, ok := clientConn.(closeWriter); ok {
				cw.CloseWrite()
			}
		}()
		wg.Wait()
	}
}

func getFD(conn net.Conn) (int, error) {
	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("connection does not support syscall.Conn")
	}
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd int
	var errControl error
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return 0, err
	}
	if errControl != nil {
		return 0, errControl
	}
	return fd, nil
}
