package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
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

var nextIndex uint32
var activeEbpfConns int32
var activeUserConns int32

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
	// Fallback to old behavior
	if !strings.Contains(s, ":") && !strings.Contains(s, "/") {
		return "tcp", ":" + s
	}
	if strings.Contains(s, "/") {
		return "unix", s
	}
	return "tcp", s
}

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <listen-addr> <dial-addr>\n", os.Args[0])
		fmt.Printf("Examples:\n")
		fmt.Printf("  %s 8888 127.0.0.1:8080\n", os.Args[0])
		fmt.Printf("  %s udp:9999 udp:127.0.0.1:9090\n", os.Args[0])
		fmt.Printf("  %s unix:/tmp/listen.sock unix:/tmp/dest.sock\n", os.Args[0])
		os.Exit(1)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	listenStr := os.Args[1]
	dialStr := os.Args[2]

	listenNet, listenAddr := parseAddr(listenStr)
	dialNet, dialAddr := parseAddr(dialStr)

	// Clean up stale unix sockets
	if listenNet == "unix" {
		os.Remove(listenAddr)
	}

	// Load eBPF objects
	objs := bpfcatObjects{}
	if err := loadBpfcatObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach program to map
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.SockMap.FD(),
		Program: objs.BpfcatVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	}); err != nil {
		log.Fatalf("Attaching program to map: %v", err)
	}

	// Start stats reporter
	go statsLoop(&objs)

	if listenNet == "udp" {
		listenUDP(listenAddr, dialNet, dialAddr, &objs)
	} else {
		ln, err := net.Listen(listenNet, listenAddr)
		if err != nil {
			log.Fatalf("Listen (%s): %v", listenNet, err)
		}
		defer ln.Close()

		fmt.Printf("bpfcat (Multi-Protocol) listening on %s://%s, forwarding to %s://%s\n", listenNet, listenAddr, dialNet, dialAddr)

		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			go handleConn(conn, dialNet, dialAddr, &objs)
		}
	}
}

func listenUDP(listenAddr, dialNet, dialAddr string, objs *bpfcatObjects) {
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

	fmt.Printf("bpfcat (UDP) listening on udp://%s, forwarding to %s://%s\n", listenAddr, dialNet, dialAddr)

	// Since UDP is connectionless, we use a map to track "sessions" from different clients
	type session struct {
		remoteConn net.Conn
		lastSeen   time.Time
	}
	sessions := make(map[string]*session)
	var mu sync.Mutex

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read from UDP error: %v", err)
			continue
		}

		mu.Lock()
		s, ok := sessions[srcAddr.String()]
		if !ok {
			// New UDP session
			remoteConn, err := net.Dial(dialNet, dialAddr)

			if err != nil {
				log.Printf("Dial remote error: %v", err)
				mu.Unlock()
				continue
			}
			s = &session{
				remoteConn: remoteConn,
				lastSeen:   time.Now(),
			}
			sessions[srcAddr.String()] = s

			// Go routine to handle responses from remote to local
			go func(src *net.UDPAddr, rConn net.Conn) {
				rBuf := make([]byte, 65535)
				for {
					rn, err := rConn.Read(rBuf)
					if err != nil {
						mu.Lock()
						delete(sessions, src.String())
						mu.Unlock()
						rConn.Close()
						return
					}
					conn.WriteToUDP(rBuf[:rn], src)
					atomic.AddUint64(&manualBytes, uint64(rn))
				}
			}(srcAddr, remoteConn)
		}
		s.lastSeen = time.Now()
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

		// Read total bytes (key 0)
		if err := objs.Stats.Lookup(uint32(0), &bytesValues); err != nil {
			log.Printf("Lookup bytes stats: %v", err)
			continue
		}
		// Read total packets (key 1)
		if err := objs.Stats.Lookup(uint32(1), &packetsValues); err != nil {
			log.Printf("Lookup packets stats: %v", err)
			continue
		}

		var currentBytes, currentPackets uint64
		for _, v := range bytesValues {
			currentBytes += v
		}
		for _, v := range packetsValues {
			currentPackets += v
		}
		// Add user-space manual copy stats
		currentBytes += atomic.LoadUint64(&manualBytes)

		diffBytes := currentBytes - prevBytes
		diffPackets := currentPackets - prevPackets
		
		// Basic units formatting
		mbps := float64(diffBytes) * 8 / 1024 / 1024
		
		fmt.Printf("\r[Stats] Throughput: %.2f Mbps | QPS: %d | Active: %d (eBPF: %d, User: %d) | Total: %s", 
			mbps, diffPackets, atomic.LoadInt32(&activeEbpfConns)+atomic.LoadInt32(&activeUserConns), 
			atomic.LoadInt32(&activeEbpfConns), atomic.LoadInt32(&activeUserConns), formatBytes(currentBytes))
		
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

func handleConn(clientConn net.Conn, dialNet, dialAddr string, objs *bpfcatObjects) {
	defer clientConn.Close()

	destConn, err := net.Dial(dialNet, dialAddr)
	if err != nil {
		log.Printf("Dial error: %v", err)
		return
	}
	defer destConn.Close()

	clientFD, err := getFD(clientConn)
	if err != nil {
		log.Printf("Get client FD error: %v", err)
		return
	}

	destFD, err := getFD(destConn)
	if err != nil {
		log.Printf("Get dest FD error: %v", err)
		return
	}

	clientCookie, err := unix.GetsockoptUint64(clientFD, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		log.Printf("Get client cookie error: %v", err)
		return
	}

	destCookie, err := unix.GetsockoptUint64(destFD, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		log.Printf("Get dest cookie error: %v", err)
		return
	}

	// Allocate two indices
	idxA := atomic.AddUint32(&nextIndex, 1) % 65535
	idxB := atomic.AddUint32(&nextIndex, 1) % 65535

	listenNet := clientConn.LocalAddr().Network()
	if listenNet == "tcp" && dialNet == "tcp" {
		// TCP to TCP: Use eBPF for zero-copy
		atomic.AddInt32(&activeEbpfConns, 1)
		defer atomic.AddInt32(&activeEbpfConns, -1)

		if err := objs.CookieToPeerIndex.Update(clientCookie, idxB, ebpf.UpdateAny); err != nil {
			log.Printf("Update client cookie mapping error: %v", err)
		}
		if err := objs.CookieToPeerIndex.Update(destCookie, idxA, ebpf.UpdateAny); err != nil {
			log.Printf("Update dest cookie mapping error: %v", err)
		}
		if err := objs.SockMap.Update(idxA, uint32(clientFD), ebpf.UpdateAny); err != nil {
			log.Printf("Update client sock_map error: %v", err)
		}
		if err := objs.SockMap.Update(idxB, uint32(destFD), ebpf.UpdateAny); err != nil {
			log.Printf("Update dest sock_map error: %v", err)
		}

		// Wait for closure
		errChan := make(chan error, 1)
		go func() {
			buf := make([]byte, 1)
			_, err := clientConn.Read(buf)
			errChan <- err
		}()
		<-errChan
	} else {
		// Cross-protocol or Unix: Use User-space copy as fallback
		atomic.AddInt32(&activeUserConns, 1)
		defer atomic.AddInt32(&activeUserConns, -1)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			n, _ := io.Copy(destConn, clientConn)
			atomic.AddUint64(&manualBytes, uint64(n))
			if c, ok := destConn.(*net.TCPConn); ok {
				c.CloseWrite()
			}
		}()
		go func() {
			defer wg.Done()
			n, _ := io.Copy(clientConn, destConn)
			atomic.AddUint64(&manualBytes, uint64(n))
			if c, ok := clientConn.(*net.TCPConn); ok {
				c.CloseWrite()
			}
		}()
		wg.Wait()
	}

	// Cleanup
	objs.CookieToPeerIndex.Delete(clientCookie)
	objs.CookieToPeerIndex.Delete(destCookie)
}

var manualBytes uint64

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
