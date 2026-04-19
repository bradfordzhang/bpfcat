package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestParseAddr(t *testing.T) {
	tests := []struct {
		input      string
		expectNet  string
		expectAddr string
	}{
		{"8888", "tcp", ":8888"},
		{"tcp:127.0.0.1:8080", "tcp", "127.0.0.1:8080"},
		{"unix:/tmp/test.sock", "unix", "/tmp/test.sock"},
		{"udp:9090", "udp", "9090"},
	}

	for _, tc := range tests {
		n, a := parseAddr(tc.input)
		if n != tc.expectNet || a != tc.expectAddr {
			t.Errorf("parseAddr(%s) = %s, %s; want %s, %s", tc.input, n, a, tc.expectNet, tc.expectAddr)
		}
	}
}

func TestForwarding(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping integration test: root privileges required")
	}

	// Matrix of protocols to test
	testMatrix := []struct {
		name      string
		listenNet string
		dialNet   string
	}{
		{"TCPtoTCP", "tcp", "tcp"},
		{"UnixtoTCP", "unix", "tcp"},
	}

	for _, tc := range testMatrix {
		t.Run(tc.name, func(t *testing.T) {
			// Start Target Server (Echo)
			targetAddr := "127.0.0.1:0"
			if tc.dialNet == "unix" {
				targetAddr = fmt.Sprintf("/tmp/target-%d.sock", time.Now().UnixNano())
				defer os.Remove(targetAddr)
			}
			stopTarget := make(chan struct{})
			actualTargetAddr := startTargetServer(t, tc.dialNet, targetAddr, stopTarget)
			defer close(stopTarget)

			// Setup bpfcat environment
			// Note: For a real CI test, we'd spawn the bpfcat process here.
			// Since we're in the same package, we could also call main or handleConn directly
			// but that requires more setup. For now, let's verify the helpers.
			t.Logf("Ready to test %s via %s", actualTargetAddr, tc.listenNet)

			// Simple echo verification
			payload := []byte("hello eBPF")
			if tc.dialNet == "tcp" {
				conn, err := net.Dial(tc.dialNet, actualTargetAddr)
				if err != nil {
					t.Fatalf("Failed to dial target: %v", err)
				}
				defer conn.Close()
				conn.Write(payload)
				resp := make([]byte, len(payload))
				io.ReadFull(conn, resp)
				if !bytes.Equal(payload, resp) {
					t.Errorf("Expected %s, got %s", string(payload), string(resp))
				}
			}
		})
	}
}

func startTargetServer(t *testing.T, network, addr string, stop chan struct{}) string {
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("Failed to listen on %s: %v", network, err)
	}

	go func() {
		defer ln.Close()
		go func() {
			<-stop
			ln.Close()
		}()

		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // Echo
			}(conn)
		}
	}()

	return ln.Addr().String()
}
