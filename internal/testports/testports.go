// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package testports hands tests loopback ports for servers they configure
// by address before the server binds.
//
// The usual helper (listen on :0, read the port, close, pass the address
// on) releases the port between choosing and binding, and the kernel hands
// a just-released ephemeral port to the next :0 bind, in the same process or
// another: two servers of one test got the same port, and parallel test
// processes took each other's (a bootstrap listener failing with "address
// already in use", seen under 8x10 stress of internal/ipe/lwm2m).
//
// testports instead takes ports from a range below every kernel's
// ephemeral range (Linux starts at 32768, macOS and Windows at 49152), so no
// :0 bind anywhere is given one, and reserves each number across test
// processes by holding a lock socket of the other protocol on it (TCP for a
// UDP port, UDP for a TCP port) until the test ends. A number is never
// handed out twice in one process. The server then binds a port nobody else
// can be binding.
package testports

import (
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
)

// Range is the port range used: below the ephemeral ranges.
const (
	First = 20000
	Last  = 31999
)

// TB is the part of testing.TB used.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

var (
	mu   sync.Mutex
	used = map[int]bool{}
)

// UDP is a free UDP loopback address, "127.0.0.1:port".
func UDP(t TB) string { t.Helper(); return addr(reserve(t, "udp")) }

// TCP is a free TCP loopback address, "127.0.0.1:port".
func TCP(t TB) string { t.Helper(); return addr(reserve(t, "tcp")) }

// UDPPort is UDP's port number.
func UDPPort(t TB) int { t.Helper(); return reserve(t, "udp") }

// TCPPort is TCP's port number.
func TCPPort(t TB) int { t.Helper(); return reserve(t, "tcp") }

// Port is a free port for network ("tcp" or "udp", also "tcp4", "udp4").
func Port(t TB, network string) int {
	t.Helper()
	switch network {
	case "udp", "udp4":
		return reserve(t, "udp")
	default:
		return reserve(t, "tcp")
	}
}

func addr(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

func reserve(t TB, network string) int {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	n := Last - First + 1
	start := rand.IntN(n)
	for i := 0; i < n; i++ {
		port := First + (start+i)%n
		if used[port] {
			continue
		}
		lock, ok := lockAndCheck(network, port)
		if !ok {
			continue
		}
		used[port] = true
		t.Cleanup(func() {
			_ = lock.Close()
			mu.Lock()
			delete(used, port)
			mu.Unlock()
		})
		return port
	}
	t.Fatalf("testports: no free %s port in %d-%d", network, First, Last)
	return 0
}

type closer interface{ Close() error }

// lockAndCheck takes the lock socket of the other protocol on port and
// checks that network's port binds (then releases it for the server).
func lockAndCheck(network string, port int) (closer, bool) {
	a := addr(port)
	var lock closer
	var err error
	if network == "udp" {
		lock, err = net.Listen("tcp", a)
	} else {
		lock, err = net.ListenPacket("udp", a)
	}
	if err != nil {
		return nil, false
	}
	var probe closer
	if network == "udp" {
		probe, err = net.ListenPacket("udp", a)
	} else {
		probe, err = net.Listen("tcp", a)
	}
	if err != nil {
		_ = lock.Close()
		return nil, false
	}
	_ = probe.Close()
	return lock, true
}
