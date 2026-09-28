// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package testports

import (
	"net"
	"testing"
)

// Ports are distinct within a process, below the ephemeral ranges, locked
// against other processes while the test runs, and bindable by the server.
func TestReserve(t *testing.T) {
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		for _, network := range []string{"udp", "tcp"} {
			p := Port(t, network)
			if seen[p] || p < First || p > Last {
				t.Fatalf("port %d handed out twice or outside %d-%d", p, First, Last)
			}
			seen[p] = true
		}
	}
	u := UDP(t)
	// The server binds it; another reservation cannot take the number
	// (the TCP lock is held).
	c, err := net.ListenPacket("udp", u)
	if err != nil {
		t.Fatalf("the server cannot bind %s: %v", u, err)
	}
	defer c.Close()
	if l, err := net.Listen("tcp", u); err == nil {
		_ = l.Close()
		t.Fatalf("the lock on %s is not held", u)
	}
	tc := TCP(t)
	l, err := net.Listen("tcp", tc)
	if err != nil {
		t.Fatalf("the server cannot bind %s: %v", tc, err)
	}
	defer l.Close()
}
