package httpapi

import (
	"errors"
	"net"
	"testing"
	"time"
)

// RS8-03: the listener holds at most n connections; a closed one frees
// its slot, and Close ends a waiting Accept.
func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := LimitListener(inner, 2)
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	var clients []net.Conn
	for range 3 {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
	}
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()
	first, second := <-accepted, <-accepted
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted while two are open")
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	_ = first.Close() // a second Close frees nothing more
	select {
	case third := <-accepted:
		_ = third.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the freed slot was not used")
	}
	if _, ok := second.(interface{ CloseWrite() error }); !ok {
		t.Fatal("the connection hides CloseWrite")
	}
	_ = second.Close()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	for range accepted {
	}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
}
