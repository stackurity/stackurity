package feedback

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func TestClamdScan(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				cmd, _ := r.ReadString(0)
				if cmd != "zINSTREAM\x00" {
					return
				}
				var data []byte
				for {
					var n uint32
					if binary.Read(r, binary.BigEndian, &n) != nil {
						return
					}
					if n == 0 {
						break
					}
					chunk := make([]byte, n)
					if _, err := io.ReadFull(r, chunk); err != nil {
						return
					}
					data = append(data, chunk...)
				}
				if bytes.Contains(data, []byte("EICAR")) {
					c.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
				} else {
					c.Write([]byte("stream: OK\x00"))
				}
			}(c)
		}
	}()
	c := &Clamd{Addr: ln.Addr().String()}
	if err := c.Scan(strings.NewReader("%PDF-1.4 clean")); err != nil {
		t.Fatalf("clean: %v", err)
	}
	if err := c.Scan(strings.NewReader("X5O!P%@AP EICAR test")); !errors.Is(err, ErrInfected) {
		t.Fatalf("infected: %v", err)
	}
	down := &Clamd{Addr: "127.0.0.1:1"}
	if err := down.Scan(strings.NewReader("x")); err == nil || errors.Is(err, ErrInfected) {
		t.Fatalf("scanner down must fail closed: %v", err)
	}
}

func TestEmailTemplates(t *testing.T) {
	for _, name := range EmailTemplates() {
		m, err := RenderEmail(name, EmailData{Ref: "FB-12", Summary: "The export button does nothing\nsecond line", Resolution: "We do this in the API instead.", Version: "0.15.0"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(m.Subject, "FB-12") || strings.ContainsAny(m.Subject, "\r\n") {
			t.Errorf("%s subject %q", name, m.Subject)
		}
		// Text from the sender is never put in the email (the address is
		// not verified).
		if strings.Contains(m.Body, "export button") || !strings.Contains(m.Body, "FB-12") {
			t.Errorf("%s body: %s", name, m.Body)
		}
	}
	if _, err := RenderEmail("other", EmailData{}); err == nil {
		t.Error("unknown template rendered")
	}
}
