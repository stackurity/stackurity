package sitecheck

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
)

// acceptsOldTLS reports whether the site agrees to TLS 1.0 or 1.1. It sends
// one ClientHello that offers nothing newer than TLS 1.1 and reads the
// version the server picks in its ServerHello, then closes the connection:
// no handshake is completed, no key is agreed and nothing is encrypted or
// sent beyond the hello, so the check never uses an outdated protocol for
// anything. A server that refuses old versions answers with an alert
// (protocol_version or handshake_failure) or closes the connection.
//
// The connection goes through the same guarded dialer as the rest of the
// check (no private addresses, checked on the address dialled).
func acceptsOldTLS(ctx context.Context, u *url.URL) bool {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	conn, err := netguard.Policy{}.DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(oldClientHello(u.Hostname())); err != nil {
		return false
	}
	v, ok := serverHelloVersion(conn)
	return ok && (v == 0x0301 || v == 0x0302)
}

// oldClientHello is a TLS ClientHello record offering at most TLS 1.1
// (legacy_version 0x0302, no supported_versions extension), with SNI and the
// cipher suites TLS 1.0/1.1 servers commonly accept.
func oldClientHello(host string) []byte {
	var body []byte
	body = binary.BigEndian.AppendUint16(body, 0x0302) // client_version: TLS 1.1
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)
	body = append(body, 0) // session_id: empty
	suites := []uint16{0xc013, 0xc014, 0xc009, 0xc00a, 0x002f, 0x0035, 0x000a}
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(suites)))
	for _, s := range suites {
		body = binary.BigEndian.AppendUint16(body, s)
	}
	body = append(body, 1, 0) // compression_methods: null only

	var ext []byte
	if net.ParseIP(host) == nil && host != "" {
		name := []byte(host)
		sni := binary.BigEndian.AppendUint16(nil, uint16(len(name)+3)) // server_name_list length
		sni = append(sni, 0)                                           // host_name
		sni = binary.BigEndian.AppendUint16(sni, uint16(len(name)))
		sni = append(sni, name...)
		ext = appendExt(ext, 0x0000, sni)
	}
	ext = appendExt(ext, 0x000a, []byte{0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d}) // supported_groups: P-256, P-384, X25519
	ext = appendExt(ext, 0x000b, []byte{0x01, 0x00})                                     // ec_point_formats: uncompressed
	ext = appendExt(ext, 0xff01, []byte{0x00})                                           // renegotiation_info
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{1} // handshake type: client_hello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := []byte{22, 0x03, 0x01} // handshake record, record version TLS 1.0
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func appendExt(b []byte, typ uint16, data []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// serverHelloVersion reads the first record the server sends and returns the
// server_version of its ServerHello. ok is false for an alert, another
// message, or a connection closed or malformed before it.
func serverHelloVersion(r io.Reader) (version uint16, ok bool) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil || hdr[0] != 22 {
		return 0, false // 21 = alert: the old versions were refused
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n < 6 || n > 1<<14+2048 {
		return 0, false
	}
	// The handshake header (4 bytes) and server_version (2) are enough.
	var head [6]byte
	if _, err := io.ReadFull(r, head[:]); err != nil || head[0] != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(head[4:6]), true
}
