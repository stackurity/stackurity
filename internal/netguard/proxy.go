package netguard

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Proxy is an HTTP CONNECT proxy on a loopback port that dials every tunnel
// through the policy. It is for tools run as separate processes (Syft) that
// make their own connections: with HTTPS_PROXY pointing here, each
// connection they open, including after a redirect or a second DNS answer,
// is checked like the server's own.
type Proxy struct {
	URL string // http://127.0.0.1:port

	srv   *http.Server
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]bool
	done  bool
}

// StartProxy serves a guarded proxy for ctx's workspace until Close.
func StartProxy(ctx context.Context) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	policy := PolicyFor(ctx)
	p := &Proxy{URL: "http://" + ln.Addr().String(), conns: map[net.Conn]bool{}}
	p.srv = &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
				return
			}
			up, err := policy.DialContext(ctx, "tcp", r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				up.Close()
				http.Error(w, "hijacking not supported", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			down, buf, err := hj.Hijack()
			if err != nil {
				up.Close()
				return
			}
			if !p.track(up, down) {
				up.Close()
				down.Close()
				return
			}
			go func() {
				defer p.wg.Done()
				defer p.untrack(up, down)
				done := make(chan struct{}, 2)
				go func() {
					if n := buf.Reader.Buffered(); n > 0 {
						b, _ := buf.Reader.Peek(n)
						_, _ = up.Write(b)
					}
					_, _ = io.Copy(up, down)
					done <- struct{}{}
				}()
				go func() { _, _ = io.Copy(down, up); done <- struct{}{} }()
				select {
				case <-done:
				case <-ctx.Done():
				}
			}()
		}),
	}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

func (p *Proxy) track(cs ...net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return false
	}
	for _, c := range cs {
		p.conns[c] = true
	}
	p.wg.Add(1)
	return true
}

func (p *Proxy) untrack(cs ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range cs {
		c.Close()
		delete(p.conns, c)
	}
}

// Close stops the proxy and every tunnel it opened.
func (p *Proxy) Close() {
	_ = p.srv.Close()
	p.mu.Lock()
	p.done = true
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}
