package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"syscall"
	"time"
)

// DefaultSocket is where the Docker daemon listens on a Linux host.
const DefaultSocket = "/var/run/docker.sock"

// ErrNoDocker means there is no Docker daemon to ask: no socket at the
// path, or nothing listening on it.
var ErrNoDocker = errors.New("docker is not running on this host")

// ErrDenied means the socket exists but the agent's user may not use it.
var ErrDenied = errors.New("permission denied on the Docker socket")

// Engine is a read-only client for the Docker Engine API on a Unix socket.
// It lists containers, inspects images and exports them; it never creates,
// starts, stops or changes anything.
type Engine struct {
	Socket string
	hc     *http.Client
}

// NewEngine returns a client for the daemon at socket.
func NewEngine(socket string) *Engine {
	if socket == "" {
		socket = DefaultSocket
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableCompression:    true,
		ResponseHeaderTimeout: 2 * time.Minute,
		MaxIdleConns:          2,
	}
	return &Engine{Socket: socket, hc: &http.Client{Transport: tr}}
}

// Container is the part of GET /containers/json the agent uses.
type Container struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`   // the reference the container was created from
	ImageID string   `json:"ImageID"` // sha256:...
	State   string   `json:"State"`
}

// Image is the part of GET /images/{id}/json the agent uses.
type Image struct {
	ID           string   `json:"Id"`
	RepoTags     []string `json:"RepoTags"`
	RepoDigests  []string `json:"RepoDigests"`
	Size         int64    `json:"Size"`
	Os           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
	Variant      string   `json:"Variant"`
	Config       *struct {
		WorkingDir string `json:"WorkingDir"`
	} `json:"Config"`
}

// WorkingDir is the image's working directory, or "".
func (im *Image) WorkingDir() string {
	if im.Config == nil {
		return ""
	}
	return im.Config.WorkingDir
}

var imageIDRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Containers lists the running containers.
func (e *Engine) Containers(ctx context.Context) ([]Container, error) {
	var out []Container
	if err := e.getJSON(ctx, "/containers/json", 32<<20, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Image inspects one image by its ID.
func (e *Engine) Image(ctx context.Context, id string) (*Image, error) {
	if !imageIDRE.MatchString(id) {
		return nil, fmt.Errorf("unexpected image id %q", id)
	}
	var out Image
	if err := e.getJSON(ctx, "/images/"+url.PathEscape(id)+"/json", 4<<20, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Export streams the image as the tar archive docker save writes. The
// caller reads it once, front to back, and closes it.
func (e *Engine) Export(ctx context.Context, id string) (io.ReadCloser, error) {
	if !imageIDRE.MatchString(id) {
		return nil, fmt.Errorf("unexpected image id %q", id)
	}
	resp, err := e.get(ctx, "/images/"+url.PathEscape(id)+"/get")
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (e *Engine) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		return nil, e.classify(err)
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&msg)
		if len(msg.Message) > 300 {
			msg.Message = msg.Message[:300]
		}
		return nil, fmt.Errorf("docker API %s: HTTP %d %s", path, resp.StatusCode, msg.Message)
	}
	return resp, nil
}

func (e *Engine) getJSON(ctx context.Context, path string, max int64, v any) error {
	resp, err := e.get(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, max)).Decode(v); err != nil {
		return fmt.Errorf("docker API %s: %w", path, err)
	}
	return nil
}

// classify turns a dial failure into ErrNoDocker or ErrDenied.
func (e *Engine) classify(err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("%w (no daemon listening at %s)", ErrNoDocker, e.Socket)
	case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Errorf("%w %s", ErrDenied, e.Socket)
	}
	return err
}
