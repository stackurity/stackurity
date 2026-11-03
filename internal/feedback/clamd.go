package feedback

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Clamd scans files with a ClamAV daemon over TCP (the INSTREAM command).
// It is optional: STACKURITY_FEEDBACK_CLAMD names the daemon, and without
// it attachments get the type, size and structure checks only.
type Clamd struct {
	Addr    string // host:port
	Timeout time.Duration
}

// ErrInfected is a file the scanner flagged.
var ErrInfected = errors.New("an attachment was flagged by the virus scanner")

// Scan streams r to clamd. It returns ErrInfected for a match, and another
// error when the scan could not be done (the caller refuses the file then:
// a scanner that is configured but down fails closed).
func (c *Clamd) Scan(r io.Reader) error {
	to := c.Timeout
	if to == 0 {
		to = 2 * time.Minute
	}
	conn, err := net.DialTimeout("tcp", c.Addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("virus scanner: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(to))
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return fmt.Errorf("virus scanner: %w", err)
	}
	buf := make([]byte, 64<<10)
	var hdr [4]byte
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, err := conn.Write(hdr[:]); err != nil {
				return fmt.Errorf("virus scanner: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return fmt.Errorf("virus scanner: %w", err)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return fmt.Errorf("virus scanner: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString(0)
	if err != nil && line == "" {
		return fmt.Errorf("virus scanner: %w", err)
	}
	line = strings.TrimRight(line, "\x00\n")
	switch {
	case strings.HasSuffix(line, " OK"):
		return nil
	case strings.HasSuffix(line, " FOUND"):
		return ErrInfected
	default:
		return fmt.Errorf("virus scanner answered %q", line)
	}
}
