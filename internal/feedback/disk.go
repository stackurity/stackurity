package feedback

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
)

// Disk keeps the queue's attachments in one private directory, each under a
// random name. Names from people never reach the file system, and every
// open goes through an os.Root, so no stored key can point outside it.
type Disk struct {
	root *os.Root
	Dir  string
}

var keyPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidKey reports whether k is a storage key Disk made.
func ValidKey(k string) bool { return keyPattern.MatchString(k) }

// OpenDisk opens (and creates, mode 0700) the attachment directory.
func OpenDisk(dir string) (*Disk, error) {
	if dir == "" {
		return nil, errors.New("feedback: no attachment directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Disk{root: root, Dir: dir}, nil
}

func newKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Write stores r under a new key, reading at most limit bytes: more is a
// *TooLarge error for k and nothing is kept. It returns the key and size.
func (d *Disk) Write(r io.Reader, k Kind, limit int64) (string, int64, error) {
	key, err := newKey()
	if err != nil {
		return "", 0, err
	}
	tmp := "tmp-" + key
	f, err := d.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = &TooLarge{Kind: k}
	}
	if err != nil {
		_ = d.root.Remove(tmp)
		return "", 0, err
	}
	if err := d.root.Rename(tmp, key); err != nil {
		_ = d.root.Remove(tmp)
		return "", 0, err
	}
	return key, n, nil
}

// Open opens a stored attachment.
func (d *Disk) Open(key string) (*os.File, error) {
	if !ValidKey(key) {
		return nil, fs.ErrNotExist
	}
	return d.root.Open(key)
}

// Remove deletes a stored attachment; a missing one is not an error.
func (d *Disk) Remove(key string) error {
	if !ValidKey(key) {
		return fmt.Errorf("feedback: invalid storage key")
	}
	if err := d.root.Remove(key); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// RemoveStale deletes temporary files left by a crash during an upload.
func (d *Disk) RemoveStale() error {
	f, err := d.root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, n := range names {
		if len(n) == 36 && n[:4] == "tmp-" && ValidKey(n[4:]) {
			_ = d.root.Remove(n)
		}
	}
	return nil
}
