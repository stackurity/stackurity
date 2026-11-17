package confcheck

import (
	"bytes"
	"io"
	"os"
)

// readTail reads the last limit bytes of a file of the given size,
// dropping a partial first line.
func readTail(p string, size, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	off := int64(0)
	if size > limit {
		off = size - limit
	}
	data, err := io.ReadAll(io.NewSectionReader(f, off, size-off))
	if err != nil {
		return nil, err
	}
	if off > 0 {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return data, nil
}
