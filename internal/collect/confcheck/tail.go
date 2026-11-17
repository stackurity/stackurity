package confcheck

import (
	"bytes"
	"io"
	"os"
)

// readTail reads the last limit bytes of an open regular file, dropping a
// partial first line.
func readTail(f *os.File, limit int64) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
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
