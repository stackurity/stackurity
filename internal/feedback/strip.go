package feedback

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	_ "image/gif"  // DecodeConfig
	_ "image/jpeg" // DecodeConfig
	_ "image/png"  // DecodeConfig
)

// MaxPixels bounds an image's declared size, so a small file cannot claim a
// picture that would take gigabytes to open on an operator's machine.
const MaxPixels = 100_000_000

// ErrBadImage is an image whose structure could not be read.
var ErrBadImage = errors.New("the image could not be read; attach it as a PNG or JPEG")

// StripImage returns the image without metadata: EXIF (with any location),
// XMP, IPTC, comments and text chunks. Pixels are copied byte for byte (no
// re-encoding, so nothing is lost in quality); anything the walk does not
// understand fails rather than passing through.
func StripImage(k Kind, b []byte) ([]byte, error) {
	var out []byte
	var err error
	switch k {
	case PNG:
		out, err = stripPNG(b)
	case JPEG:
		out, err = stripJPEG(b)
	case GIF:
		out, err = stripGIF(b)
	case WebP:
		return stripWebP(b)
	default:
		return nil, ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(out))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > MaxPixels {
		return nil, ErrBadImage
	}
	return out, nil
}

// pngKeep are the PNG chunks kept: the image, its colour information and
// APNG animation. Text (tEXt, zTXt, iTXt), eXIf, tIME and unknown chunks go.
var pngKeep = map[string]bool{
	"IHDR": true, "PLTE": true, "IDAT": true, "IEND": true, "tRNS": true, "gAMA": true, "cHRM": true,
	"sRGB": true, "iCCP": true, "sBIT": true, "pHYs": true, "bKGD": true, "acTL": true, "fcTL": true, "fdAT": true,
}

func stripPNG(b []byte) ([]byte, error) {
	const sig = "\x89PNG\r\n\x1a\n"
	if !bytes.HasPrefix(b, []byte(sig)) {
		return nil, ErrBadImage
	}
	out := make([]byte, 0, len(b))
	out = append(out, sig...)
	p := len(sig)
	first := true
	for {
		if p+12 > len(b) {
			return nil, ErrBadImage
		}
		n := binary.BigEndian.Uint32(b[p:])
		if n > uint32(len(b)-p-12) {
			return nil, ErrBadImage
		}
		typ := string(b[p+4 : p+8])
		end := p + 12 + int(n)
		if crc32.ChecksumIEEE(b[p+4:p+8+int(n)]) != binary.BigEndian.Uint32(b[p+8+int(n):end]) {
			return nil, ErrBadImage
		}
		if first && typ != "IHDR" {
			return nil, ErrBadImage
		}
		first = false
		if pngKeep[typ] {
			out = append(out, b[p:end]...)
		}
		p = end
		if typ == "IEND" {
			// Anything after IEND (a second file glued on) is dropped.
			return out, nil
		}
	}
}

func stripJPEG(b []byte) ([]byte, error) {
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 {
		return nil, ErrBadImage
	}
	out := make([]byte, 0, len(b))
	out = append(out, 0xFF, 0xD8)
	p := 2
	inScan := false
	for p < len(b) {
		if inScan {
			// Entropy-coded data: copy up to the next marker. 0xFF 0x00 is
			// a stuffed byte and 0xFF 0xD0-0xD7 are restart markers.
			start := p
			for p < len(b) {
				if b[p] == 0xFF && p+1 < len(b) {
					m := b[p+1]
					if m == 0x00 || (m >= 0xD0 && m <= 0xD7) {
						p += 2
						continue
					}
					if m == 0xFF {
						p++
						continue
					}
					break
				}
				p++
			}
			out = append(out, b[start:p]...)
			inScan = false
			continue
		}
		if b[p] != 0xFF || p+1 >= len(b) {
			return nil, ErrBadImage
		}
		m := b[p+1]
		switch {
		case m == 0xFF: // fill byte
			p++
			continue
		case m == 0xD9: // EOI: anything after it (appended images, trailers) is dropped
			return append(out, 0xFF, 0xD9), nil
		case m >= 0xD0 && m <= 0xD7, m == 0x01:
			out = append(out, 0xFF, m)
			p += 2
			continue
		}
		if p+4 > len(b) {
			return nil, ErrBadImage
		}
		n := int(binary.BigEndian.Uint16(b[p+2:]))
		if n < 2 || p+2+n > len(b) {
			return nil, ErrBadImage
		}
		seg := b[p : p+2+n]
		p += 2 + n
		switch {
		case m == 0xE0, m == 0xEE:
			// APP0 (JFIF) and APP14 (Adobe colour transform) describe how to
			// decode the pixels and say nothing about the person.
			out = append(out, seg...)
		case m >= 0xE1 && m <= 0xEF, m == 0xFE:
			// APP1-APP15 (EXIF, XMP, ICC, IPTC, MPF...) and comments go.
		default:
			out = append(out, seg...)
			if m == 0xDA {
				inScan = true
			}
		}
	}
	return nil, ErrBadImage
}

func stripGIF(b []byte) ([]byte, error) {
	if len(b) < 13 {
		return nil, ErrBadImage
	}
	out := make([]byte, 0, len(b))
	p := 13
	if b[10]&0x80 != 0 {
		p += 3 << (int(b[10]&0x07) + 1)
	}
	if p > len(b) {
		return nil, ErrBadImage
	}
	out = append(out, b[:p]...)
	// subBlocks returns the end of a run of data sub-blocks starting at q.
	subBlocks := func(q int) (int, error) {
		for {
			if q >= len(b) {
				return 0, ErrBadImage
			}
			n := int(b[q])
			q++
			if n == 0 {
				return q, nil
			}
			q += n
		}
	}
	for p < len(b) {
		switch b[p] {
		case 0x3B: // trailer
			return append(out, 0x3B), nil
		case 0x21: // extension
			if p+2 > len(b) {
				return nil, ErrBadImage
			}
			label := b[p+1]
			end, err := subBlocks(p + 2)
			if err != nil {
				return nil, err
			}
			keep := label == 0xF9 || label == 0x01 // graphic control, plain text
			if label == 0xFF && p+14 <= len(b) && b[p+2] == 11 {
				// Application extensions: only the looping one stays (XMP
				// and others go).
				id := string(b[p+3 : p+14])
				keep = id == "NETSCAPE2.0" || id == "ANIMEXTS1.0"
			}
			if keep {
				out = append(out, b[p:end]...)
			}
			p = end
		case 0x2C: // image
			if p+10 > len(b) {
				return nil, ErrBadImage
			}
			q := p + 10
			if b[p+9]&0x80 != 0 {
				q += 3 << (int(b[p+9]&0x07) + 1)
			}
			q++ // LZW minimum code size
			end, err := subBlocks(q)
			if err != nil {
				return nil, err
			}
			out = append(out, b[p:end]...)
			p = end
		default:
			return nil, ErrBadImage
		}
	}
	return nil, ErrBadImage
}

// stripWebP drops the EXIF and XMP chunks of a WebP file and clears their
// flags in VP8X. The image chunks are copied as they are.
func stripWebP(b []byte) ([]byte, error) {
	if len(b) < 20 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WEBP" {
		return nil, ErrBadImage
	}
	size := int(binary.LittleEndian.Uint32(b[4:]))
	if size < 12 || size+8 > len(b) {
		return nil, ErrBadImage
	}
	b = b[:size+8]
	out := make([]byte, 12, len(b))
	copy(out, b[:12])
	p := 12
	sawImage := false
	// dims records a declared size; any over MaxPixels refuses the file.
	var w, h int64
	dims := func(width, height int64) bool {
		if width <= 0 || height <= 0 || width*height > MaxPixels {
			return false
		}
		w, h = width, height
		return true
	}
	for p < len(b) {
		if p+8 > len(b) {
			return nil, ErrBadImage
		}
		typ := string(b[p : p+4])
		n := int(binary.LittleEndian.Uint32(b[p+4:]))
		end := p + 8 + n + n%2
		if n < 0 || end > len(b) || end < p {
			return nil, ErrBadImage
		}
		chunk := b[p:end]
		p = end
		switch typ {
		case "EXIF", "XMP ":
			continue
		case "VP8X":
			if n < 10 {
				return nil, ErrBadImage
			}
			d := chunk[8:]
			if !dims(int64(d[4])|int64(d[5])<<8|int64(d[6])<<16+1, int64(d[7])|int64(d[8])<<8|int64(d[9])<<16+1) {
				return nil, ErrBadImage
			}
			c := append([]byte(nil), chunk...)
			c[8] &^= 0x08 | 0x04 // EXIF and XMP present
			out = append(out, c...)
			continue
		case "VP8L":
			d := chunk[8 : 8+n]
			if n < 5 || d[0] != 0x2f {
				return nil, ErrBadImage
			}
			bits := binary.LittleEndian.Uint32(d[1:5])
			if !dims(int64(bits&0x3fff)+1, int64((bits>>14)&0x3fff)+1) {
				return nil, ErrBadImage
			}
			sawImage = true
		case "VP8 ":
			d := chunk[8 : 8+n]
			if n < 10 || d[3] != 0x9d || d[4] != 0x01 || d[5] != 0x2a {
				return nil, ErrBadImage
			}
			if !dims(int64(binary.LittleEndian.Uint16(d[6:])&0x3fff), int64(binary.LittleEndian.Uint16(d[8:])&0x3fff)) {
				return nil, ErrBadImage
			}
			sawImage = true
		case "ANMF", "ALPH":
			sawImage = true
		case "ICCP", "ANIM":
		default:
			// Unknown chunks may carry anything.
			continue
		}
		out = append(out, chunk...)
	}
	if !sawImage || w == 0 || h == 0 {
		return nil, ErrBadImage
	}
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)-8))
	return out, nil
}
