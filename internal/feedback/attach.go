// Package feedback holds what the feedback queue and the dashboard's Send
// feedback share: which attachments are accepted and how they are made safe
// to keep (attach.go, strip.go), where the queue keeps them (disk.go), the
// optional virus scan (clamd.go), and the emails to the person who sent an
// item (email.go).
//
// Attachments are untrusted. Their type comes from their first bytes, never
// from the file name or the browser's Content-Type; images lose their
// metadata (EXIF, XMP, comments, GPS) before they leave the installation,
// and again when the queue stores them. Files are stored under random names
// and are only ever served as downloads.
package feedback

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"
)

// Kind is what an attachment is, decided from its content.
type Kind string

const (
	PNG  Kind = "png"
	JPEG Kind = "jpeg"
	GIF  Kind = "gif"
	WebP Kind = "webp"
	MP4  Kind = "mp4"
	WebM Kind = "webm"
	PDF  Kind = "pdf"
)

// Limits on what one item may carry. The total stays under Cloudflare's
// 100 MB request limit in front of stackurity.dev.
const (
	MaxFiles      = 3
	MaxImageBytes = 10 << 20
	MaxPDFBytes   = 10 << 20
	MaxVideoBytes = 50 << 20
	MaxTotalBytes = 90 << 20
	// SniffBytes is how much of a file Detect needs.
	SniffBytes = 64
)

// ContentType is the media type a Kind is stored and served as.
func (k Kind) ContentType() string {
	switch k {
	case PNG:
		return "image/png"
	case JPEG:
		return "image/jpeg"
	case GIF:
		return "image/gif"
	case WebP:
		return "image/webp"
	case MP4:
		return "video/mp4"
	case WebM:
		return "video/webm"
	case PDF:
		return "application/pdf"
	}
	return "application/octet-stream"
}

// Ext is the file extension for a Kind, without the dot.
func (k Kind) Ext() string {
	if k == JPEG {
		return "jpg"
	}
	return string(k)
}

// Image reports whether the Kind is a picture (metadata is stripped).
func (k Kind) Image() bool { return k == PNG || k == JPEG || k == GIF || k == WebP }

// Video reports whether the Kind is a video.
func (k Kind) Video() bool { return k == MP4 || k == WebM }

// MaxBytes is the size limit for one file of this Kind.
func (k Kind) MaxBytes() int64 {
	switch {
	case k.Video():
		return MaxVideoBytes
	case k == PDF:
		return MaxPDFBytes
	default:
		return MaxImageBytes
	}
}

// KindFromContentType maps a stored media type back to its Kind.
func KindFromContentType(ct string) (Kind, bool) {
	for _, k := range []Kind{PNG, JPEG, GIF, WebP, MP4, WebM, PDF} {
		if k.ContentType() == ct {
			return k, true
		}
	}
	return "", false
}

// ErrUnsupported is a file whose content is none of the accepted kinds.
var ErrUnsupported = errors.New("attach a PNG, JPEG, WebP or GIF image, an MP4 or WebM video, or a PDF")

// mp4Brands are ISO base media major brands of MP4 files. QuickTime ("qt  ")
// and HEIF images are not accepted.
var mp4Brands = map[string]bool{
	"isom": true, "iso2": true, "iso3": true, "iso4": true, "iso5": true, "iso6": true,
	"mp41": true, "mp42": true, "avc1": true, "dash": true, "M4V ": true, "mp71": true, "MSNV": true,
}

// Detect decides a file's Kind from its first bytes (at least SniffBytes
// unless the file is shorter).
func Detect(head []byte) (Kind, error) {
	switch {
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		return PNG, nil
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF}):
		return JPEG, nil
	case bytes.HasPrefix(head, []byte("GIF87a")), bytes.HasPrefix(head, []byte("GIF89a")):
		return GIF, nil
	case len(head) >= 12 && string(head[0:4]) == "RIFF" && string(head[8:12]) == "WEBP":
		return WebP, nil
	case bytes.HasPrefix(head, []byte("%PDF-")):
		return PDF, nil
	case len(head) >= 12 && string(head[4:8]) == "ftyp" && mp4Brands[string(head[8:12])]:
		return MP4, nil
	case bytes.HasPrefix(head, []byte{0x1A, 0x45, 0xDF, 0xA3}):
		// EBML: the DocType element (0x42 0x82) says "webm" (Matroska is
		// not accepted).
		if i := bytes.Index(head, []byte{0x42, 0x82}); i > 0 && i+3 < len(head) {
			n := int(head[i+2] & 0x7F)
			if head[i+2]&0x80 != 0 && i+3+n <= len(head) && string(head[i+3:i+3+n]) == "webm" {
				return WebM, nil
			}
		}
	}
	return "", ErrUnsupported
}

// TooLarge says which limit a file broke.
type TooLarge struct {
	Kind  Kind
	Total bool
}

func (e *TooLarge) Error() string {
	if e.Total {
		return fmt.Sprintf("attachments may be %d MB together at most", MaxTotalBytes>>20)
	}
	what := "an image"
	switch {
	case e.Kind.Video():
		what = "a video"
	case e.Kind == PDF:
		what = "a PDF"
	}
	return fmt.Sprintf("%s may be %d MB at most", what, e.Kind.MaxBytes()>>20)
}

// SafeName reduces a file name from a browser to something safe to show and
// to offer as a download name: the base name only, letters, digits, spaces,
// dots, dashes and underscores, at most 80 characters, and the extension of
// the detected Kind.
func SafeName(name string, k Kind) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)), r == ' ', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), " .")
	if len(out) > 80 {
		out = out[:80]
	}
	if out == "" || out == "." || out == ".." {
		out = "attachment"
	}
	return out + "." + k.Ext()
}
