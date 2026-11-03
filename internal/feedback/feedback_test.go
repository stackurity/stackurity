package feedback

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 8, 6))
	for x := 0; x < 8; x++ {
		img.Set(x, x%6, color.RGBA{200, 10, 10, 255})
	}
	return img
}

func pngChunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(typ)
	b.Write(data)
	_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), data...)))
	return b.Bytes()
}

// secret is what metadata carries in these tests; none of it may survive.
const secret = "GPS 12.9716N 77.5946E owner@example.com"

func pngWithMetadata(t *testing.T) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, testImage()); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	// Insert tEXt and eXIf after IHDR (8 + 25 bytes), and a file after IEND.
	at := 8 + 25
	out := append([]byte{}, raw[:at]...)
	out = append(out, pngChunk("tEXt", []byte("Comment\x00"+secret))...)
	out = append(out, pngChunk("eXIf", []byte("MM\x00*"+secret))...)
	out = append(out, raw[at:]...)
	return append(out, []byte("PK\x03\x04"+secret)...)
}

func jpegWithMetadata(t *testing.T) []byte {
	var b bytes.Buffer
	if err := jpeg.Encode(&b, testImage(), &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	seg := func(m byte, data string) []byte {
		s := []byte{0xFF, m, 0, 0}
		binary.BigEndian.PutUint16(s[2:], uint16(len(data)+2))
		return append(s, data...)
	}
	out := append([]byte{}, raw[:2]...)
	out = append(out, seg(0xE1, "Exif\x00\x00"+secret)...)
	out = append(out, seg(0xE1, "http://ns.adobe.com/xap/1.0/\x00"+secret)...)
	out = append(out, seg(0xED, "Photoshop 3.0\x00"+secret)...)
	out = append(out, seg(0xFE, secret)...)
	out = append(out, raw[2:]...)
	return append(out, []byte(secret)...) // after EOI
}

func gifWithMetadata(t *testing.T) []byte {
	pal := image.NewPaletted(image.Rect(0, 0, 4, 4), color.Palette{color.Black, color.White})
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, &gif.GIF{Image: []*image.Paletted{pal, pal}, Delay: []int{10, 10}, LoopCount: 0}); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	// Insert a comment and an XMP application extension before the trailer.
	comment := append([]byte{0x21, 0xFE, byte(len(secret))}, secret...)
	comment = append(comment, 0)
	xmp := append([]byte{0x21, 0xFF, 11}, "XMP DataXMP"...)
	xmp = append(xmp, byte(len(secret)))
	xmp = append(xmp, secret...)
	xmp = append(xmp, 0)
	out := append([]byte{}, raw[:len(raw)-1]...)
	out = append(out, comment...)
	out = append(out, xmp...)
	return append(out, 0x3B)
}

func riff(chunks ...[]byte) []byte {
	body := []byte("WEBP")
	for _, c := range chunks {
		body = append(body, c...)
	}
	out := []byte("RIFF")
	out = binary.LittleEndian.AppendUint32(out, uint32(len(body)))
	return append(out, body...)
}

func webpChunk(typ string, data []byte) []byte {
	c := []byte(typ)
	c = binary.LittleEndian.AppendUint32(c, uint32(len(data)))
	c = append(c, data...)
	if len(data)%2 == 1 {
		c = append(c, 0)
	}
	return c
}

func TestDetectByContentNotName(t *testing.T) {
	cases := map[string]struct {
		head string
		want Kind
	}{
		"png":       {"\x89PNG\r\n\x1a\n....", PNG},
		"jpeg":      {"\xFF\xD8\xFF\xE0", JPEG},
		"gif":       {"GIF89a", GIF},
		"webp":      {"RIFF\x10\x00\x00\x00WEBPVP8 ", WebP},
		"pdf":       {"%PDF-1.7\n", PDF},
		"mp4":       {"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00", MP4},
		"webm":      {"\x1A\x45\xDF\xA3\x9F\x42\x86\x81\x01\x42\x82\x84webm\x42\x87", WebM},
		"matroska":  {"\x1A\x45\xDF\xA3\x9F\x42\x86\x81\x01\x42\x82\x88matroska", ""},
		"quicktime": {"\x00\x00\x00\x14ftypqt  \x00\x00\x02\x00", ""},
		"heic":      {"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00", ""},
		"svg":       {"<svg xmlns=\"http://www.w3.org/2000/svg\"", ""},
		"html":      {"<!doctype html><script>", ""},
		"exe":       {"MZ\x90\x00", ""},
		"zip":       {"PK\x03\x04", ""},
		"empty":     {"", ""},
		"riff-wav":  {"RIFF\x10\x00\x00\x00WAVEfmt ", ""},
	}
	for name, c := range cases {
		got, err := Detect([]byte(c.head))
		if c.want == "" {
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("%s: got %q, want unsupported", name, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got %q %v, want %q", name, got, err, c.want)
		}
	}
}

func TestStripImageRemovesMetadata(t *testing.T) {
	vp8l := webpChunk("VP8L", []byte{0x2f, 0x07, 0xc0, 0x01, 0x00, 0x07, 0x10, 0x11, 0x11, 0x88, 0x88, 0xfe, 0x07, 0x00})
	vp8x := webpChunk("VP8X", []byte{0x08 | 0x04 | 0x10, 0, 0, 0, 7, 0, 0, 5, 0, 0})
	cases := map[Kind][]byte{
		PNG:  pngWithMetadata(t),
		JPEG: jpegWithMetadata(t),
		GIF:  gifWithMetadata(t),
		WebP: riff(vp8x, webpChunk("EXIF", []byte(secret)), webpChunk("XMP ", []byte(secret)), webpChunk("ALPH", []byte{0}), vp8l),
	}
	for k, in := range cases {
		if !bytes.Contains(in, []byte("12.9716N")) {
			t.Fatalf("%s: fixture has no metadata", k)
		}
		out, err := StripImage(k, in)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if bytes.Contains(out, []byte("12.9716N")) || bytes.Contains(out, []byte("owner@example.com")) {
			t.Errorf("%s: metadata survived", k)
		}
		got, err := Detect(out)
		if err != nil || got != k {
			t.Errorf("%s: stripped file detected as %q %v", k, got, err)
		}
		switch k {
		case PNG, JPEG, GIF:
			img, _, err := image.Decode(bytes.NewReader(out))
			if err != nil || img.Bounds().Dx() == 0 {
				t.Errorf("%s: stripped image does not decode: %v", k, err)
			}
		case WebP:
			if binary.LittleEndian.Uint32(out[4:]) != uint32(len(out)-8) {
				t.Errorf("webp: RIFF size not updated")
			}
			if out[20]&0x0C != 0 {
				t.Errorf("webp: EXIF/XMP flags still set: %x", out[20])
			}
		}
		// Stripping twice changes nothing (the installation strips, then
		// the queue again).
		again, err := StripImage(k, out)
		if err != nil || !bytes.Equal(again, out) {
			t.Errorf("%s: second strip changed the file (%v)", k, err)
		}
	}
	// GIF keeps its animation loop.
	out, _ := StripImage(GIF, cases[GIF])
	if g, err := gif.DecodeAll(bytes.NewReader(out)); err != nil || len(g.Image) != 2 || g.LoopCount != 0 {
		t.Errorf("gif animation lost: %v", err)
	}
}

func TestStripImageRefusesBrokenAndHugeFiles(t *testing.T) {
	good := pngWithMetadata(t)
	broken := append([]byte{}, good[:40]...)
	if _, err := StripImage(PNG, broken); err == nil {
		t.Error("truncated PNG accepted")
	}
	// A bad CRC.
	bad := append([]byte{}, good...)
	bad[30] ^= 0xFF
	if _, err := StripImage(PNG, bad); err == nil {
		t.Error("PNG with a bad CRC accepted")
	}
	// A huge declared size (a decompression bomb's header).
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 100000)
	binary.BigEndian.PutUint32(ihdr[4:], 100000)
	ihdr[8], ihdr[9] = 8, 2
	bomb := append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", ihdr)...)
	bomb = append(bomb, pngChunk("IDAT", []byte{0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01})...)
	bomb = append(bomb, pngChunk("IEND", nil)...)
	if _, err := StripImage(PNG, bomb); !errors.Is(err, ErrBadImage) {
		t.Errorf("10-gigapixel PNG: %v", err)
	}
	// A JPEG whose segment length runs past the end.
	if _, err := StripImage(JPEG, []byte{0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF, 1, 2}); err == nil {
		t.Error("broken JPEG accepted")
	}
	// A GIF whose sub-blocks run past the end.
	if _, err := StripImage(GIF, []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00\x21\xFE\x40abc")); err == nil {
		t.Error("broken GIF accepted")
	}
	// A WebP with no image chunk, or a chunk running past the end.
	if _, err := StripImage(WebP, riff(webpChunk("EXIF", []byte(secret)))); err == nil {
		t.Error("WebP without an image accepted")
	}
	// A WebP declaring a 16-million-pixel-square canvas.
	huge := webpChunk("VP8X", []byte{0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if _, err := StripImage(WebP, riff(huge, webpChunk("VP8L", []byte{0x2f, 0x07, 0xc0, 0x01, 0x00}))); !errors.Is(err, ErrBadImage) {
		t.Errorf("huge WebP canvas: %v", err)
	}
	// Random bytes in a VP8 chunk are not an image.
	if _, err := StripImage(WebP, riff(webpChunk("VP8 ", []byte("not a vp8 frame at all")))); err == nil {
		t.Error("garbage VP8 accepted")
	}
	w := riff(webpChunk("VP8L", []byte{1, 2}))
	binary.LittleEndian.PutUint32(w[16:], 1<<30)
	if _, err := StripImage(WebP, w); err == nil {
		t.Error("WebP with an oversized chunk accepted")
	}
	if _, err := StripImage(PDF, []byte("%PDF-1.4")); err == nil {
		t.Error("PDF stripped as an image")
	}
}

func TestSafeName(t *testing.T) {
	cases := map[string]string{
		"screenshot.png":                 "screenshot.png",
		"../../etc/passwd":               "passwd.png",
		`C:\Users\me\Desktop\bug 1.PNG`:  "bug 1.png",
		"evil.html":                      "evil.png",
		"résumé<script>.png":             "r_sum_script.png",
		"":                               "attachment.png",
		"..":                             "attachment.png",
		strings.Repeat("a", 300) + ".js": strings.Repeat("a", 80) + ".png",
	}
	for in, want := range cases {
		if got := SafeName(in, PNG); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := SafeName("clip.mov", MP4); got != "clip.mp4" {
		t.Errorf("got %q", got)
	}
}

func TestDiskKeepsFilesInsideItsDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fb")
	d, err := OpenDisk(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", fi.Mode().Perm())
	}
	key, n, err := d.Write(strings.NewReader("hello"), PDF, 10)
	if err != nil || n != 5 || !ValidKey(key) {
		t.Fatalf("write: %q %d %v", key, n, err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, key)); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", fi.Mode().Perm())
	}
	f, err := d.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "hello" {
		t.Fatalf("read %q", b)
	}
	var tl *TooLarge
	if _, _, err := d.Write(strings.NewReader("0123456789AB"), PDF, 10); !errors.As(err, &tl) {
		t.Fatalf("over the limit: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left behind: %v", entries)
	}
	for _, k := range []string{"../x", "/etc/passwd", key + "/..", "tmp-" + key, strings.ToUpper(key)} {
		if _, err := d.Open(k); err == nil {
			t.Errorf("opened %q", k)
		}
	}
	if err := d.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(key); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}
