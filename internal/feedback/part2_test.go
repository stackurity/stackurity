package feedback

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEmailTemplates(t *testing.T) {
	for _, name := range EmailTemplates() {
		m, err := RenderEmail(name, EmailData{Ref: "FB-12", Summary: "The export button does nothing\nsecond line", Resolution: "We do this in the API instead.", Version: "0.15.0"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(m.Subject, "FB-12") || strings.ContainsAny(m.Subject, "\r\n") {
			t.Errorf("%s subject %q", name, m.Subject)
		}
		// Text from the sender is never put in the email (the address is
		// not verified).
		if strings.Contains(m.Body, "export button") || !strings.Contains(m.Body, "FB-12") {
			t.Errorf("%s body: %s", name, m.Body)
		}
	}
	if _, err := RenderEmail("other", EmailData{}); err == nil {
		t.Error("unknown template rendered")
	}
}

// A 1x1 lossless WebP.
const tinyWebP = "UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA=="

func TestReencode(t *testing.T) {
	for _, k := range []Kind{PNG, JPEG, GIF} {
		var in []byte
		switch k {
		case PNG:
			in = pngWithMetadata(t)
		case JPEG:
			in = jpegWithMetadata(t)
		case GIF:
			in = gifWithMetadata(t)
		}
		stripped, err := StripImage(k, in)
		if err != nil {
			t.Fatal(err)
		}
		out, k2, err := Reencode(k, stripped)
		if err != nil || k2 != k {
			t.Fatalf("%s: %v %s", k, err, k2)
		}
		if got, err := Detect(out); err != nil || got != k {
			t.Errorf("%s re-encoded detects as %s", k, got)
		}
		if strings.Contains(string(out), "12.9716N") {
			t.Errorf("%s: metadata survived", k)
		}
	}
	w, _ := base64.StdEncoding.DecodeString(tinyWebP)
	out, k, err := Reencode(WebP, w)
	if err != nil || k != PNG || !strings.HasPrefix(string(out), "\x89PNG") {
		t.Fatalf("webp: %v %s", err, k)
	}
	// A PNG claiming 50 megapixels is refused before decoding.
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 10000)
	binary.BigEndian.PutUint32(ihdr[4:], 5000)
	ihdr[8], ihdr[9] = 8, 2
	big := append([]byte("\x89PNG\r\n\x1a\n"), pngChunk("IHDR", ihdr)...)
	big = append(big, pngChunk("IEND", nil)...)
	if _, _, err := Reencode(PNG, big); err != ErrTooManyPixels {
		t.Fatalf("50 MP: %v", err)
	}
	if _, _, err := Reencode(PNG, []byte("\x89PNG\r\n\x1a\nbroken")); err != ErrBadImage {
		t.Fatalf("broken: %v", err)
	}
}
