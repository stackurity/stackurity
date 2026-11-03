package feedback

import (
	"bytes"
	"errors"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"

	"golang.org/x/image/webp"
)

// MaxReencodePixels bounds the pictures that are decoded and encoded again
// (40 megapixels is about 160 MB while decoding). Screenshots and phone
// photos are well under it.
const MaxReencodePixels = 40_000_000

// ErrTooManyPixels is an image too large to re-encode.
var ErrTooManyPixels = errors.New("the image is too large (over 40 megapixels); attach a smaller screenshot")

// Reencode decodes an image and encodes its pixels again, so the stored file
// holds only what the encoder writes: no chunk, segment or trailing data
// from the original survives, whatever StripImage could not recognise.
// PNG, JPEG (quality 92) and GIF (all frames) keep their format; WebP, for
// which Go has no encoder, becomes PNG. It returns the new bytes and kind.
func Reencode(k Kind, b []byte) ([]byte, Kind, error) {
	var cfg image.Config
	var err error
	switch k {
	case WebP:
		cfg, err = webp.DecodeConfig(bytes.NewReader(b))
	case PNG, JPEG, GIF:
		cfg, _, err = image.DecodeConfig(bytes.NewReader(b))
	default:
		return nil, "", ErrUnsupported
	}
	if err != nil {
		return nil, "", ErrBadImage
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > MaxReencodePixels {
		return nil, "", ErrTooManyPixels
	}
	var out bytes.Buffer
	switch k {
	case GIF:
		g, err := gif.DecodeAll(bytes.NewReader(b))
		if err != nil {
			return nil, "", ErrBadImage
		}
		// Frames times the canvas bounds the work too.
		if int64(len(g.Image))*int64(cfg.Width)*int64(cfg.Height) > 4*MaxReencodePixels {
			return nil, "", ErrTooManyPixels
		}
		g.Config.ColorModel = nil
		if err := gif.EncodeAll(&out, &gif.GIF{Image: g.Image, Delay: g.Delay, LoopCount: g.LoopCount,
			Disposal: g.Disposal, BackgroundIndex: g.BackgroundIndex, Config: image.Config{Width: g.Config.Width, Height: g.Config.Height}}); err != nil {
			return nil, "", err
		}
		return out.Bytes(), GIF, nil
	case JPEG:
		img, err := jpeg.Decode(bytes.NewReader(b))
		if err != nil {
			return nil, "", ErrBadImage
		}
		if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 92}); err != nil {
			return nil, "", err
		}
		return out.Bytes(), JPEG, nil
	case WebP:
		img, err := webp.Decode(bytes.NewReader(b))
		if err != nil {
			return nil, "", ErrBadImage
		}
		if err := png.Encode(&out, img); err != nil {
			return nil, "", err
		}
		return out.Bytes(), PNG, nil
	default: // PNG
		img, err := png.Decode(bytes.NewReader(b))
		if err != nil {
			return nil, "", ErrBadImage
		}
		if err := (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(&out, img); err != nil {
			return nil, "", err
		}
		return out.Bytes(), PNG, nil
	}
}
