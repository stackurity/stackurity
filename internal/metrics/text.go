// Package metrics exposes Prometheus metrics in the text exposition format
// (version 0.0.4), written by hand so the server needs no client library.
// It is served on a separate listener (STACKURITY_METRICS_ADDR), never on
// the public API port. Labels are kept to bounded sets: route patterns,
// job kinds, task and feed names; never workspace, asset or user ids.
package metrics

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// ContentType is the media type of the text exposition format.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Writer writes metric families. Call Family once per metric, then Sample
// for each of its series, before starting the next family.
type Writer struct {
	w   io.Writer
	err error
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Err returns the first write error.
func (w *Writer) Err() error { return w.err }

func (w *Writer) printf(format string, args ...any) {
	if w.err == nil {
		_, w.err = fmt.Fprintf(w.w, format, args...)
	}
}

// Family starts a metric family: typ is counter, gauge or histogram.
func (w *Writer) Family(name, typ, help string) {
	w.printf("# HELP %s %s\n# TYPE %s %s\n", name, escapeHelp(help), name, typ)
}

// Sample writes one series; labels are name, value pairs.
func (w *Writer) Sample(name string, value float64, labels ...string) {
	w.printf("%s%s %s\n", name, labelSet(labels), formatValue(value))
}

// Gauge writes a family with a single unlabelled series.
func (w *Writer) Gauge(name, help string, value float64) {
	w.Family(name, "gauge", help)
	w.Sample(name, value)
}

func labelSet(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(labels); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(labels[i])
		b.WriteString(`="`)
		b.WriteString(escapeLabel(labels[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

var (
	labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }

func formatValue(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
