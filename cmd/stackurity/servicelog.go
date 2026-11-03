package main

import (
	"bufio"
	"io"
	"strings"
)

// maxLogLine keeps one event log entry well under the event log's limit of
// about 31,000 characters.
const maxLogLine = 8000

// pumpLines calls emit for each line read from r, without its line ending,
// until r ends. A line longer than maxLogLine is cut. Used on Windows,
// where a service has no console, to send the agent's output to the event
// log; it must keep reading whatever it is given, or the agent would block
// on a full pipe.
func pumpLines(r io.Reader, emit func(string)) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			if len(line) > maxLogLine {
				line = strings.ToValidUTF8(line[:maxLogLine], "") + " [cut]"
			}
			emit(line)
		}
		if err != nil { // the end, or a closed pipe: nothing more will come
			return
		}
	}
}
