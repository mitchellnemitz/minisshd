package logging

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// encodeJSON writes a single JSON-Lines log event to buf. The envelope
// fields ts, level, event are written first; event-specific fields follow
// in alphabetical order by key for stable output.
func (l *Logger) encodeJSON(buf *bytes.Buffer, level, event string, fields []field) {
	buf.WriteByte('{')
	writeJSONStringField(buf, "ts", l.now().Format(time.RFC3339))
	buf.WriteByte(',')
	writeJSONStringField(buf, "level", level)
	buf.WriteByte(',')
	writeJSONStringField(buf, "event", event)

	// Sort event fields alphabetically by key for stable output.
	sorted := make([]field, len(fields))
	copy(sorted, fields)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].key < sorted[j].key })
	for _, f := range sorted {
		buf.WriteByte(',')
		writeJSONField(buf, f)
	}

	buf.WriteByte('}')
	buf.WriteByte('\n')
}

// writeJSONStringField writes "key":"value" to buf.
func writeJSONStringField(buf *bytes.Buffer, key, value string) {
	writeJSONKey(buf, key)
	writeJSONString(buf, value)
}

// writeJSONKey writes "key": to buf (colon but no space, per the wire format).
func writeJSONKey(buf *bytes.Buffer, key string) {
	writeJSONString(buf, key)
	buf.WriteByte(':')
}

// writeJSONField dispatches on f.kind to write the appropriate JSON value.
func writeJSONField(buf *bytes.Buffer, f field) {
	writeJSONKey(buf, f.key)
	switch f.kind {
	case fieldInt:
		// f.value already holds the decimal form produced by intField;
		// digits only, no JSON-special characters.
		buf.WriteString(f.value)
	case fieldDurationSec:
		// Emit as float seconds. f.dur is the canonical source; f.value
		// holds the logfmt string form (e.g. "27s") which must NOT be used here.
		secs := f.dur.Seconds()
		s := strconv.FormatFloat(secs, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		buf.WriteString(s)
	default: // fieldString
		writeJSONString(buf, f.value)
	}
}

// writeJSONString encodes s as an RFC 8259 JSON string (with surrounding
// double-quote characters) and writes it to buf. encoding/json.Marshal is
// used to ensure full RFC compliance including all control-character escapes.
func writeJSONString(buf *bytes.Buffer, s string) {
	b, _ := json.Marshal(s) // cannot fail for a string
	buf.Write(b)
}
