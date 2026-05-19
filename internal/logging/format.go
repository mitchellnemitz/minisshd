package logging

import "fmt"

// Format is the on-the-wire encoding selected at startup.
type Format int

const (
	FormatLogfmt Format = iota
	FormatJSON
)

// String returns a human-readable name for the format.
func (f Format) String() string {
	switch f {
	case FormatLogfmt:
		return "logfmt"
	case FormatJSON:
		return "json"
	default:
		return fmt.Sprintf("Format(%d)", int(f))
	}
}

// ParseFormat resolves the log-format selector per spec §9. flagValue is
// the literal --log-format value; flagSet reports whether the flag was
// supplied. envValue / envSet describe the MINISSHD_LOG_FORMAT environment
// variable. The default is FormatLogfmt. An unrecognized value returns an
// error whose message names the rejected value.
func ParseFormat(flagValue string, flagSet bool, envValue string, envSet bool) (Format, error) {
	// If the flag was explicitly set (even to ""), validate it.
	if flagSet {
		return parseFormatString(flagValue)
	}
	// Flag was not set. Use env if present and non-empty.
	if envSet && envValue != "" {
		return parseFormatString(envValue)
	}
	// Default.
	return FormatLogfmt, nil
}

func parseFormatString(s string) (Format, error) {
	switch s {
	case "logfmt":
		return FormatLogfmt, nil
	case "json":
		return FormatJSON, nil
	default:
		return 0, fmt.Errorf("--log-format %q: unknown format (valid: logfmt, json)", s)
	}
}
