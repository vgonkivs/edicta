package inclusion

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrDuplicateSource means two sources share a host, so they are one provider.
var ErrDuplicateSource = fmt.Errorf("%w: two sources on the same host", ErrConfig)

var defaultPorts = map[string]string{"http": "80", "ws": "80", "https": "443", "wss": "443"}

// NormalizeSourceURL returns scheme://host:port plus the path without trailing
// slashes. The scheme and host are lower-case, one trailing dot of the host is
// dropped and the port defaults by scheme. Query, fragment and user info are
// dropped.
func NormalizeSourceURL(raw string) (string, error) {
	scheme, host, port, path, err := splitSource(raw)
	if err != nil {
		return "", err
	}
	return scheme + "://" + net.JoinHostPort(host, port) + path, nil
}

func splitSource(raw string) (scheme, host, port, path string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", "", fmt.Errorf("%w: source URL does not parse", ErrConfig)
	}
	scheme = strings.ToLower(u.Scheme)
	def, ok := defaultPorts[scheme]
	if !ok {
		return "", "", "", "", fmt.Errorf("%w: source URL needs an http, https, ws or wss scheme", ErrConfig)
	}
	host = strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", "", "", "", fmt.Errorf("%w: source URL has no host", ErrConfig)
	}
	port = u.Port()
	if port == "" {
		port = def
	}
	return scheme, host, port, strings.TrimRight(u.Path, "/"), nil
}

// CheckDistinctSources refuses a list in which two URLs have the same
// normalized host, whatever their scheme, port or path.
func CheckDistinctSources(urls []string) error {
	seen := map[string]int{}
	for i, raw := range urls {
		_, host, _, _, err := splitSource(raw)
		if err != nil {
			return fmt.Errorf("source %d: %w", i+1, err)
		}
		if j, dup := seen[host]; dup {
			return fmt.Errorf("sources %d and %d: %w", j+1, i+1, ErrDuplicateSource)
		}
		seen[host] = i
	}
	return nil
}

// SourceHost is the normalized host of a source URL, the identity used to
// decide whether two sources are one provider.
func SourceHost(raw string) (string, error) {
	_, host, _, _, err := splitSource(raw)
	return host, err
}
