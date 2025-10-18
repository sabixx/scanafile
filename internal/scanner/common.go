// internal/scanner/common.go
package scanner

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"scanafile/internal/types"
)

// ---- small shared helpers ----

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func parseX509(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	return base64.StdEncoding.DecodeString(s)
}

// discoveryFromDER builds a Discovery with parsed x509 metadata (when possible).
func discoveryFromDER(source types.Source, path, alias, scope string, der []byte) types.Discovery {
	var meta types.CertMeta
	if c, err := parseX509(der); err == nil && c != nil {
		meta = types.CertMeta{
			Subject:   c.Subject.String(),
			Issuer:    c.Issuer.String(),
			NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
			Serial:    c.SerialNumber.String(),
			SHA256:    sha256Hex(der),
			IsCA:      c.IsCA,
		}
	} else {
		meta = types.CertMeta{SHA256: sha256Hex(der)}
	}
	return types.Discovery{
		Source: source,
		Path:   path,
		Alias:  alias,
		Scope:  scope,
		DER:    der,
		Meta:   meta,
	}
}

// SkipPath returns true for noisy/protected system locations; keep conservative.
func SkipPath(p string) bool {
	lp := strings.ToLower(filepath.Clean(p))

	if runtime.GOOS != "windows" {
		// Linux/Unix virtual/system trees
		if strings.HasPrefix(lp, "/proc") ||
			strings.HasPrefix(lp, "/sys") ||
			strings.HasPrefix(lp, "/dev") ||
			strings.HasPrefix(lp, "/run") {
			return true
		}
		// Common container runtimes
		if strings.HasPrefix(lp, "/var/lib/docker") ||
			strings.HasPrefix(lp, "/var/lib/containerd") {
			return true
		}
		return false
	}

	// Windows protected/huge trees
	if strings.HasPrefix(lp, `c:\windows\winsxs`) ||
		strings.HasPrefix(lp, `c:\windows\softwaredistribution`) ||
		strings.HasPrefix(lp, `c:\windows\system32\config`) {
		return true
	}
	return false
}
