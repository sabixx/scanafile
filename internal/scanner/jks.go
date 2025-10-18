// internal/scanner/jks.go
package scanner

import (
	"bytes"

	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"scanafile/internal/types"
)

func ScanJKS(path string, data []byte, passwords []string) ([]types.Discovery, bool) {
	for _, pw := range passwords {
		ks := keystore.New()
		if err := ks.Load(bytes.NewReader(data), []byte(pw)); err != nil {
			continue
		}
		var out []types.Discovery
		for _, alias := range ks.Aliases() {
			if e, err := ks.GetTrustedCertificateEntry(alias); err == nil && e.Certificate.Type == "X509" {
				der := e.Certificate.Content
				out = append(out, discoveryFromDER(types.SourceJKS, path, alias, "file", der))
			}
		}
		if len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}
