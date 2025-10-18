package scanner

import (
	//"crypto/x509"

	p12 "software.sslmate.com/src/go-pkcs12"

	"scanafile/internal/logx"
	"scanafile/internal/types"
)

func ScanPKCS12(path string, data []byte, passwords []string) ([]types.Discovery, bool) {
	for _, pw := range passwords {
		priv, cert, _, err := p12.DecodeChain(data, pw)
		if err != nil {
			continue
		}
		if cert == nil || priv == nil {
			continue
		}
		// Pair is good; keep original keystore & password
		d := types.Discovery{
			Source:        types.SourcePKCS12,
			Path:          path,
			DER:           cert.Raw,
			Cert:          cert,
			HasPrivateKey: true,
			P12Raw:        data,
			P12Password:   pw,
		}
		return []types.Discovery{d}, true
	}
	logx.Warn("P12: could not open %s with provided passwords", path)
	return nil, false
}
