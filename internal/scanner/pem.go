package scanner

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/youmark/pkcs8"
	//p12 "software.sslmate.com/src/go-pkcs12"

	//"scanafile/internal/logx"
	"scanafile/internal/types"
)

func LooksLikePEM(b []byte) bool {
	s := string(b)
	return bytes.Contains([]byte(s), []byte("-----BEGIN CERTIFICATE-----")) ||
		bytes.Contains([]byte(s), []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) ||
		bytes.Contains([]byte(s), []byte("-----BEGIN PRIVATE KEY-----")) ||
		bytes.Contains([]byte(s), []byte("-----BEGIN RSA PRIVATE KEY-----")) ||
		bytes.Contains([]byte(s), []byte("-----BEGIN EC PRIVATE KEY-----"))
}

// ScanPEM returns only discoveries where a private key was found & paired.
// It builds a PKCS#12 in-memory with a random password for import.
// func ScanPEM(path string, data []byte, passwords []string) []types.Discovery {
// 	var certs []*x509.Certificate
// 	var keyCandidates [][]byte
// 	var out []types.Discovery

// 	rest := data
// 	for {
// 		blk, rem := pem.Decode(rest)
// 		if blk == nil {
// 			break
// 		}
// 		rest = rem

// 		switch blk.Type {
// 		case "CERTIFICATE":
// 			// wherever you build the discovery for this cert:
// 			d := discoveryFromDER(source, path, "", "", block.Bytes)
// 			d.HasPrivateKey = hasKeyInline // <-- tells playbook to reuse same file
// 			// (optional but helpful)
// 			d.Cert, _ = x509.ParseCertificate(block.Bytes)
// 			findings = append(findings, d)
// 		case "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
// 			keyCandidates = append(keyCandidates, pem.EncodeToMemory(blk))
// 		}
// 	}

// 	if len(certs) == 0 || len(keyCandidates) == 0 {
// 		return nil // only process when we have both cert(s) and a key
// 	}

// 	// try to decrypt/parse keys using candidate passwords
// 	var privKey any
// 	var usedPass string
// 	for _, pemKey := range keyCandidates {
// 		blk, _ := pem.Decode(pemKey)
// 		if blk == nil {
// 			continue
// 		}

// 		// Try all passwords (empty included)
// 		for _, pw := range passwords {
// 			k, err := parseAnyPEMPrivateKey(blk, []byte(pw))
// 			if err == nil {
// 				privKey = k
// 				usedPass = pw
// 				break
// 			}
// 		}
// 		if privKey != nil {
// 			break
// 		}
// 	}

// 	if privKey == nil {
// 		logx.Warn("PEM: could not decrypt/parse private key in %s", path)
// 		return nil // per latest directive, do not emit cert-only
// 	}

// 	// pair with best leaf (prefer IsCA=false & key usages)
// 	leaf := pickLeafForKey(certs, privKey)
// 	if leaf == nil {
// 		// fallback: first cert
// 		leaf = certs[0]
// 	}

// 	// Build PKCS#12 (leaf only; chain not strictly required for import call)
// 	pw := randomPassword()
// 	pfx, err := p12.Encode(rand.Reader, privKey, leaf, nil, pw)
// 	if err != nil {
// 		logx.Warn("PEM: p12 encode failed for %s: %v", path, err)
// 		return nil
// 	}

// 	d := discoveryFromCert(types.SourcePEM, path, leaf)
// 	d.HasPrivateKey = true
// 	d.P12Raw = pfx
// 	d.P12Password = pw
// 	_ = usedPass // we don't store plaintext PEM key password; not needed after p12 build

// 	out = append(out, d)
// 	return out
// }

func ScanPEM(path string, data []byte, passwords []string) []types.Discovery {
    var out []types.Discovery
    hasKeyInline := false

    rest := data
    for {
        blk, rem := pem.Decode(rest)
        if blk == nil {
            break
        }
        rest = rem

        switch blk.Type {
        case "CERTIFICATE":
            d := discoveryFromDER(types.Source("pem"), path, "", "", blk.Bytes)
            if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
                d.Cert = c
            }
            d.HasPrivateKey = hasKeyInline // same file has a key block
            out = append(out, d)

        case "ENCRYPTED PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
            hasKeyInline = true
        }
    }

    return out
}



func parseAnyPEMPrivateKey(blk *pem.Block, password []byte) (any, error) {
	switch blk.Type {
	case "ENCRYPTED PRIVATE KEY":
		// PKCS#8 Encrypted
		return pkcs8.ParsePKCS8PrivateKey(blk.Bytes, password)
	case "PRIVATE KEY":
		// Unencrypted PKCS#8
		return x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY", "EC PRIVATE KEY":
		// Might be legacy-encrypted
		var der []byte
		var err error
		if x509.IsEncryptedPEMBlock(blk) {
			der, err = x509.DecryptPEMBlock(blk, password)
			if err != nil {
				return nil, err
			}
		} else {
			der = blk.Bytes
		}
		if blk.Type == "RSA PRIVATE KEY" {
			if k, e := x509.ParsePKCS1PrivateKey(der); e == nil {
				return k, nil
			}
		}
		if blk.Type == "EC PRIVATE KEY" {
			if k, e := x509.ParseECPrivateKey(der); e == nil {
				return k, nil
			}
		}
		// last resort try PKCS#8
		return x509.ParsePKCS8PrivateKey(der)
	default:
		return nil, errors.New("unsupported key type")
	}
}

func pickLeafForKey(certs []*x509.Certificate, key any) *x509.Certificate {
	pub := publicFromPrivate(key)
	if pub == nil {
		return nil
	}
	for _, c := range certs {
		if publicEqual(c.PublicKey, pub) && !c.IsCA {
			return c
		}
	}
	// relax: match any equal pubkey if no non-CA
	for _, c := range certs {
		if publicEqual(c.PublicKey, pub) {
			return c
		}
	}
	return nil
}

func publicFromPrivate(k any) any {
	switch t := k.(type) {
	case *x509.Certificate: // not expected
		return t.PublicKey
	default:
		// use x509 to marshal then compare bytes
		return extractPublicKey(k)
	}
}

func extractPublicKey(k any) any {
	switch kt := k.(type) {
	case interface{ Public() any }:
		return kt.Public()
	default:
		return nil
	}
}

func publicEqual(a, b any) bool {
	ab, _ := x509.MarshalPKIXPublicKey(a)
	bb, _ := x509.MarshalPKIXPublicKey(b)
	return ab != nil && bb != nil && bytes.Equal(ab, bb)
}

func randomPassword() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("%x", buf)
}

// Helper to build discovery from cert
func discoveryFromCert(src types.Source, path string, cert *x509.Certificate) types.Discovery {
	return types.Discovery{
		Source: src,
		Path:   path,
		DER:    cert.Raw,
		Cert:   cert,
	}
}
