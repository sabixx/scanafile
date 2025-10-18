// internal/importer/outage.go
package cm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	p12 "software.sslmate.com/src/go-pkcs12"

	"scanafile/internal/logx"
	"scanafile/internal/types"
)

type odCert struct {
	Certificate    string   `json:"certificate"`              // base64(der)
	ApplicationIDs []string `json:"applicationIds,omitempty"` // optional
}

type odReq struct {
	Certificates []odCert `json:"certificates"`
}

// pretty headers for debug
func headersString(h http.Header) string {
	var b bytes.Buffer
	for k, vv := range h {
		for _, v := range vv {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func stamp(outDir, prefix, ext string) string {
	_ = os.MkdirAll(outDir, 0o755)
	ts := time.Now().UTC().Format("20060102-150405.000Z")
	return filepath.Join(outDir, prefix+"-"+ts+"."+ext)
}

func pretty(b []byte) []byte {
	var buf bytes.Buffer
	if json.Indent(&buf, b, "", "  ") == nil {
		return buf.Bytes()
	}
	return b
}

// ImportOutageDetection uploads discovered public certificates to the OD inventory.
// - Pulls DER directly from d.DER when available
// - Else uses d.Cert.Raw if present
// - Else extracts a leaf from PKCS#12 (d.P12Raw + d.P12Password)
func ImportOutageDetection(
	ctx context.Context,
	baseURL, apiKey, outDir string,
	debug bool,
	findings []types.Discovery,
	applicationIDs []string,
) (int, error) {
	// Build payload
	var certs []odCert
	for _, d := range findings {
		var der []byte

		if len(d.DER) > 0 {
			der = d.DER
		} else if d.Cert != nil && len(d.Cert.Raw) > 0 {
			der = d.Cert.Raw
		} else if len(d.P12Raw) > 0 && d.P12Password != "" {
			if blocks, err := p12.ToPEM(d.P12Raw, d.P12Password); err == nil {
				// prefer a leaf (IsCA=false); else first CERT
				var first []byte
				for _, blk := range blocks {
					if blk.Type != "CERTIFICATE" || len(blk.Bytes) == 0 {
						continue
					}
					if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
						if !c.IsCA {
							der = blk.Bytes
							break
						}
					}
					if first == nil {
						first = blk.Bytes
					}
				}
				if der == nil && first != nil {
					der = first
				}
			}
		}

		if len(der) == 0 {
			continue
		}

		certs = append(certs, odCert{
			Certificate:    base64.StdEncoding.EncodeToString(der),
			ApplicationIDs: applicationIDs,
		})
	}

	if len(certs) == 0 {
		return 0, nil
	}

	// Per-item diagnostics to help spot problematic certs
	if debug {
		for i, oc := range certs {
			derBytes, _ := base64.StdEncoding.DecodeString(oc.Certificate)
			fp := sha256.Sum256(derBytes)
			cn := "<parse-failed>"
			na := "<parse-failed>"
			if c, err := x509.ParseCertificate(derBytes); err == nil {
				cn = c.Subject.CommonName
				na = c.NotAfter.Format(time.RFC3339)
			}
			logx.Debug("OD item[%d]: sha256=%s CN=%s NotAfter=%s appIDs=%v",
				i, hex.EncodeToString(fp[:])[:16]+"…", cn, na, oc.ApplicationIDs)
		}
	}

	url := strings.TrimRight(baseURL, "/") + "/outagedetection/v1/certificates"
	payload := odReq{Certificates: certs}
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("tppl-api-key", apiKey)

	if debug {
		fnReq := stamp(outDir, "od_import_req_raw", "json")
		_ = os.WriteFile(fnReq, pretty(raw), 0600)

		// Full call details (API key redacted length only)
		logx.Debug("HTTP %s %s", http.MethodPost, url)
		logx.Debug("Request headers:\naccept: application/json\ncontent-type: application/json\ntppl-api-key: <redacted:%d>", len(apiKey))
		logx.Debug("Request body (saved %s):\n%s", filepath.Base(fnReq), string(pretty(raw)))

		// cURL reproduction (API key redacted). Escape single quotes for POSIX shells.
		escaped := strings.ReplaceAll(string(raw), "'", "'\"'\"'")
		curlText := "curl --request POST \\\n" +
			"  --url " + url + " \\\n" +
			"  --header 'accept: application/json' \\\n" +
			"  --header 'content-type: application/json' \\\n" +
			"  --header 'tppl-api-key: <REDACTED>' \\\n" +
			"  --data '" + escaped + "'\n"
		fnCurl := stamp(outDir, "od_import_curl", "txt")
		_ = os.WriteFile(fnCurl, []byte(curlText), 0600)
		logx.Debug("cURL repro saved -> %s", filepath.Base(fnCurl))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if debug {
		fnResp := stamp(outDir, "od_import_resp_raw", "json")
		_ = os.WriteFile(fnResp, pretty(respBody), 0600)
		logx.Debug("Response %s", resp.Status)
		logx.Debug("Response headers:\n%s", headersString(resp.Header))
		logx.Debug("Response body saved -> %s", filepath.Base(fnResp))
	}

	if resp.StatusCode/100 != 2 && resp.StatusCode != 201 {
		// Optional isolation: try each certificate individually to find the failing one
		if debug && len(certs) > 1 && resp.StatusCode >= 500 {
			logx.Debug("OD bulk import failed %s; isolating by sending single items…", resp.Status)
			for i, oc := range certs {
				one := odReq{Certificates: []odCert{oc}}
				j, _ := json.Marshal(one)
				r, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(j))
				r.Header.Set("accept", "application/json")
				r.Header.Set("content-type", "application/json")
				r.Header.Set("tppl-api-key", apiKey)
				rs, err := http.DefaultClient.Do(r)
				if err != nil {
					logx.Debug(" isolate[%d]: request error: %v", i, err)
					continue
				}
				bb, _ := io.ReadAll(rs.Body)
				_ = rs.Body.Close()
				derBytes, _ := base64.StdEncoding.DecodeString(oc.Certificate)
				fp := sha256.Sum256(derBytes)
				shortFP := hex.EncodeToString(fp[:])[:16] + "…"
				if rs.StatusCode/100 == 2 || rs.StatusCode == 201 {
					logx.Debug(" isolate[%d]: OK (%s) sha256=%s", i, rs.Status, shortFP)
				} else {
					logx.Debug(" isolate[%d]: FAIL %s sha256=%s body=%s",
						i, rs.Status, shortFP, string(bb))
				}
			}
		}

		trunc := string(respBody)
		if len(trunc) > 4000 {
			trunc = trunc[:4000] + "...(truncated)"
		}
		return 0, fmt.Errorf("POST %s -> %s\n%s", url, resp.Status, trunc)
	}

	return len(certs), nil
}
