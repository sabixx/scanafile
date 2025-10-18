package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scanafile/internal/logx"
)

/* ---------- Types from main ---------- */

type ImportItem struct {
	Certificate                 string `json:"certificate,omitempty"`
	DekEncryptedPassword        string `json:"dekEncryptedPassword,omitempty"`
	DekEncryptedPrivateKey      string `json:"dekEncryptedPrivateKey,omitempty"`
	PasswordEncryptedPrivateKey string `json:"passwordEncryptedPrivateKey,omitempty"`
	PKCS12Keystore              string `json:"pkcs12Keystore,omitempty"`
}

type ImportReq struct {
	ImportInformation []ImportItem `json:"importInformation"`
	EdgeInstanceID    string       `json:"edgeInstanceId"`
	EncryptionKeyID   string       `json:"encryptionKeyId"`
}

type EdgeInstancesResp struct {
	EdgeInstances []struct {
		ID              string `json:"id"`
		EdgeStatus      string `json:"edgeStatus"`
		EncryptionKeyID string `json:"encryptionKeyId"`
	} `json:"edgeInstances"`
}

/* ---------- Public functions ---------- */
// headersString prints headers with tppl-api-key value redacted (keeps length).
func headersString(h http.Header) string {
	if h == nil {
		return ""
	}
	clone := h.Clone()
	if vals, ok := clone["Tppl-Api-Key"]; ok {
		key := strings.Join(vals, ",")
		clone["Tppl-Api-Key"] = []string{fmt.Sprintf("<redacted:%d>", len(key))}
	}
	var b bytes.Buffer
	for k, vals := range clone {
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(vals, ","))
	}
	return b.String()
}

func FetchLatestActiveEdge(ctx context.Context, base, edgesEP, apiKey, outDir string, debug bool) (edgeID, dekID string, err error) {
	url := strings.TrimRight(base, "/") + edgesEP
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("accept", "application/json")
	req.Header.Set("tppl-api-key", apiKey)

	if debug {
		logx.Debug("HTTP %s %s", http.MethodGet, url)
		logx.Debug("Request headers:\n%s", headersString(req.Header))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if debug {
		fn := stamp(outDir, "edges_resp_raw", "json")
		_ = os.WriteFile(fn, pretty(body), 0600)
		logx.Debug("Response %s", resp.Status)
		logx.Debug("Response headers:\n%s", headersString(resp.Header))
		logx.Debug("Response body (saved %s):\n%s", filepath.Base(fn), string(pretty(body)))
	}

	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("GET %s -> %s", url, resp.Status)
	}

	var out struct {
		EdgeInstances []struct {
			ID              string `json:"id"`
			EdgeStatus      string `json:"edgeStatus"`
			EncryptionKeyID string `json:"encryptionKeyId"`
		} `json:"edgeInstances"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", err
	}

	idx := -1
	for i := range out.EdgeInstances {
		if strings.EqualFold(out.EdgeInstances[i].EdgeStatus, "ACTIVE") {
			idx = i // last ACTIVE wins
		}
	}
	if idx < 0 {
		return "", "", fmt.Errorf("no ACTIVE edge instance found")
	}
	return out.EdgeInstances[idx].ID, out.EdgeInstances[idx].EncryptionKeyID, nil
}



func PostImportBatches(
    ctx context.Context,
    base, importEP, apiKey, outDir string, debug bool,
    reqBody ImportReq,
) (int, string, error) {
    raw, err := json.Marshal(reqBody)
    if err != nil {
        return 0, "", err
    }
    url := strings.TrimRight(base, "/") + importEP
    req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
    req.Header.Set("accept", "application/json")
    req.Header.Set("content-type", "application/json")
    req.Header.Set("tppl-api-key", apiKey)

    if debug {
        red := redactedImportReq(reqBody)
        redJSON, _ := json.MarshalIndent(red, "", "  ")
        fnReq := stamp(outDir, "import_req", "json")
        _ = os.WriteFile(fnReq, redJSON, 0600)
        logx.Debug("HTTP POST %s (tppl-api-key: <redacted>)", url)
        logx.Debug("Request saved -> %s (%d items)", filepath.Base(fnReq), len(reqBody.ImportInformation))
    }

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return 0, "", err
    }
    defer resp.Body.Close()

    b, _ := io.ReadAll(resp.Body)

    if debug {
        fnResp := stamp(outDir, "import_resp", "json")
        _ = os.WriteFile(fnResp, pretty(b), 0600)
        logx.Debug("Response saved -> %s (%s, %d bytes)", filepath.Base(fnResp), resp.Status, len(b))
    }

    if resp.StatusCode/100 != 2 && resp.StatusCode != 201 {
        trunc := string(b)
        if len(trunc) > 2000 {
            trunc = trunc[:2000] + "...(truncated)"
        }
        return 0, "", fmt.Errorf("POST %s -> %s\n%s", url, resp.Status, trunc)
    }

    // Parse job id
    var jr struct{ ID string `json:"id"` }
    _ = json.Unmarshal(b, &jr)
    if jr.ID != "" {
        logx.Debug("Import job id: %s", jr.ID)
    }

    return len(reqBody.ImportInformation), jr.ID, nil
}


/* ---------- Helpers ---------- */

func writeDebug(outDir, name string, b []byte) {
	_ = os.MkdirAll(outDir, 0o755)
	_ = os.WriteFile(filepath.Join(outDir, name), b, 0600)
}

func stamp(outDir, prefix, ext string) string {
	_ = os.MkdirAll(outDir, 0o755)
	ts := time.Now().UTC().Format("20060102-150405.000Z")
	return filepath.Join(outDir, fmt.Sprintf("%s-%s.%s", prefix, ts, ext))
}

func pretty(b []byte) []byte {
	var buf bytes.Buffer
	if json.Indent(&buf, b, "", "  ") == nil {
		return buf.Bytes()
	}
	return b
}

func redactedImportReq(in ImportReq) ImportReq {
	out := in // shallow copy
	redact := func(s string) string {
		if s == "" {
			return ""
		}
		return fmt.Sprintf("<redacted:%d>", len(s))
	}
	for i := range out.ImportInformation {
		out.ImportInformation[i].DekEncryptedPassword = redact(out.ImportInformation[i].DekEncryptedPassword)
		out.ImportInformation[i].DekEncryptedPrivateKey = redact(out.ImportInformation[i].DekEncryptedPrivateKey)
		out.ImportInformation[i].PasswordEncryptedPrivateKey = redact(out.ImportInformation[i].PasswordEncryptedPrivateKey)
		if out.ImportInformation[i].PKCS12Keystore != "" {
			out.ImportInformation[i].PKCS12Keystore = "<base64:pkcs12:redacted>"
		}
		if out.ImportInformation[i].Certificate != "" {
			out.ImportInformation[i].Certificate = "<pem:cert:redacted>"
		}
	}
	return out
}

