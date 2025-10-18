package main

import (
	"context"
	//"encoding/base64"
    //"encoding/pem"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"scanafile/internal/export"
	"scanafile/internal/logx"
	"scanafile/internal/pipeline"
	"scanafile/internal/scanner"
	"scanafile/internal/types"
	"scanafile/internal/cm" 
)

var (
	version = "2.3.6" // override at build: -ldflags "-X main.version=0.3.3+build"

	// general
	flagDebug      = flag.Bool("debug", false, "debug logging & base64 capture")
	flagDryRun     = flag.Bool("dry-run", false, "do not call CM; just log")
	flagVersion    = flag.Bool("version", false, "print version and exit")
	flagNoPlaybook = flag.Bool("no-playbook", false, "do not write playbook.yaml")

	// output / import behavior
	flagOutDir = flag.String("out-dir", defaultOutDir(), "output directory for logs/playbook")

	// CM base/region + endpoint overrides
	flagCMRegion = flag.String("cm-region", "us", "CM SaaS region code: us|au|ca|eu|sg|uk (ignored if --cm-base set)")
	flagCMBase   = flag.String("cm-base", "", "CM base URL (e.g., https://api.venafi.cloud). If set, overrides --cm-region")
	flagCMKey    = flag.String("cm-key", "", "CM API key (or SCANAFI_API_KEY env)")
	flagEdgesEP  = flag.String("cm-edges", "/v1/edgeinstances", "CM edge instances path")
	flagImportEP = flag.String("cm-import", "/v1/certificates/imports", "CM import-with-keys path")

	// discovery
	flagWin = flag.String("win-store", "machine", "Windows stores to scan: none|user|machine|both")
	flagMax = flag.Int64("max-file-bytes", 10<<20, "max file size to read")

	// passwords
	flagPassFile = flag.String("passwords-file", "", "passwords file (one per line)")
	flagPassURL  = flag.String("passwords-url", "", "passwords URL (raw text)")
	flagPass     multiFlag
	flagPath     multiFlag

	//appIDs := []string{} // optionally fill with application IDs if you want assignment
	appIDs = []string{"75da18a0-a8c0-11f0-a7d6-9bbf8462d37d"}
)

type multiFlag []string

func (m *multiFlag) String() string     { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func defaultOutDir() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\scanafi-file-scan`
	}
	return "/var/log/scanafi-file-scan"
}

func main() {
	flag.Var(&flagPass, "password", "add a password candidate (repeatable)")
	flag.Var(&flagPath, "path", "path to scan (repeatable)")
	flag.Parse()

	// figure out API key: CLI > env > (optional) fallback or error
	if strings.TrimSpace(*flagCMKey) == "" {
		if v := strings.TrimSpace(os.Getenv("SCANAFI_API_KEY")); v != "" {
			*flagCMKey = v
		}
	}

	if strings.TrimSpace(*flagCMKey) == "" {
		// either pick a hard fallback or keep current behavior (scan-only)
		// Option A (strict, recommended): fail unless provided
		logx.Warn("No API key provided – running in SCAN-ONLY mode (no uploads). Set --cm-key or SCANAFI_API_KEY to enable uploads.")
		*flagDryRun = true

		// Option B (NOT recommended): uncomment to force a fallback dev key
		// *flagCMKey = "b5c4ea11-09a9-4a63-b115-e788bc85cb1a"
	}

	if *flagVersion {
		fmt.Println(version)
		return
	}

	logx.DebugEnabled = *flagDebug
	logx.Info("scanafile v%s starting (debug=%v)", version, *flagDebug)

	// API key
	if v := os.Getenv("SCANAFI_API_KEY"); v != "" && *flagCMKey == "" {
		*flagCMKey = v
	}
	if strings.TrimSpace(*flagCMKey) == "" {
		logx.Warn("No API key provided – running in SCAN-ONLY mode (no uploads). Set --cm-key or SCANAFI_API_KEY to enable uploads.")
		*flagDryRun = true
	}

	// require something to scan
	if len(flagPath) == 0 && *flagWin == "none" {
		logx.Error("no paths and --win-store=none; nothing to do")
		os.Exit(2)
	}

	// CM base (region -> base)
	cmBase := resolveCMBase(*flagCMBase, *flagCMRegion)
	logx.Info("CM Base: %s", cmBase)

	// Password candidates
	passwords := loadPasswords(*flagPassFile, *flagPassURL, flagPass)
	if *flagDebug {
		logx.Info("password candidates loaded: %d", len(passwords))
	}

	// 1) SCAN ONLY
	findings := scanAll(passwords)

	// 2) PLAYBOOK (default on)
	if !*flagNoPlaybook {
		host := hostname()
		if dst, err := export.WritePlaybook(*flagOutDir, host, findings); err != nil {
			logx.Warn("playbook.yaml write failed: %v", err)
		} else {
			logx.Info("playbook written: %s", dst)
		}
	} else {
		logx.Info("playbook output suppressed (--no-playbook)")
	}

	// 3) IMPORT (if not dry-run)
	if *flagDryRun {
		logx.Info("DRY-RUN enabled: skipping upload to %s%s", cmBase, *flagImportEP)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var odAppIDs []string
	odAppIDs = []string{"75da18a0-a8c0-11f0-a7d6-9bbf8462d37d"}

	n, err := cm.ImportOutageDetection(ctx, cmBase, *flagCMKey, *flagOutDir, *flagDebug, findings, odAppIDs)

	// (drop CAPI discoveries from OD payload for testing)
	// filtered := make([]types.Discovery, 0, len(findings))
	// for _, d := range findings {
	// 	if d.Source == types.SourceWinStore {
	// 		if *flagDebug { logx.Debug("OD-skip (CAPI): %s", d.CAPIFriendly) }
	// 		continue
	// 	}
	// 	filtered = append(filtered, d)
	// }
	// n, err := cm.ImportOutageDetection(ctx, cmBase, *flagCMKey, *flagOutDir, *flagDebug, filtered, odAppIDs)


	if err != nil {
		logx.Warn("Outage Detection import failed: %v", err)
	} else {
		logx.Info("Outage Detection import complete: %d certificates submitted", n)
	}

	// edgeID, dekID, err := importer.FetchLatestActiveEdge(ctx, cmBase, *flagEdgesEP, *flagCMKey, *flagOutDir, *flagDebug)
	// if err != nil {
	// 	logx.Warn("could not resolve ACTIVE edge instance: %v", err)
	// 	return
	// }
	// logx.Debug("Using EdgeInstance: %s (DEK=%s)", edgeID, dekID)

	// items := buildImportItemsFromFindings(findings)
	// if len(items) == 0 {
	// 	logx.Info("No importable items (with private key + P12) found. Done.")
	// 	return
	// }

	// total := 0
	// const batchSize = 100
	// for i := 0; i < len(items); i += batchSize {
	// 	j := i + batchSize
	// 	if j > len(items) {
	// 		j = len(items)
	// 	}
	// 	req := importer.ImportReq{
	// 		ImportInformation: items[i:j],
	// 		EdgeInstanceID:    edgeID,
	// 		EncryptionKeyID:   dekID,
	// 	}
	// 	n, _, err := importer.PostImportBatches(
	// 		ctx, cmBase, *flagImportEP, *flagCMKey, *flagOutDir, *flagDebug, req,
	// 	)

	// 	if err != nil {
	// 		logx.Warn("import batch %d-%d failed: %v", i, j-1, err)
	// 		continue
	// 	}
	// 	total += n
	// 	logx.Debug("Imported batch %d-%d (%d items)", i, j-1, n)
	// }

	// logx.Info("Done. Imported items total=%d", total)
}

// ---------------- breakdown funcs ----------------

func scanAll(passwords []string) []types.Discovery {
	var findings []types.Discovery

	// Filesystem
	for _, base := range flagPath {
		base = filepath.Clean(base)
		filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !*flagDebug && scanner.SkipPath(p) {
				return nil
			}
			if *flagMax > 0 {
				if st, e := os.Stat(p); e == nil && st.Size() > *flagMax {
					return nil
				}
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			switch ext := strings.ToLower(filepath.Ext(p)); {
			case scanner.LooksLikePEM(data):
				findings = append(findings, scanner.ScanPEM(p, data, passwords)...)
			case ext == ".p12" || ext == ".pfx":
				if f, ok := scanner.ScanPKCS12(p, data, passwords); ok {
					findings = append(findings, f...)
				}
			case ext == ".jks":
				if f, ok := scanner.ScanJKS(p, data, passwords); ok {
					findings = append(findings, f...)
				}
			}
			return nil
		})
	}

	// Windows CAPI
	findings = append(findings, scanner.ScanWindowsStores(*flagWin)...)

	// Dedup + debug b64
	findings = pipeline.DedupByFingerprint(findings)
	if *flagDebug {
		pipeline.AddDebugB64(findings)
		pipeline.DumpDebugFindings(*flagOutDir, findings)
	}
	logx.Info("Findings: %d", len(findings))
	return findings
}

type edgeInstancesResp struct {
	EdgeInstances []struct {
		ID              string `json:"id"`
		EdgeStatus      string `json:"edgeStatus"`
		EncryptionKeyID string `json:"encryptionKeyId"`
	} `json:"edgeInstances"`
}

// func fetchLatestActiveEdge(ctx context.Context, base, edgesEP, apiKey string) (edgeID, dekID string, err error) {
// 	url := strings.TrimRight(base, "/") + edgesEP
// 	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
// 	req.Header.Set("accept", "application/json")
// 	req.Header.Set("tppl-api-key", apiKey)
// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		return "", "", err
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode/100 != 2 {
// 		b, _ := io.ReadAll(resp.Body)
// 		return "", "", fmt.Errorf("GET %s -> %s: %s", url, resp.Status, string(b))
// 	}
// 	var out edgeInstancesResp
// 	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
// 		return "", "", err
// 	}
// 	// last ACTIVE
// 	idx := -1
// 	for i := range out.EdgeInstances {
// 		if strings.EqualFold(out.EdgeInstances[i].EdgeStatus, "ACTIVE") {
// 			idx = i
// 		}
// 	}
// 	if idx < 0 {
// 		return "", "", fmt.Errorf("no ACTIVE edge instance found")
// 	}
// 	return out.EdgeInstances[idx].ID, out.EdgeInstances[idx].EncryptionKeyID, nil
// }

type importItem struct {
	Certificate                 string `json:"certificate,omitempty"`
	DekEncryptedPassword        string `json:"dekEncryptedPassword,omitempty"`
	DekEncryptedPrivateKey      string `json:"dekEncryptedPrivateKey,omitempty"`
	PasswordEncryptedPrivateKey string `json:"passwordEncryptedPrivateKey,omitempty"`
	PKCS12Keystore              string `json:"pkcs12Keystore,omitempty"`
}

type importReq struct {
	ImportInformation []importItem `json:"importInformation"`
	EdgeInstanceID    string       `json:"edgeInstanceId"`
	EncryptionKeyID   string       `json:"encryptionKeyId"`
}

func postImportBatches(ctx context.Context, base, importEP, apiKey string, reqBody importReq) (int, error) {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return 0, err
	}
	url := strings.TrimRight(base, "/") + importEP
	req, _ := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(body)))
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("tppl-api-key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 && resp.StatusCode != 201 {
		return 0, fmt.Errorf("POST %s -> %s: %s", url, resp.Status, string(b))
	}
	// Assume success for all items in the batch
	return len(reqBody.ImportInformation), nil
}

// -------- helpers --------

func resolveCMBase(explicit, region string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return strings.TrimRight(explicit, "/")
	}
	switch strings.ToLower(strings.TrimSpace(region)) {
	case "us", "":
		return "https://api.venafi.cloud"
	case "au":
		return "https://api.au.venafi.cloud"
	case "ca":
		return "https://api.ca.venafi.cloud"
	case "eu":
		return "https://api.eu.venafi.cloud"
	case "sg":
		return "https://api.sg.venafi.cloud"
	case "uk":
		return "https://api.uk.venafi.cloud"
	default:
		return "https://api.venafi.cloud"
	}
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown-host"
	}
	return h
}

func loadPasswords(file, url string, cli multiFlag) []string {
	pw := []string{""}
	// CLI
	pw = append(pw, cli...)

	// local file
	if f := strings.TrimSpace(file); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			pw = append(pw, parsePasswordLines(string(b))...)
		} else {
			logx.Warn("could not read passwords file %s: %v", f, err)
		}
	}

	// URL (supports GitHub raw + optional GITHUB_TOKEN)
	if u := strings.TrimSpace(url); u != "" {
		req, _ := http.NewRequest("GET", u, nil)
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Accept", "application/vnd.github.raw+json")
		}
		if resp, err := http.DefaultClient.Do(req); err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			if body, _ := io.ReadAll(resp.Body); len(body) > 0 {
				pw = append(pw, parsePasswordLines(string(body))...)
			}
		} else if err != nil {
			logx.Warn("could not fetch passwords url: %v", err)
		}
	}

	// common demo defaults at the end
	pw = append(pw, "1234356677", "changeit", "password", "Password1", "admin", "test")
	return dedupStrings(pw)
}

func parsePasswordLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
