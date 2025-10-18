//go:build windows

package scanner

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"scanafile/internal/logx"
	"scanafile/internal/types"
)

// ScanWindowsStores enumerates Windows cert stores and returns discoveries with public certs only.
// mode: "none" | "user" | "machine" | "both"
func ScanWindowsStores(mode string) []types.Discovery {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "machine"
	}
	if mode == "none" {
		return nil
	}

	var stores []string
	switch mode {
	case "user":
		stores = []string{`Cert:\CurrentUser\My`}
	case "machine":
		stores = []string{`Cert:\LocalMachine\My`}
	case "both":
		stores = []string{`Cert:\CurrentUser\My`, `Cert:\LocalMachine\My`}
	default:
		stores = []string{`Cert:\LocalMachine\My`}
	}

	// Pass store list via env var to avoid -Command param binding issues
	ps := `
$ErrorActionPreference = 'SilentlyContinue'
$stores = ($env:SCANA_STORES -split ';') | Where-Object { $_ -and $_.Trim() -ne '' }
$all = @()
foreach ($s in $stores) {
  if ($s -and (Test-Path -LiteralPath $s)) {
    Get-ChildItem -LiteralPath $s | ForEach-Object {
      $all += [pscustomobject]@{
        Store        = $s
        FriendlyName = $_.FriendlyName
        HasPrivateKey= $_.HasPrivateKey
        PSPath       = $_.PSPath
        Thumbprint   = $_.Thumbprint
        Subject      = $_.Subject
        NotAfter     = $_.NotAfter
        NotBefore    = $_.NotBefore
        B64          = [Convert]::ToBase64String($_.RawData) # public cert (DER)
      }
    }
  }
}
$all | ConvertTo-Json -Depth 3
`

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
	cmd.Env = append(os.Environ(),
		"SCANA_STORES="+strings.Join(stores, ";"),
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		logx.Warn("CAPI enumerate failed: %v\n%s", err, string(out))
		return nil
	}

	// Unmarshal (array or single object)
	type item struct {
		Store         string `json:"Store"`
		FriendlyName  string `json:"FriendlyName"`
		HasPrivateKey bool   `json:"HasPrivateKey"`
		PSPath        string `json:"PSPath"`
		B64           string `json:"B64"`
	}
	var items []item
	if err := json.Unmarshal(out, &items); err != nil {
		var one item
		if err2 := json.Unmarshal(out, &one); err2 == nil && (one.PSPath != "" || one.B64 != "") {
			items = []item{one}
		} else {
			logx.Warn("CAPI JSON parse failed: %v\n%s", err, string(out))
			return nil
		}
	}

	var findings []types.Discovery
	for _, it := range items {
		b64 := strings.TrimSpace(it.B64)
		if b64 == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(der) == 0 {
			continue
		}

		// Build discovery with DER for OD and store metadata for playbook
		d := capiDiscovery(it.Store, it.FriendlyName, der)
		d.Path = it.PSPath // keep PSPath for uniqueness/debug
		// No PFX export attempt; we import as public cert only.

		// If you have a helper that parses x509, keep it (optional)
		if c, err := parseX509(der); err == nil && c != nil {
			d.Cert = c
		}

		// We intentionally DO NOT set P12Raw/P12Password or HasPrivateKey (leave false)
		findings = append(findings, d)
	}
	return findings
}

func capiDiscovery(capiStore, friendly string, der []byte) types.Discovery {
	return types.Discovery{
		Source:        types.SourceWinStore,
		Path:          friendly,
		DER:           der,    // this is what outage import uses
		HasPrivateKey: false,  // public-only for CAPI
		CAPIStore:     capiStore,
		CAPIFriendly:  friendly,
	}
}
