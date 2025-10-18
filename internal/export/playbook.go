// internal/export/playbook.go
package export

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
	"scanafile/internal/types"
)

// type Playbook struct {
// 	Config struct {
// 		Connection struct {
// 			Platform    string `yaml:"platform"`
// 			Credentials struct {
// 				APIKey string `yaml:"apiKey"`
// 			} `yaml:"credentials"`
// 		} `yaml:"connection"`
// 		CertificateTasks []Task `yaml:"certificateTasks"`
// 	} `yaml:"config"`
// }


type Playbook struct {
	Config struct {
		Connection struct {
			Platform    string `yaml:"platform"`
			Credentials struct {
				APIKey string `yaml:"apiKey"`
			} `yaml:"credentials"`
		} `yaml:"connection"`
	} `yaml:"config"`
	CertificateTasks []Task `yaml:"certificateTasks"` // <-- moved to top-level
}

type Task struct {
	Name        string `yaml:"name"`
	RenewBefore string `yaml:"renewBefore"`
	Request     struct {
		CSR     string `yaml:"csr"`
		Subject struct {
			CommonName   string   `yaml:"commonName"`
			Country      string   `yaml:"country,omitempty"`
			Locality     string   `yaml:"locality,omitempty"`
			State        string   `yaml:"state,omitempty"`
			Organization string   `yaml:"organization,omitempty"`
			OrgUnits     []string `yaml:"orgUnits,omitempty"`
		} `yaml:"subject"`
		Zone string `yaml:"zone"`
	} `yaml:"request"`
	Installations []any `yaml:"installations"`
}

func WritePlaybook(outDir, host string, ds []types.Discovery) (string, error) {
	var pb Playbook
	pb.Config.Connection.Platform = "vaas"
	pb.Config.Connection.Credentials.APIKey = `{{ Env "SCANAFI_API_KEY" }}`

	for i, d := range ds {
		t := Task{
			Name:        "task-" + host + "-" + itoa(i),
			RenewBefore: "31d",
		}

		// CSR & subject copied from discovered cert
		t.Request.CSR = "local"
		if d.Cert != nil {
			sub := d.Cert.Subject
			cn := sub.CommonName
			if cn == "" && len(d.Cert.DNSNames) > 0 { cn = d.Cert.DNSNames[0] }
			t.Request.Subject.CommonName = cn
			if len(sub.Country) > 0 { t.Request.Subject.Country = sub.Country[0] }
			if len(sub.Locality) > 0 { t.Request.Subject.Locality = sub.Locality[0] }
			if len(sub.Province) > 0 { t.Request.Subject.State = sub.Province[0] }
			if len(sub.Organization) > 0 { t.Request.Subject.Organization = sub.Organization[0] }
			if len(sub.OrganizationalUnit) > 0 {
				t.Request.Subject.OrgUnits = append([]string{}, sub.OrganizationalUnit...)
			}
		}

		// Zone comes from environment at runtime (no hard-coded default)
		t.Request.Zone = `{{ Env "SCANAFI_ZONE" }}`

		switch string(d.Source) {
		case "pem", "PEM":
		    keyFile := d.Path
			if !d.HasPrivateKey {
				// no private key inline; point to a sidecar key file
				keyFile = absPath(d.Path) + ".key" }
			t.Installations = append(t.Installations, map[string]any{
				"format":             "PEM",
				"file":               absPath(d.Path),
				"chainFile":          "",
				"keyFile":            keyFile,
				"afterInstallAction": "echo Success!!!",
			})

		case "pkcs12", "PKCS12":
			// include discovered PKCS#12 password
			inst := map[string]any{
				"format":             "PKCS12",
				"file":               absPath(d.Path),
				"afterInstallAction": "echo Success!!!",
			}
			if d.P12Password != "" {
				inst["p12Password"] = d.P12Password
			}
			t.Installations = append(t.Installations, inst)

		case "jks", "JKS":
			inst := map[string]any{
				"format":             "JKS",
				"file":               absPath(d.Path),
				"afterInstallAction": "echo Success!!!",
			}
			// include discovered JKS password & alias when available
			if d.JKSPassword != "" {
				inst["jksPassword"] = d.JKSPassword
			}
			if d.JKSAlias != "" {
				inst["jksAlias"] = d.JKSAlias
			}
			t.Installations = append(t.Installations, inst)

		case "winstore", "WinStore", "CAPI":
			t.Installations = append(t.Installations, map[string]any{
				"format":              "CAPI",
				"capiLocation":        d.CAPIStore,
				"capiFriendlyName":    d.CAPIFriendly,
				"capiIsNonExportable": true, // per your instruction: always True
			})
		}

		pb.CertificateTasks = append(pb.CertificateTasks, t)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil { return "", err }
	dst := filepath.Join(outDir, "playbook.yaml")
	b, _ := yaml.Marshal(pb)
	if err := os.WriteFile(dst, b, 0o644); err != nil { return "", err }
	return dst, nil
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }

func absPath(p string) string {
    if p == "" {
        return ""
    }
    if ap, err := filepath.Abs(p); err == nil {
        return ap
    }
    return p
}
