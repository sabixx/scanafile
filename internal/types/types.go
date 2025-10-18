package types

import "crypto/x509"

// Source is a string alias so switch/case with string literals compiles.
type Source string

const (
	SourcePEM      Source = "pem"
	SourcePKCS12   Source = "pkcs12"
	SourceJKS      Source = "jks"
	SourceWinStore Source = "winstore"
)

// CertMeta holds parsed, human-friendly cert metadata (used by pipelines/exports).
type CertMeta struct {
	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
	Serial    string `json:"serial,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	IsCA      bool   `json:"isCa,omitempty"`
}

// Discovery is the unit produced by scanners and consumed by pipeline/export.
type Discovery struct {
	// Identity & origin
	Source Source `json:"source"`
	Path   string `json:"path,omitempty"`
	Alias  string `json:"alias,omitempty"` // keystore alias / CAPI friendly name
	Scope  string `json:"scope,omitempty"` // "fs", "file", "capi", etc.

	// Parsed certificate (some scanners set this directly)
	Cert *x509.Certificate `json:"-"`

	// Raw cert bytes (DER) + quick meta used in dedup/export
	DER  []byte   `json:"-"`
	Meta CertMeta `json:"meta"`

	// Private key / keystore info (filled only when we actually have the key)
	HasPrivateKey bool   `json:"hasPrivateKey,omitempty"`

	// PKCS#12 (used for import-with-keys API)
	P12Raw      []byte `json:"-"`
	P12Password string `json:"-"`

	// PEM key captured/decrypted from PEM files (if applicable)
	PEMPrivateKey []byte `json:"-"`

	// JKS specifics (for playbook output)
	JKSAlias    string `json:"-"`
	JKSPassword string `json:"-"`

	// Windows CAPI specifics (for playbook output)
	CAPIStore     string `json:"-"`
	CAPIFriendly  string `json:"-"`
	// Set true when export of private key failed; playbook should mark capiIsNonExportable: True
	CAPIExportFailed bool `json:"-"`

	// Optional debug helpers
	DebugB64 string `json:"-"`
}
