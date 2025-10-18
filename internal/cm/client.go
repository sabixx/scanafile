package cm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

type Client struct {
	base   string
	key    string
	http   *http.Client
	DryRun bool

	EdgeInstancesEP string // "/v1/edgeinstances"
	EdgeImportEP    string // "/v1/certificates/imports"
}

func New(base, apiKey string) *Client {
	return &Client{
		base:           trimSlash(base),
		key:            apiKey,
		http:           &http.Client{Timeout: 30 * time.Second},
		EdgeInstancesEP: "/v1/edgeinstances",
		EdgeImportEP:    "/v1/certificates/imports",
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, c.base+path, r)
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")
	req.Header.Set("tppl-api-key", c.key)
	return c.http.Do(req)
}

/* -------- edgeinstances -------- */

type EdgeInstance struct {
	ID               string    `json:"id"`
	EdgeStatus       string    `json:"edgeStatus"`
	ModificationDate time.Time `json:"modificationDate"`
	EncryptionKeyId  string    `json:"encryptionKeyId"`
}

type listEdgeResp struct {
	EdgeInstances []EdgeInstance `json:"edgeInstances"`
}

func (c *Client) LastActiveEdge(ctx context.Context) (*EdgeInstance, error) {
	resp, err := c.do(ctx, "GET", c.EdgeInstancesEP, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var le listEdgeResp
	if err := json.NewDecoder(resp.Body).Decode(&le); err != nil {
		return nil, err
	}
	var active []EdgeInstance
	for _, e := range le.EdgeInstances {
		if e.EdgeStatus == "ACTIVE" {
			active = append(active, e)
		}
	}
	if len(active) == 0 {
		return nil, fmt.Errorf("no ACTIVE edge instance found")
	}
	sort.Slice(active, func(i, j int) bool {
		return active[i].ModificationDate.Before(active[j].ModificationDate)
	})
	e := active[len(active)-1] // last ACTIVE
	return &e, nil
}

/* -------- imports -------- */

type ImportItem struct {
	// For our flow we only need the P12 and its password (plain in dekEncryptedPassword)
	PKCS12Keystore       string `json:"pkcs12Keystore,omitempty"`
	DekEncryptedPassword string `json:"dekEncryptedPassword,omitempty"`
	// Other fields exist but we are not using them in this flow:
	// Certificate, DekEncryptedPrivateKey, PasswordEncryptedPrivateKey
}

type ImportReq struct {
	EdgeInstanceId  string       `json:"edgeInstanceId"`
	EncryptionKeyId string       `json:"encryptionKeyId"`
	ImportInfo      []ImportItem `json:"importInformation"`
}

func (c *Client) ImportCertificatesWithKeys(ctx context.Context, edgeID, dekID string, items []ImportItem) error {
	if c.DryRun {
		return nil
	}
	req := ImportReq{
		EdgeInstanceId:  edgeID,
		EncryptionKeyId: dekID,
		ImportInfo:      items,
	}
	resp, err := c.do(ctx, "POST", c.EdgeImportEP, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("import failed: %s", string(b))
	}
	return nil
}
