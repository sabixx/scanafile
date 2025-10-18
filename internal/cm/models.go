package cm

// ---------- Keys ----------
type EncryptionKeysResponse struct {
    EncryptionKeys []struct {
        ID         string `json:"id"`
        CompanyID  string `json:"companyId"`
        Key        string `json:"key"`
        Algorithm  string `json:"keyAlgorithm"`
    } `json:"encryptionKeys"`
}

// ---------- Teams ----------
type TeamsResponse struct {
    Teams []struct {
        ID   string `json:"id"`
        Name string `json:"name"`
    } `json:"teams"`
}

// ---------- Edge Instances ----------
type EdgeInstancesResponse struct {
    EdgeInstances []struct {
        ID string `json:"id"`
    } `json:"edgeInstances"`
}

// ---------- Machines ----------
type Machine struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}

type MachinesResponse struct {
    Machines []Machine `json:"machines"`
}

type CreateMachineRequest struct {
    ConnectionDetails struct {
        CredentialType   string `json:"credentialType"`
        HostnameOrAddress string `json:"hostnameOrAddress"`
    } `json:"connectionDetails"`
    DekID         string `json:"dekId"`
    EdgeInstanceID string `json:"edgeInstanceId"`
    Name          string `json:"name"`
    OwningTeamID  string `json:"owningTeamId"`
    PluginID      string `json:"pluginId,omitempty"`
    Status        string `json:"status"`
}

type GenericID struct {
    ID string `json:"id"`
}

// ---------- Imports ----------
type ImportPEMRequest struct {
    CertificatePEM string            `json:"certificatePem"`
    Metadata       map[string]string `json:"metadata,omitempty"`
}
