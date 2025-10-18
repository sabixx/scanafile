package pipeline

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"scanafile/internal/logx"
	"scanafile/internal/types"
)

func AddDebugB64(ds []types.Discovery) {
	for i := range ds {
		if ds[i].DebugB64 == "" && len(ds[i].DER) > 0 {
			ds[i].DebugB64 = base64.StdEncoding.EncodeToString(ds[i].DER)
		}
	}
}

// Writes a JSONL file with full context; also logs each line at DEBUG.
func DumpDebugFindings(outDir string, ds []types.Discovery) {
	if len(ds) == 0 {
		return
	}
	// Stable order: by Source, then Path, then Alias
	sort.Slice(ds, func(i, j int) bool {
		if ds[i].Source != ds[j].Source {
			return ds[i].Source < ds[j].Source
		}
		if ds[i].Path != ds[j].Path {
			return ds[i].Path < ds[j].Path
		}
		return ds[i].Alias < ds[j].Alias
	})
	fn := filepath.Join(outDir, "found-debug.jsonl")
	f, err := os.Create(fn)
	if err != nil {
		logx.Warn("debug dump open failed: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, d := range ds {
		// Only dump password in debug contexts; caller ensures this is only called when --debug
		_ = enc.Encode(d)
		b, _ := json.Marshal(d)
		logx.Debug("FOUND %s", string(b))
	}
	logx.Info("debug dump written: %s", fn)
}
