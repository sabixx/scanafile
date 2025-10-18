// internal/pipeline/pipeline.go
package pipeline

import (
	"runtime"

	"scanafile/internal/types"
)

func DedupByFingerprint(in []types.Discovery) []types.Discovery {
	seen := make(map[string]struct{}, len(in))
	out := make([]types.Discovery, 0, len(in))
	for _, d := range in {
		fp := d.Meta.SHA256
		if fp == "" {
			out = append(out, d)
			continue
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, d)
	}
	return out
}

func HostOS() string {
	return runtime.GOOS
}
