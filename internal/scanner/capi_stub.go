//go:build !windows

package scanner

import "scanafile/internal/types"

func ScanWindowsStores(which string) []types.Discovery { return nil }
