// Package inventory builds the list of packages a target depends on, using Syft.
package inventory

import (
	"context"
	"fmt"
	"sort"

	"github.com/anchore/syft/syft"
	_ "modernc.org/sqlite" // Syft needs a registered SQLite driver to read newer RPM databases
)

// Package is one dependency found in the target.
type Package struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Type      string   `json:"type"`
	PURL      string   `json:"purl"`
	Locations []string `json:"locations,omitempty"`
	Image     string   `json:"image,omitempty"` // container image the package was found in (--images)
}

// Collect catalogs every package in target. Target is anything Syft accepts:
// a directory, a file, or a container image reference such as "alpine:3.19".
func Collect(ctx context.Context, target string) ([]Package, error) {
	return collect(ctx, target, syft.DefaultGetSourceConfig())
}

// CollectImage catalogs a container image pulled straight from its
// registry, without looking for a local Docker or Podman daemon.
func CollectImage(ctx context.Context, ref string) ([]Package, error) {
	return collect(ctx, ref, syft.DefaultGetSourceConfig().WithSources("registry"))
}

func collect(ctx context.Context, target string, cfg *syft.GetSourceConfig) ([]Package, error) {
	src, err := syft.GetSource(ctx, target, cfg)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", target, err)
	}
	defer src.Close()

	s, err := syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig())
	if err != nil {
		return nil, fmt.Errorf("catalog %q: %w", target, err)
	}

	var out []Package
	for _, p := range s.Artifacts.Packages.Sorted() {
		var locs []string
		seen := map[string]bool{}
		for _, l := range p.Locations.ToSlice() {
			if !seen[l.RealPath] {
				seen[l.RealPath] = true
				locs = append(locs, l.RealPath)
			}
		}
		sort.Strings(locs)
		out = append(out, Package{
			Name:      p.Name,
			Version:   p.Version,
			Type:      string(p.Type),
			PURL:      p.PURL,
			Locations: locs,
		})
	}
	return out, nil
}
