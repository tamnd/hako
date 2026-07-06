package policy

import (
	"os"
	"path/filepath"
	"sort"
)

// systemRead is the read set every preset needs so binaries, dynamic
// linkers and locale data resolve. Paths that do not exist on a given
// OS are harmless.
func systemRead() []string {
	return []string{
		"/usr", "/bin", "/sbin", "/opt", "/etc", "/var", "/tmp",
		"/System", "/Library", "/private",
		"/lib", "/lib64", "/proc", "/run",
	}
}

// Preset returns a built-in policy by name. cwd anchors the working
// tree paths. The bool reports whether the name exists.
func Preset(name, cwd string) (*Policy, bool) {
	tmp := filepath.Clean(os.TempDir())
	switch name {
	case "restricted":
		return &Policy{
			Name: "restricted",
			FS: FS{
				Read: append(systemRead(), cwd),
			},
			Net: Net{Allow: new(false)},
		}, true
	case "standard":
		return &Policy{
			Name: "standard",
			FS: FS{
				Read:  []string{"/"},
				Write: []string{cwd, "/tmp", tmp},
			},
			Net: Net{Allow: new(false)},
		}, true
	case "net":
		return &Policy{
			Name: "net",
			FS: FS{
				Read:  []string{"/"},
				Write: []string{cwd, "/tmp", tmp},
			},
			Net: Net{Allow: new(true)},
		}, true
	case "dev":
		h := home()
		return &Policy{
			Name: "dev",
			FS: FS{
				Read: []string{"/"},
				Write: []string{
					cwd, "/tmp", tmp,
					filepath.Join(h, ".cache"),
					filepath.Join(h, "Library", "Caches"),
					filepath.Join(h, "go", "pkg"),
				},
			},
			Net: Net{Allow: new(true)},
		}, true
	}
	return nil, false
}

// PresetNames lists built-in presets in stable order.
func PresetNames() []string {
	names := []string{"restricted", "standard", "net", "dev"}
	sort.Strings(names)
	return names
}

// PresetSummary is a one-line description for `hako presets`.
func PresetSummary(name string) string {
	switch name {
	case "restricted":
		return "read cwd and system dirs only, no writes, no network"
	case "standard":
		return "read everything (minus secrets), write cwd and tmp, no network"
	case "net":
		return "standard plus outbound network"
	case "dev":
		return "net plus write access to build caches"
	}
	return ""
}
