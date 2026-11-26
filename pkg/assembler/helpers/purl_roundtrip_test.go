package helpers

import "testing"

func TestGuacPkgPurlRoundTrip(t *testing.T) {
	for _, tt := range []struct{ name, version string }{
		{name: "Apache Commons Lang", version: "3.12.0"},
		{name: "zlib", version: "1.3.1#1"},
		{name: "pkg", version: "1.0?beta"},
		{name: "pkg", version: "1.0 100%"},
		{name: "a+b", version: "2.0+build"},
	} {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			version := tt.version
			got, err := PurlToPkg(GuacPkgPurl(tt.name, &version))
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != tt.name || got.Version == nil || *got.Version != tt.version {
				t.Errorf("round trip gave name %q version %v, want %q %q", got.Name, got.Version, tt.name, tt.version)
			}
		})
	}
}
