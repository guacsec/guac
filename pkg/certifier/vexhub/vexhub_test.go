//
// Copyright 2026 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vexhub

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// noopLogger satisfies the logger interface used by getArchiveURL in tests.
type noopLogger struct{}

func (n noopLogger) Infof(_ string, _ ...interface{}) {}

// buildTestArchive creates a tar.gz archive with index.json and optional VEX files.
// All entries are nested under a "vexhub-main/" top-level directory (simulating a
// GitHub archive download).
func buildTestArchive(t *testing.T, indexJSON string, vexFiles map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	writeFile := func(name, content string) {
		hdr := &tar.Header{
			Name: "vexhub-main/" + name,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}

	writeFile("index.json", indexJSON)
	for path, content := range vexFiles {
		writeFile(path, content)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// buildArchiveWithoutIndex creates a tar.gz that intentionally omits index.json.
func buildArchiveWithoutIndex(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{Name: "vexhub-main/other.json", Mode: 0644, Size: 2}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestGetArchiveURL verifies that getArchiveURL correctly filters spec versions
// and parses the // subdirectory separator.
func TestGetArchiveURL(t *testing.T) {
	logger := noopLogger{}
	tests := []struct {
		name       string
		manifest   Manifest
		wantURL    string
		wantSubdir string
	}{
		{
			name: "supported spec version simple URL",
			manifest: Manifest{
				Versions: []ManifestVersion{{
					SpecVersion: "0.1",
					Locations:   []ManifestLocation{{URL: "https://example.com/vex.tar.gz"}},
				}},
			},
			wantURL:    "https://example.com/vex.tar.gz",
			wantSubdir: "",
		},
		{
			name:       "empty manifest",
			manifest:   Manifest{},
			wantURL:    "",
			wantSubdir: "",
		},
		{
			name: "URL with subdirectory",
			manifest: Manifest{
				Versions: []ManifestVersion{{
					SpecVersion: "0.1",
					Locations:   []ManifestLocation{{URL: "https://github.com/org/repo/archive/refs/heads/main.tar.gz//vexhub-main"}},
				}},
			},
			wantURL:    "https://github.com/org/repo/archive/refs/heads/main.tar.gz",
			wantSubdir: "vexhub-main",
		},
		{
			// P1 fix: unknown spec version must be skipped; no URL returned.
			name: "unsupported spec version is skipped",
			manifest: Manifest{
				Versions: []ManifestVersion{
					{
						SpecVersion: "99.0",
						Locations:   []ManifestLocation{{URL: "https://example.com/new.tar.gz"}},
					},
				},
			},
			wantURL:    "",
			wantSubdir: "",
		},
		{
			// First entry is unsupported, second entry is supported — should pick the second.
			name: "multi-version manifest picks first compatible",
			manifest: Manifest{
				Versions: []ManifestVersion{
					{
						SpecVersion: "99.0",
						Locations:   []ManifestLocation{{URL: "https://example.com/new.tar.gz"}},
					},
					{
						SpecVersion: "0.1",
						Locations:   []ManifestLocation{{URL: "https://example.com/old.tar.gz"}},
					},
				},
			},
			wantURL:    "https://example.com/old.tar.gz",
			wantSubdir: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotSubdir := getArchiveURL(logger, &tt.manifest)
			if gotURL != tt.wantURL {
				t.Errorf("URL = %q, want %q", gotURL, tt.wantURL)
			}
			if gotSubdir != tt.wantSubdir {
				t.Errorf("subdir = %q, want %q", gotSubdir, tt.wantSubdir)
			}
		})
	}
}

// TestEmitVEXDocuments exercises PURL canonicalization, deduplication, guac
// skipping, and the version-stripped fallback.
func TestEmitVEXDocuments(t *testing.T) {
	vexDoc := []byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "test"}`)

	// Index keyed with canonical PURL (no version).
	vexDocs := map[string][]byte{
		canonicalizePURL("pkg:npm/lodash"): vexDoc,
	}

	t.Run("exact versioned purl matches via version-stripped fallback", func(t *testing.T) {
		docChan := make(chan *processor.Document, 10)
		docs, err := emitVEXDocuments(
			[]string{"pkg:npm/lodash@4.17.21"},
			vexDocs,
			docChan,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 1 {
			t.Fatalf("expected 1 doc, got %d", len(docs))
		}
		if docs[0].Type != processor.DocumentOpenVEX {
			t.Errorf("expected type %v, got %v", processor.DocumentOpenVEX, docs[0].Type)
		}
	})

	t.Run("no match emits nothing", func(t *testing.T) {
		docs, err := emitVEXDocuments(
			[]string{"pkg:npm/express@1.0.0"},
			vexDocs,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 0 {
			t.Fatalf("expected 0 docs, got %d", len(docs))
		}
	})

	t.Run("guac purls are skipped", func(t *testing.T) {
		docs, err := emitVEXDocuments(
			[]string{"pkg:guac/test@1.0"},
			vexDocs,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 0 {
			t.Fatalf("expected 0 docs for guac purl, got %d", len(docs))
		}
	})

	t.Run("duplicate purls only emit once", func(t *testing.T) {
		docChan := make(chan *processor.Document, 10)
		docs, err := emitVEXDocuments(
			[]string{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.20"},
			vexDocs,
			docChan,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 1 {
			t.Fatalf("expected 1 doc for duplicate purls, got %d", len(docs))
		}
	})

	t.Run("stripped-version-still-misses for unknown package", func(t *testing.T) {
		// A versioned PURL that, even after stripping, has no index entry.
		docs, err := emitVEXDocuments(
			[]string{"pkg:npm/totally-unknown@1.2.3"},
			vexDocs,
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 0 {
			t.Fatalf("expected 0 docs for unknown package, got %d", len(docs))
		}
	})
}

// TestCertifyComponentTypeMismatch checks that a wrong component type returns
// the expected sentinel error.
func TestCertifyComponentTypeMismatch(t *testing.T) {
	c := &vexHubCertifier{httpClient: http.DefaultClient, manifestURL: "http://example.com"}
	err := c.CertifyComponent(context.Background(), "wrong type", nil)
	if err == nil || err != ErrComponentTypeMismatch {
		t.Errorf("expected ErrComponentTypeMismatch, got %v", err)
	}
}

// TestCertifyComponentEndToEnd runs the full certifier pipeline against an
// in-process httptest server serving a manifest and archive.
func TestCertifyComponentEndToEnd(t *testing.T) {
	vexDoc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test-vex","statements":[{"vulnerability":{"name":"CVE-2021-44228"},"products":[{"@id":"pkg:npm/lodash"}],"status":"not_affected"}]}`
	indexJSON := `{"updated_at":"2024-01-01T00:00:00Z","packages":[{"id":"pkg:npm/lodash","location":"pkg/npm/lodash/vex.json"}]}`

	archive := buildTestArchive(t, indexJSON, map[string]string{
		"pkg/npm/lodash/vex.json": vexDoc,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/vex-repository.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[{"spec_version":"0.1","locations":[{"url":"%s/archive.tar.gz"}]}]}`, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	certifier := &vexHubCertifier{
		httpClient:  server.Client(),
		manifestURL: server.URL + "/vex-repository.json",
	}

	docChan := make(chan *processor.Document, 10)
	nodes := []*root_package.PackageNode{
		{Purl: "pkg:npm/lodash@4.17.21"},
		{Purl: "pkg:npm/express@1.0.0"},
	}

	err := certifier.CertifyComponent(context.Background(), nodes, docChan)
	if err != nil {
		t.Fatalf("CertifyComponent failed: %v", err)
	}

	close(docChan)
	var docs []*processor.Document
	for doc := range docChan {
		docs = append(docs, doc)
	}

	if len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
	}
	if docs[0].Type != processor.DocumentOpenVEX {
		t.Errorf("expected type %v, got %v", processor.DocumentOpenVEX, docs[0].Type)
	}
	if docs[0].SourceInformation.Collector != VEXHubCollector {
		t.Errorf("expected collector %q, got %q", VEXHubCollector, docs[0].SourceInformation.Collector)
	}
}

// TestMalformedManifest verifies that a non-JSON manifest body returns an error.
func TestMalformedManifest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not valid json {{{{"))
	}))
	defer server.Close()

	c := &vexHubCertifier{
		httpClient:  server.Client(),
		manifestURL: server.URL + "/vex-repository.json",
	}
	err := c.CertifyComponent(context.Background(), []*root_package.PackageNode{{Purl: "pkg:npm/lodash@1.0"}}, nil)
	if err == nil {
		t.Fatal("expected error for malformed manifest, got nil")
	}
}

// TestMissingIndexJSON verifies that an archive without index.json returns an error.
func TestMissingIndexJSON(t *testing.T) {
	archive := buildArchiveWithoutIndex(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/vex-repository.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[{"spec_version":"0.1","locations":[{"url":"%s/archive.tar.gz"}]}]}`, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &vexHubCertifier{
		httpClient:  server.Client(),
		manifestURL: server.URL + "/vex-repository.json",
	}
	err := c.CertifyComponent(context.Background(), []*root_package.PackageNode{{Purl: "pkg:npm/lodash@1.0"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "index.json") {
		t.Fatalf("expected index.json error, got: %v", err)
	}
}

// TestOversizedArchive verifies that an archive exceeding maxArchiveBytes is rejected.
func TestOversizedArchive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vex-repository.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[{"spec_version":"0.1","locations":[{"url":"%s/archive.tar.gz"}]}]}`, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		// Send more than maxArchiveBytes of zeros (uncompressed, but enough to trigger the limit check).
		chunk := make([]byte, 1024*1024) // 1 MiB chunk
		for i := 0; i <= int(maxArchiveBytes/int64(len(chunk)))+1; i++ {
			_, _ = w.Write(chunk)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &vexHubCertifier{
		httpClient:  server.Client(),
		manifestURL: server.URL + "/vex-repository.json",
	}
	err := c.CertifyComponent(context.Background(), []*root_package.PackageNode{{Purl: "pkg:npm/lodash@1.0"}}, nil)
	if err == nil {
		t.Fatal("expected error for oversized archive, got nil")
	}
}

// TestNetworkError verifies that a network failure during archive download
// is surfaced as an error from CertifyComponent.
func TestNetworkError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/vex-repository.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[{"spec_version":"0.1","locations":[{"url":"%s/archive.tar.gz"}]}]}`, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection to force a network error mid-response.
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &vexHubCertifier{
		httpClient:  server.Client(),
		manifestURL: server.URL + "/vex-repository.json",
	}
	err := c.CertifyComponent(context.Background(), []*root_package.PackageNode{{Purl: "pkg:npm/lodash@1.0"}}, nil)
	if err == nil {
		t.Fatal("expected error for network failure, got nil")
	}
}

// TestMultiVersionManifest checks that when the manifest has multiple versions
// the certifier picks the first one with the supported spec_version.
func TestMultiVersionManifest(t *testing.T) {
	vexDoc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"multi-test"}`
	indexJSON := `{"updated_at":"2024-01-01T00:00:00Z","packages":[{"id":"pkg:npm/lodash","location":"pkg/npm/lodash/vex.json"}]}`
	archive := buildTestArchive(t, indexJSON, map[string]string{
		"pkg/npm/lodash/vex.json": vexDoc,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/vex-repository.json", func(w http.ResponseWriter, r *http.Request) {
		// Serve an unsupported version first; the certifier should skip it.
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[
			{"spec_version":"99.0","locations":[{"url":"%s/should-not-be-used.tar.gz"}]},
			{"spec_version":"0.1","locations":[{"url":"%s/archive.tar.gz"}]}
		]}`, "http://"+r.Host, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	})
	// Crash if the wrong archive is requested.
	mux.HandleFunc("/should-not-be-used.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "wrong version selected", http.StatusBadRequest)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := &vexHubCertifier{
		httpClient:  server.Client(),
		manifestURL: server.URL + "/vex-repository.json",
	}
	docChan := make(chan *processor.Document, 10)
	err := c.CertifyComponent(context.Background(), []*root_package.PackageNode{{Purl: "pkg:npm/lodash@4.17.21"}}, docChan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(docChan)
	var docs []*processor.Document
	for doc := range docChan {
		docs = append(docs, doc)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
	}
}
