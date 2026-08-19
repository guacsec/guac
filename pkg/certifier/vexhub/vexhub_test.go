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
	"sync/atomic"
	"testing"

	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// newTestCertifier returns a vexHubCertifier with all maps initialised,
// suitable for direct use in white-box tests.
func newTestCertifier(client *http.Client, manifestURL string) *vexHubCertifier {
	return &vexHubCertifier{
		httpClient:  client,
		manifestURL: manifestURL,
		cache:       make(map[string]*manifestCacheEntry),
		seen:        make(map[string]struct{}),
	}
}

// buildTestArchive creates a tar.gz archive with index.json and optional VEX files.
// All entries are nested under a "vexhub-main/" top-level directory (simulating a
// GitHub archive download).
func buildTestArchive(t *testing.T, indexJSON string, vexFiles map[string]string) []byte {
	t.Helper()
	return buildTestArchiveWithPrefix(t, "vexhub-main/", indexJSON, vexFiles)
}

// buildTestArchiveWithPrefix creates a tar.gz archive with index.json and optional VEX files
// prefixed by prefix.
func buildTestArchiveWithPrefix(t *testing.T, prefix string, indexJSON string, vexFiles map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	writeFile := func(name, content string) {
		hdr := &tar.Header{
			Name: prefix + name,
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

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
					Locations:   []ManifestLocation{{URL: srv.URL + "/vex.tar.gz"}},
				}},
			},
			wantURL:    srv.URL + "/vex.tar.gz",
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
					Locations:   []ManifestLocation{{URL: srv.URL + "/archive.tar.gz//vexhub-main"}},
				}},
			},
			wantURL:    srv.URL + "/archive.tar.gz",
			wantSubdir: "vexhub-main",
		},
		{
			name: "unsupported spec version is skipped",
			manifest: Manifest{
				Versions: []ManifestVersion{{
					SpecVersion: "99.0",
					Locations:   []ManifestLocation{{URL: srv.URL + "/new.tar.gz"}},
				}},
			},
			wantURL:    "",
			wantSubdir: "",
		},
		{
			name: "multi-version manifest picks first compatible",
			manifest: Manifest{
				Versions: []ManifestVersion{
					{
						SpecVersion: "99.0",
						Locations:   []ManifestLocation{{URL: srv.URL + "/new.tar.gz"}},
					},
					{
						SpecVersion: "0.1",
						Locations:   []ManifestLocation{{URL: srv.URL + "/old.tar.gz"}},
					},
				},
			},
			wantURL:    srv.URL + "/old.tar.gz",
			wantSubdir: "",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotSubdir := getArchiveURL(ctx, srv.Client(), &tt.manifest)
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
		c := newTestCertifier(http.DefaultClient, "")
		docChan := make(chan *processor.Document, 10)
		docs, err := c.emitVEXDocuments(context.Background(), []string{"pkg:npm/lodash@4.17.21"}, vexDocs, docChan)
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
		c := newTestCertifier(http.DefaultClient, "")
		docs, err := c.emitVEXDocuments(context.Background(), []string{"pkg:npm/express@1.0.0"}, vexDocs, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 0 {
			t.Fatalf("expected 0 docs, got %d", len(docs))
		}
	})

	t.Run("guac purls are skipped", func(t *testing.T) {
		c := newTestCertifier(http.DefaultClient, "")
		docs, err := c.emitVEXDocuments(context.Background(), []string{"pkg:guac/test@1.0"}, vexDocs, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 0 {
			t.Fatalf("expected 0 docs for guac purl, got %d", len(docs))
		}
	})

	t.Run("duplicate purls only emit once", func(t *testing.T) {
		c := newTestCertifier(http.DefaultClient, "")
		docChan := make(chan *processor.Document, 10)
		docs, err := c.emitVEXDocuments(
			context.Background(),
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

	t.Run("cross-batch deduplication via struct-level seen map", func(t *testing.T) {
		c := newTestCertifier(http.DefaultClient, "")
		docChan := make(chan *processor.Document, 10)
		// First batch emits one doc.
		docs1, err := c.emitVEXDocuments(context.Background(), []string{"pkg:npm/lodash@4.17.21"}, vexDocs, docChan)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs1) != 1 {
			t.Fatalf("batch 1: expected 1 doc, got %d", len(docs1))
		}
		// Second batch with same PURL should emit nothing.
		docs2, err := c.emitVEXDocuments(context.Background(), []string{"pkg:npm/lodash@4.17.20"}, vexDocs, docChan)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs2) != 0 {
			t.Fatalf("batch 2: expected 0 docs (dedup across batches), got %d", len(docs2))
		}
	})

	t.Run("stripped-version-still-misses for unknown package", func(t *testing.T) {
		c := newTestCertifier(http.DefaultClient, "")
		docs, err := c.emitVEXDocuments(context.Background(), []string{"pkg:npm/totally-unknown@1.2.3"}, vexDocs, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(docs) != 0 {
			t.Fatalf("expected 0 docs for unknown package, got %d", len(docs))
		}
	})

	t.Run("context cancellation aborts emission", func(t *testing.T) {
		c := newTestCertifier(http.DefaultClient, "")
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // cancel immediately
		unbufferedChan := make(chan *processor.Document)
		_, err := c.emitVEXDocuments(ctx, []string{"pkg:npm/lodash@4.17.21"}, vexDocs, unbufferedChan)
		if err == nil {
			t.Fatal("expected error on cancelled context, got nil")
		}
	})
}

// TestCertifyComponentTypeMismatch checks that a wrong component type returns
// the expected sentinel error.
func TestCertifyComponentTypeMismatch(t *testing.T) {
	c := newTestCertifier(http.DefaultClient, "http://example.com")
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
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := newTestCertifier(server.Client(), server.URL+"/vex-repository.json")

	docChan := make(chan *processor.Document, 10)
	nodes := []*root_package.PackageNode{
		{Purl: "pkg:npm/lodash@4.17.21"},
		{Purl: "pkg:npm/express@1.0.0"},
	}

	err := c.CertifyComponent(context.Background(), nodes, docChan)
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

	c := newTestCertifier(server.Client(), server.URL+"/vex-repository.json")
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
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := newTestCertifier(server.Client(), server.URL+"/vex-repository.json")
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
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		chunk := make([]byte, 1024*1024) // 1 MiB chunks
		for i := 0; i <= int(maxArchiveBytes/int64(len(chunk)))+1; i++ {
			_, _ = w.Write(chunk)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := newTestCertifier(server.Client(), server.URL+"/vex-repository.json")
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
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Hijack the connection on GET to force a network error.
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

	c := newTestCertifier(server.Client(), server.URL+"/vex-repository.json")
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
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[
			{"spec_version":"99.0","locations":[{"url":"%s/should-not-be-used.tar.gz"}]},
			{"spec_version":"0.1","locations":[{"url":"%s/archive.tar.gz"}]}
		]}`, "http://"+r.Host, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(archive)
	})
	mux.HandleFunc("/should-not-be-used.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "wrong version selected", http.StatusBadRequest)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := newTestCertifier(server.Client(), server.URL+"/vex-repository.json")
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

// TestSubdirVsTopLevelDirMismatch tests archives where the top-level directory
// inside the tarball does not match the subdir specified after "//" in the URL.
func TestSubdirVsTopLevelDirMismatch(t *testing.T) {
	vexDoc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"subdir-test"}`
	indexJSON := `{"updated_at":"2024-01-01T00:00:00Z","packages":[{"id":"pkg:npm/lodash","location":"pkg/npm/lodash/vex.json"}]}`
	// The tar archive has a top-level dir "github-release-1.0.0/", and inside it "custom-subdir/pkg/npm/lodash/vex.json".
	archive := buildTestArchiveWithPrefix(t, "github-release-1.0.0/custom-subdir/", indexJSON, map[string]string{
		"pkg/npm/lodash/vex.json": vexDoc,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/vex-repository.json", func(w http.ResponseWriter, r *http.Request) {
		// URL specifies subdirectory "custom-subdir" after "//"
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[{"spec_version":"0.1","locations":[{"url":"%s/archive.tar.gz//custom-subdir"}]}]}`, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := newTestCertifier(server.Client(), server.URL+"/vex-repository.json")
	docChan := make(chan *processor.Document, 10)
	err := c.CertifyComponent(context.Background(), []*root_package.PackageNode{{Purl: "pkg:npm/lodash@4.17.21"}}, docChan)
	if err != nil {
		t.Fatalf("CertifyComponent failed: %v", err)
	}
	close(docChan)
	var docs []*processor.Document
	for doc := range docChan {
		docs = append(docs, doc)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 document with custom subdir, got %d", len(docs))
	}
}

// TestFormatFiltering verifies that non-openvex format entries are skipped.
func TestFormatFiltering(t *testing.T) {
	vexDoc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"format-test"}`
	// Index with one openvex entry and one csaf entry.
	indexJSON := `{"updated_at":"2024-01-01T00:00:00Z","packages":[
		{"id":"pkg:npm/lodash","location":"pkg/npm/lodash/vex.json","format":"openvex"},
		{"id":"pkg:npm/express","location":"pkg/npm/express/csaf.json","format":"csaf"}
	]}`
	archive := buildTestArchive(t, indexJSON, map[string]string{
		"pkg/npm/lodash/vex.json":   vexDoc,
		"pkg/npm/express/csaf.json": `{"document":{}}`,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/vex-repository.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[{"spec_version":"0.1","locations":[{"url":"%s/archive.tar.gz"}]}]}`, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := newTestCertifier(server.Client(), server.URL+"/vex-repository.json")
	docChan := make(chan *processor.Document, 10)
	nodes := []*root_package.PackageNode{
		{Purl: "pkg:npm/lodash@1.0"},
		{Purl: "pkg:npm/express@4.0"},
	}
	if err := c.CertifyComponent(context.Background(), nodes, docChan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(docChan)
	var docs []*processor.Document
	for doc := range docChan {
		docs = append(docs, doc)
	}
	// Only lodash (openvex) should be emitted; express (csaf) must be skipped.
	if len(docs) != 1 {
		t.Fatalf("expected 1 doc (openvex only), got %d", len(docs))
	}
}

// TestCachingAndTTL verifies that the certifier reuses cached manifest and vexDocs
// without re-downloading until the TTL expires.
func TestCachingAndTTL(t *testing.T) {
	var downloadCount int32
	vexDoc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"cache-test"}`
	indexJSON := `{"updated_at":"2024-01-01T00:00:00Z","packages":[{"id":"pkg:npm/lodash","location":"pkg/npm/lodash/vex.json"}]}`
	archive := buildTestArchive(t, indexJSON, map[string]string{
		"pkg/npm/lodash/vex.json": vexDoc,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/vex-repository.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"name":"test","versions":[{"spec_version":"0.1","update_interval":"1h","locations":[{"url":"%s/archive.tar.gz"}]}]}`, "http://"+r.Host)
	})
	mux.HandleFunc("/archive.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			atomic.AddInt32(&downloadCount, 1)
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	c := NewVEXHubCertifier(server.URL + "/vex-repository.json")
	nodes := []*root_package.PackageNode{{Purl: "pkg:npm/lodash@1.0"}}

	// First call downloads the archive.
	docChan := make(chan *processor.Document, 10)
	if err := c.CertifyComponent(context.Background(), nodes, docChan); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if atomic.LoadInt32(&downloadCount) != 1 {
		t.Fatalf("expected 1 download, got %d", atomic.LoadInt32(&downloadCount))
	}

	// Second call should use cache (no new download).
	if err := c.CertifyComponent(context.Background(), nodes, docChan); err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if atomic.LoadInt32(&downloadCount) != 1 {
		t.Fatalf("expected 1 download (cached), got %d", atomic.LoadInt32(&downloadCount))
	}
}
