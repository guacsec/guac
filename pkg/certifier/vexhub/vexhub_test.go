//
// Copyright 2024 The GUAC Authors.
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
	"testing"

	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// buildTestArchive creates a tar.gz archive with index.json and a VEX document.
func buildTestArchive(t *testing.T, indexJSON string, vexFiles map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Write index.json under a root dir prefix (simulating GitHub archive).
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

func TestStripPurlVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash"},
		{"pkg:maven/org.apache/log4j@2.0?type=jar", "pkg:maven/org.apache/log4j"},
		{"pkg:npm/lodash@4.17.21#sub/path", "pkg:npm/lodash"},
		{"pkg:deb/debian/curl", "pkg:deb/debian/curl"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripPurlVersion(tt.input)
			if got != tt.want {
				t.Errorf("stripPurlVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetArchiveURL(t *testing.T) {
	tests := []struct {
		name      string
		manifest  Manifest
		wantURL   string
		wantSubdir string
	}{
		{
			name: "simple URL",
			manifest: Manifest{
				Versions: []ManifestVersion{{
					Locations: []ManifestLocation{{URL: "https://example.com/vex.tar.gz"}},
				}},
			},
			wantURL:    "https://example.com/vex.tar.gz",
			wantSubdir: "",
		},
		{
			name:      "empty manifest",
			manifest:  Manifest{},
			wantURL:   "",
			wantSubdir: "",
		},
		{
			name: "URL with subdirectory",
			manifest: Manifest{
				Versions: []ManifestVersion{{
					Locations: []ManifestLocation{{URL: "https://github.com/org/repo/archive/refs/heads/main.tar.gz//vexhub-main"}},
				}},
			},
			wantURL:    "https://github.com/org/repo/archive/refs/heads/main.tar.gz",
			wantSubdir: "vexhub-main",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotSubdir := getArchiveURL(&tt.manifest)
			if gotURL != tt.wantURL {
				t.Errorf("URL = %q, want %q", gotURL, tt.wantURL)
			}
			if gotSubdir != tt.wantSubdir {
				t.Errorf("subdir = %q, want %q", gotSubdir, tt.wantSubdir)
			}
		})
	}
}

func TestEmitVEXDocuments(t *testing.T) {
	vexDoc := []byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "test"}`)
	vexDocs := map[string][]byte{
		"pkg:npm/lodash": vexDoc,
	}

	t.Run("matching purl emits document", func(t *testing.T) {
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
}

func TestCertifyComponentTypeMismatch(t *testing.T) {
	c := &vexHubCertifier{httpClient: http.DefaultClient, manifestURL: "http://example.com"}
	err := c.CertifyComponent(context.Background(), "wrong type", nil)
	if err == nil || err != ErrComponentTypeMismatch {
		t.Errorf("expected ErrComponentTypeMismatch, got %v", err)
	}
}

func TestCertifyComponentEndToEnd(t *testing.T) {
	vexDoc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test-vex","statements":[{"vulnerability":{"name":"CVE-2021-44228"},"products":[{"@id":"pkg:npm/lodash"}],"status":"not_affected"}]}`
	indexJSON := `{"updated_at":"2024-01-01T00:00:00Z","packages":[{"id":"pkg:npm/lodash","location":"pkg/npm/lodash/vex.json"}]}`

	archive := buildTestArchive(t, indexJSON, map[string]string{
		"pkg/npm/lodash/vex.json": vexDoc,
	})

	// Serve the manifest and archive.
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
