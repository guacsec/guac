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

package gomod

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"

	"github.com/google/go-cmp/cmp"
)

// proxyTestServer serves the testdata tree, which mirrors the escaped module
// proxy path layout (testdata/<module>/@v/<file>). Anything missing gets a 404
// the way the real proxy would.
func proxyTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := os.ReadFile(filepath.Join("testdata", filepath.Clean(r.URL.Path)))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	return httptest.NewServer(mux)
}

// wantDoc rebuilds the document the collector should emit for a proxy path.
func wantDoc(t *testing.T, serverURL, path string, format processor.FormatType) *processor.Document {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("testdata", filepath.Clean(path)))
	if err != nil {
		t.Fatalf("read testdata %q: %v", path, err)
	}
	return &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentGoMod,
		Format: format,
		SourceInformation: processor.SourceInformation{
			Collector:   GoModCollector,
			Source:      serverURL + path,
			DocumentRef: events.GetDocRef(blob),
		},
	}
}

type wantPath struct {
	path   string
	format processor.FormatType
}

func Test_goModCollector_RetrieveArtifacts(t *testing.T) {
	server := proxyTestServer(t)
	defer server.Close()

	tests := []struct {
		name    string
		modules []string
		want    []wantPath
	}{
		{
			name:    "no modules",
			modules: []string{},
			want:    nil,
		},
		{
			name:    "pinned version fetches info and mod",
			modules: []string{"pkg:golang/github.com/gorilla/mux@v1.8.0"},
			want: []wantPath{
				{"/github.com/gorilla/mux/@v/v1.8.0.info", processor.FormatJSON},
				{"/github.com/gorilla/mux/@v/v1.8.0.mod", processor.FormatUnknown},
			},
		},
		{
			name:    "no version expands to every listed version",
			modules: []string{"pkg:golang/github.com/gorilla/mux"},
			want: []wantPath{
				{"/github.com/gorilla/mux/@v/v1.8.0.info", processor.FormatJSON},
				{"/github.com/gorilla/mux/@v/v1.8.0.mod", processor.FormatUnknown},
				{"/github.com/gorilla/mux/@v/v1.8.1.info", processor.FormatJSON},
				{"/github.com/gorilla/mux/@v/v1.8.1.mod", processor.FormatUnknown},
			},
		},
		{
			// A purl lowercases the namespace, so uppercase modules can only be
			// reached by handing in the real module path. It gets case-encoded.
			name:    "uppercase module path is case-encoded",
			modules: []string{"github.com/BurntSushi/toml@v1.3.2"},
			want: []wantPath{
				{"/github.com/!burnt!sushi/toml/@v/v1.3.2.info", processor.FormatJSON},
				{"/github.com/!burnt!sushi/toml/@v/v1.3.2.mod", processor.FormatUnknown},
			},
		},
		{
			name:    "bare module path with version",
			modules: []string{"github.com/gorilla/mux@v1.8.1"},
			want: []wantPath{
				{"/github.com/gorilla/mux/@v/v1.8.1.info", processor.FormatJSON},
				{"/github.com/gorilla/mux/@v/v1.8.1.mod", processor.FormatUnknown},
			},
		},
		{
			name:    "duplicate module@version is fetched once",
			modules: []string{"pkg:golang/github.com/gorilla/mux@v1.8.0", "pkg:golang/github.com/gorilla/mux@v1.8.0"},
			want: []wantPath{
				{"/github.com/gorilla/mux/@v/v1.8.0.info", processor.FormatJSON},
				{"/github.com/gorilla/mux/@v/v1.8.0.mod", processor.FormatUnknown},
			},
		},
		{
			name:    "non-golang purl is skipped",
			modules: []string{"pkg:pypi/requests@2.31.0", "pkg:golang/github.com/gorilla/mux@v1.8.0"},
			want: []wantPath{
				{"/github.com/gorilla/mux/@v/v1.8.0.info", processor.FormatJSON},
				{"/github.com/gorilla/mux/@v/v1.8.0.mod", processor.FormatUnknown},
			},
		},
		{
			name:    "missing module emits nothing",
			modules: []string{"pkg:golang/example.com/does/not/exist@v0.0.0"},
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewGoModCollector(toPurlSource(tt.modules), false, time.Second)
			c.baseURL = server.URL

			collector.DeregisterDocumentCollector(GoModCollector)
			if err := collector.RegisterDocumentCollector(c, GoModCollector); err != nil {
				t.Fatalf("could not register collector: %v", err)
			}

			var got []*processor.Document
			em := func(d *processor.Document) error {
				got = append(got, d)
				return nil
			}
			eh := func(err error) bool {
				if err != nil {
					t.Errorf("RetrieveArtifacts() error = %v", err)
				}
				return true
			}
			if err := collector.Collect(context.Background(), em, eh); err != nil {
				t.Fatalf("Collect error: %v", err)
			}

			if c.Type() != GoModCollector {
				t.Errorf("Type() = %s, want %s", c.Type(), GoModCollector)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d docs, want %d", len(got), len(tt.want))
			}
			for i, w := range tt.want {
				want := wantDoc(t, server.URL, w.path, w.format)
				// DocTreeEqual normalizes blobs through a JSON round-trip, so it
				// only fits the .info docs. go.mod is plain text, so compare those
				// on raw bytes and metadata directly.
				if w.format == processor.FormatJSON {
					if !dochelper.DocTreeEqual(dochelper.DocNode(got[i]), dochelper.DocNode(want)) {
						t.Errorf("doc %d mismatch: %s", i, cmp.Diff(dochelper.DocNode(want), dochelper.DocNode(got[i])))
					}
					continue
				}
				got[i].ChildLogger = nil
				if !cmp.Equal(want, got[i]) {
					t.Errorf("doc %d mismatch: %s", i, cmp.Diff(want, got[i]))
				}
			}
		})
	}
}

func Test_escapePath(t *testing.T) {
	cases := map[string]string{
		"github.com/gorilla/mux":      "github.com/gorilla/mux",
		"github.com/BurntSushi/toml":  "github.com/!burnt!sushi/toml",
		"github.com/Azure/go-ntlmssp": "github.com/!azure/go-ntlmssp",
	}
	for in, want := range cases {
		if got := escapePath(in); got != want {
			t.Errorf("escapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func toPurlSource(purlValues []string) datasource.CollectSource {
	values := []datasource.Source{}
	for _, v := range purlValues {
		values = append(values, datasource.Source{Value: v})
	}
	ds, err := inmemsource.NewInmemDataSources(&datasource.DataSources{
		PurlDataSources: values,
	})
	if err != nil {
		panic(err)
	}
	return ds
}
