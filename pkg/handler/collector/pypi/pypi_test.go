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

package pypi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// pypiTestServer serves testdata files at /<name>/json, mirroring the PyPI
// JSON API. Unknown names get a 404 the way PyPI would return one.
func pypiTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/json")
		body, err := os.ReadFile(filepath.Join("testdata", name+".json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	return httptest.NewServer(mux)
}

func wantDoc(t *testing.T, name, source string) *processor.Document {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	return &processor.Document{
		Blob:   blob,
		Type:   processor.DocumentPyPI,
		Format: processor.FormatJSON,
		SourceInformation: processor.SourceInformation{
			Collector:   PypiCollector,
			Source:      source,
			DocumentRef: events.GetDocRef(blob),
		},
	}
}

func Test_pypiCollector_RetrieveArtifacts(t *testing.T) {
	server := pypiTestServer(t)
	defer server.Close()

	tests := []struct {
		name     string
		packages []string
		want     []string // testdata basenames expected, in order
	}{
		{
			name:     "no packages",
			packages: []string{},
			want:     nil,
		},
		{
			name:     "single pypi purl",
			packages: []string{"pkg:pypi/requests@2.31.0"},
			want:     []string{"requests"},
		},
		{
			name:     "bare package name",
			packages: []string{"requests"},
			want:     []string{"requests"},
		},
		{
			name:     "duplicate purl is fetched once",
			packages: []string{"pkg:pypi/requests@2.31.0", "pkg:pypi/requests@2.30.0"},
			want:     []string{"requests"},
		},
		{
			name:     "non-pypi purl is skipped",
			packages: []string{"pkg:npm/left-pad@1.0.0", "pkg:pypi/requests@2.31.0"},
			want:     []string{"requests"},
		},
		{
			name:     "missing package emits nothing",
			packages: []string{"pkg:pypi/does-not-exist@0.0.0"},
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewPypiCollector(toPurlSource(tt.packages), false, time.Second)
			c.baseURL = server.URL

			collector.DeregisterDocumentCollector(PypiCollector)
			if err := collector.RegisterDocumentCollector(c, PypiCollector); err != nil {
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

			if c.Type() != PypiCollector {
				t.Errorf("Type() = %s, want %s", c.Type(), PypiCollector)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d docs, want %d", len(got), len(tt.want))
			}
			for i, name := range tt.want {
				source := server.URL + "/" + name + "/json"
				want := wantDoc(t, name, source)
				if !dochelper.DocTreeEqual(dochelper.DocNode(got[i]), dochelper.DocNode(want)) {
					t.Errorf("doc %d mismatch: %s", i, cmp.Diff(dochelper.DocNode(want), dochelper.DocNode(got[i])))
				}
			}
		})
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
