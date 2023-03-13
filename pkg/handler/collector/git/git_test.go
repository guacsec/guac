//
// Copyright 2022 The GUAC Authors.
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

package git_collector

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_gitCol_RetrieveArtifacts(t *testing.T) {
	type fields struct {
		url      string
		dir      string
		poll     bool
		interval time.Duration
	}
	tests := []struct {
		name                   string
		fields                 fields
		preCreateDir           bool
		wantErr                bool
		numberOfFilesCollected int
	}{{
		name: "get repo",
		fields: fields{
			url:      "https://github.com/guacsec/git-collector-test",
			dir:      os.TempDir() + "/guac-data-test",
			poll:     false,
			interval: time.Millisecond,
		},
		preCreateDir:           false,
		wantErr:                false,
		numberOfFilesCollected: 9,
	}, {
		name: "if repo exist",
		fields: fields{
			url:      "https://github.com/guacsec/git-collector-test",
			dir:      os.TempDir() + "/guac-data-test",
			poll:     false,
			interval: time.Millisecond,
		},
		preCreateDir:           true,
		wantErr:                false,
		numberOfFilesCollected: 0,
	}, {
		name: "get repo poll",
		fields: fields{
			url:      "https://github.com/guacsec/git-collector-test",
			dir:      os.TempDir() + "/guac-data-test",
			poll:     true,
			interval: time.Millisecond,
		},
		preCreateDir:           false,
		wantErr:                false,
		numberOfFilesCollected: 9,
	}}
	for _, tt := range tests {
		ctx := logging.WithLogger(context.Background())
		logger := logging.FromContext(ctx)
		t.Run(tt.name, func(t *testing.T) {
			// in case the file exists from a failed run, delete it
			os.RemoveAll(tt.fields.dir)
			g := NewGitDocumentCollector(ctx, tt.fields.url, tt.fields.dir, tt.fields.poll, tt.fields.interval)

			if err := collector.RegisterDocumentCollector(g, CollectorGitDocument); err != nil &&
				!errors.Is(err, collector.ErrCollectorOverwrite) {
				t.Fatalf("could not register collector: %v", err)
			}

			if tt.preCreateDir {
				if err := os.Mkdir(tt.fields.dir, os.ModePerm); err != nil {
					t.Fatal(err)
				}
				err := cloneRepoToDir(logger, tt.fields.url, tt.fields.dir)
				if err != nil {
					t.Fatal(err)
				}
			}

			var cancel context.CancelFunc
			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
			}

			var collectedDocs []*processor.Document
			em := func(d *processor.Document) error {
				collectedDocs = append(collectedDocs, d)
				return nil
			}
			eh := func(err error) bool {
				if (err != nil) != tt.wantErr {
					t.Errorf("gitCollector.RetrieveArtifacts() = %v, want %v", err, tt.wantErr)
				}
				return true
			}

			defer os.RemoveAll(tt.fields.dir) // clean up
			if err := collector.Collect(ctx, em, eh); err != nil {
				t.Fatalf("Collector error handler error: %v", err)
			}

			if len(collectedDocs) != tt.numberOfFilesCollected {
				t.Errorf("number of files collected does not match test = %v, want %v", len(collectedDocs), tt.numberOfFilesCollected)
			}

			if g.Type() != CollectorGitDocument {
				t.Errorf("g.Type() = %s, want %s", g.Type(), CollectorGitDocument)
			}
		})
	}
}
