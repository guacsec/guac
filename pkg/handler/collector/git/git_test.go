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
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_gitCol_RetrieveArtifacts(t *testing.T) {
	sourceDir, expectedDocs := createTestGitRepo(t)

	type fields struct {
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
			poll:     false,
			interval: time.Millisecond,
		},
		preCreateDir:           false,
		wantErr:                false,
		numberOfFilesCollected: len(expectedDocs),
	}, {
		name: "if repo exist",
		fields: fields{
			poll:     false,
			interval: time.Millisecond,
		},
		preCreateDir:           true,
		wantErr:                false,
		numberOfFilesCollected: 0,
	}, {
		name: "get repo poll",
		fields: fields{
			poll:     true,
			interval: time.Millisecond,
		},
		preCreateDir:           false,
		wantErr:                true,
		numberOfFilesCollected: len(expectedDocs),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := logging.WithLogger(context.Background())
			logger := logging.FromContext(ctx)
			dir := filepath.Join(t.TempDir(), "repo")
			g := NewGitDocumentCollector(ctx, sourceDir, dir, tt.fields.poll, tt.fields.interval)

			collector.DeregisterDocumentCollector(CollectorGitDocument)
			if err := collector.RegisterDocumentCollector(g, CollectorGitDocument); err != nil &&
				!errors.Is(err, collector.ErrCollectorOverwrite) {
				t.Fatalf("could not register collector: %v", err)
			}

			if tt.preCreateDir {
				if err := os.Mkdir(dir, os.ModePerm); err != nil {
					t.Fatal(err)
				}
				err := cloneRepoToDir(logger, sourceDir, dir)
				if err != nil {
					t.Fatal(err)
				}
			}

			var cancel context.CancelFunc
			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
			}

			collectedDocs := map[string]struct{}{}
			em := func(d *processor.Document) error {
				blob := string(d.Blob)
				if _, ok := expectedDocs[blob]; !ok {
					return nil
				}
				collectedDocs[blob] = struct{}{}
				if cancel != nil && len(collectedDocs) == len(expectedDocs) {
					cancel()
				}
				return nil
			}
			eh := func(err error) bool {
				if (err != nil) != tt.wantErr {
					t.Errorf("gitCollector.RetrieveArtifacts() = %v, want %v", err, tt.wantErr)
				}
				return true
			}

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

func createTestGitRepo(t *testing.T) (string, map[string]struct{}) {
	t.Helper()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}

	documents := map[string]string{
		"first.json":  `{"name":"first"}`,
		"second.json": `{"name":"second"}`,
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range documents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := worktree.Add(filepath.ToSlash(name)); err != nil {
			t.Fatal(err)
		}
	}
	_, err = worktree.Commit("add test documents", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "GUAC test",
			Email: "guac-test@example.com",
			When:  time.Unix(0, 0).UTC(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedDocs := make(map[string]struct{}, len(documents))
	for _, contents := range documents {
		expectedDocs[contents] = struct{}{}
	}
	return dir, expectedDocs
}
