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
	"io"
	"os"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

func Test_gitCol_RetrieveArtifacts(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)
	type fields struct {
		url      string
		dir      string
		poll     bool
		interval time.Duration
	}
	tests := []struct {
		name         string
		fields       fields
		preCreateDir bool
		wantDirEmpty bool
		wantErr      bool
	}{{
		name: "get repo",
		fields: fields{
			url:      "https://github.com/git-fixtures/basic.git",
			dir:      "./guac-data-test",
			poll:     false,
			interval: time.Millisecond,
		},
		preCreateDir: false,
		wantDirEmpty: false,
		wantErr:      false,
	}, {
		name: "if repo exist",
		fields: fields{
			url:      "https://github.com/git-fixtures/basic.git",
			dir:      "./guac-data-test",
			poll:     false,
			interval: time.Millisecond,
		},
		preCreateDir: true,
		wantDirEmpty: false,
		wantErr:      false,
	}, {
		name: "get repo poll",
		fields: fields{
			url:      "https://github.com/git-fixtures/basic.git",
			dir:      "./guac-data-test",
			poll:     true,
			interval: time.Millisecond,
		},
		preCreateDir: false,
		wantDirEmpty: false,
		wantErr:      false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// incase the file exists from a failed run, delete it
			os.RemoveAll(tt.fields.dir)
			g := NewGitCol(ctx, tt.fields.url, tt.fields.dir, tt.fields.poll, tt.fields.interval)

			if tt.preCreateDir {
				if err := os.Mkdir(tt.fields.dir, os.ModePerm); err != nil {
					t.Fatal(err)
				}
				err := cloneRepoToTemp(logger, tt.fields.url, tt.fields.dir)
				if err != nil {
					t.Fatal(err)
				}
			}

			var cancel context.CancelFunc
			if tt.fields.poll {
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
			}

			docChan := make(chan *processor.Document, 1)
			defer close(docChan)
			defer os.RemoveAll(tt.fields.dir) // clean up
			if err := g.RetrieveArtifacts(ctx, docChan); (err != nil) != tt.wantErr {
				t.Errorf("gitCol.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
			}

			dirEmpty, err := isDirEmpty(tt.fields.dir)
			if err != nil {
				t.Errorf("isDirEmpty error = %v", err)
			}

			if dirEmpty != tt.wantDirEmpty {
				t.Errorf("isDirEmpty = %v, wantErr %v", dirEmpty, tt.wantDirEmpty)
			}
			if g.Type() != CollectorGit {
				t.Errorf("g.Type() = %s, want %s", g.Type(), CollectorGit)
			}
		})
	}
}

func isDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// read in ONLY one file
	_, err = f.Readdir(1)

	// and if the file is EOF... well, the dir is empty.
	if err == io.EOF {
		return true, nil
	}
	return false, err
}
