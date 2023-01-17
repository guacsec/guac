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

package github

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/github"
	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/migueleliasweb/go-github-mock/src/mock"
)

var (
	// GitHub SBOM .jsonl examples
	//go:embed testdata/slsa-builder-go-linux-amd64.intoto.jsonl
	gitHubAssetExample1 []byte

	//go:embed testdata/slsa-generator-container-linux-amd64.intoto.jsonl
	gitHubAssetExample2 []byte

	//go:embed testdata/slsa-generator-generic-linux-amd64.intoto.jsonl
	gitHubAssetExample3 []byte
)

func Test_github_RetrieveArtifacts(t *testing.T) {
	ctx := context.Background()
	//logger := logging.FromContext(ctx)

	go func() {
		path, err := os.Getwd()
		if err != nil {
			log.Println(err)
		}
		fmt.Print(path)
		// create file server handler
		fs := http.FileServer(http.Dir(path + "/testdata"))

		// start HTTP server with `fs` as the default handler
		log.Fatal(http.ListenAndServe(":9000", fs))
	}()

	mockedHTTPClient := mock.NewMockedHTTPClient(
		mock.WithRequestMatch(
			mock.GetReposReleasesLatestByOwnerByRepo,
			github.RepositoryRelease{
				ID:      github.Int64(123),
				URL:     github.String("URL"),
				TagName: github.String("v1.4.0"),
				Assets: []github.ReleaseAsset{{
					Name:               github.String("test.jsonl"),
					BrowserDownloadURL: github.String("http://localhost:9000/slsa-builder-go-linux-amd64.intoto.jsonl"),
				}, {
					Name:               github.String("slsa-generator-container-linux-amd64.intoto.jsonl"),
					BrowserDownloadURL: github.String("http://localhost:9000/slsa-generator-container-linux-amd64.intoto.jsonl"),
				}, {
					Name:               github.String("slsa-generator-generic-linux-amd64.intoto.jsonl"),
					BrowserDownloadURL: github.String("http://localhost:9000/slsa-generator-generic-linux-amd64.intoto.jsonl"),
				}},
			},
		),
		mock.WithRequestMatch(
			mock.GetReposCommitsByOwnerByRepoByRef,
			[]byte("01234567890"),
			[]byte("01234567890"),
		),
		mock.WithRequestMatch(
			mock.GetReposReleasesTagsByOwnerByRepoByTag,
			github.RepositoryRelease{
				ID:      github.Int64(123),
				URL:     github.String("URL"),
				TagName: github.String("v1.4.0"),
				Assets: []github.ReleaseAsset{{
					Name:               github.String("test.jsonl"),
					BrowserDownloadURL: github.String("http://localhost:9000/slsa-builder-go-linux-amd64.intoto.jsonl"),
				}, {
					Name:               github.String("slsa-generator-container-linux-amd64.intoto.jsonl"),
					BrowserDownloadURL: github.String("http://localhost:9000/slsa-generator-container-linux-amd64.intoto.jsonl"),
				}, {
					Name:               github.String("slsa-generator-generic-linux-amd64.intoto.jsonl"),
					BrowserDownloadURL: github.String("http://localhost:9000/slsa-generator-generic-linux-amd64.intoto.jsonl"),
				}},
			},
		),
	)

	docs := []*processor.Document{
		{
			Blob:   dochelper.ConsistentJsonBytes(gitHubAssetExample1),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(CollectorGitHub),
				Source:    "v1.4.0",
			},
		},
		{
			Blob:   dochelper.ConsistentJsonBytes(gitHubAssetExample2),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(CollectorGitHub),
				Source:    "v1.4.0",
			},
		},
		{
			Blob:   dochelper.ConsistentJsonBytes(gitHubAssetExample3),
			Type:   processor.DocumentUnknown,
			Format: processor.FormatUnknown,
			SourceInformation: processor.SourceInformation{
				Collector: string(CollectorGitHub),
				Source:    "v1.4.0",
			},
		},
	}
	type fields struct {
		poll     bool
		token    string
		client   *github.Client
		owner    string
		repo     string
		tag      string
		interval time.Duration
	}
	tests := []struct {
		name                   string
		fields                 fields
		numberOfFilesCollected int
		wantErr                bool
		errMessage             error
		want                   []*processor.Document
	}{{
		name: "Get all slsa packages",
		fields: fields{
			poll:     false,
			token:    os.Getenv("API_KEY"),
			client:   github.NewClient(mockedHTTPClient),
			owner:    "slsa-framework",
			repo:     "slsa-github-generator",
			tag:      "v1.4.0",
			interval: time.Millisecond,
		},
		wantErr: false,
		want:    docs,
	}, {
		name: "Tag not specified",
		fields: fields{
			poll:     false,
			token:    os.Getenv("API_KEY"),
			client:   github.NewClient(mockedHTTPClient),
			owner:    "slsa-framework",
			repo:     "slsa-github-generator",
			tag:      "",
			interval: time.Millisecond,
		},
		want:    docs,
		wantErr: false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new githubCollector
			g := &githubCollector{
				poll:     tt.fields.poll,
				interval: tt.fields.interval,
				token:    tt.fields.token,
				client:   tt.fields.client,
				owner:    tt.fields.owner,
				repo:     tt.fields.repo,
				tag:      tt.fields.tag,
				tagMap:   map[string]string{},
			}
			var err error
			docChan := make(chan *processor.Document, 1)
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- g.RetrieveArtifacts(ctx, docChan)
			}()
			numCollectors := 1
			collectorsDone := 0
			collectedDocs := []*processor.Document{}

			for collectorsDone < numCollectors {
				select {
				case d := <-docChan:
					collectedDocs = append(collectedDocs, d)
				case err := <-errChan:
					if err != nil {
						if !tt.wantErr {
							t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
							return
						}
						if ghErr, ok := err.(*github.ErrorResponse); ok {
							if !strings.Contains(ghErr.Message, tt.errMessage.Error()) {
								t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", ghErr.Message, tt.errMessage)
								return
							}
						}
					}
					collectorsDone += 1
				}
			}
			// Drain anything left in document channel
			for len(docChan) > 0 {
				d := <-docChan
				collectedDocs = append(collectedDocs, d)
			}
			if err == nil {
				for i := range collectedDocs {
					result := dochelper.DocTreeEqual(dochelper.DocNode(collectedDocs[i]), dochelper.DocNode(tt.want[i]))
					if !result {
						t.Errorf("g.RetrieveArtifacts() = %v, want %v", string(collectedDocs[i].Blob), string(tt.want[i].Blob))
					}
				}

				if g.Type() != CollectorGitHub {
					t.Errorf("g.Type() = %s, want %s", g.Type(), CollectorGitHub)
				}
			}
		})
	}

}
