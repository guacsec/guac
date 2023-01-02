package github

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guacsec/guac/internal/testing/dochelper"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

// FIXME: Test is not running properly due to a bad credentials error
func Test_github_RetrieveArtifacts(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	type fields struct {
		poll     bool
		token    string
		owner    string
		repo     string
		tag      string
		tagList  []string
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
		// TODO: Fix fields for test cases below
		name: "Get all sboms",
		fields: fields{
			poll:     false,
			token:    os.Getenv("API_KEY"),
			owner:    "slsa-framework",
			repo:     "slsa-github-generator",
			tag:      "v1.4.0",
			interval: time.Millisecond,
		},
		numberOfFilesCollected: 3,
		wantErr:                false,
		want: []*processor.Document{
			{
				Blob:   testdata.GitHubAssetExample1,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(CollectorGitHubDocument),
					Source:    "v1.4.0",
				},
			},
			{
				Blob:   testdata.GitHubAssetExample2,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(CollectorGitHubDocument),
					Source:    "v1.4.0",
				},
			},
			{
				Blob:   testdata.GitHubAssetExample3,
				Type:   processor.DocumentUnknown,
				Format: processor.FormatUnknown,
				SourceInformation: processor.SourceInformation{
					Collector: string(CollectorGitHubDocument),
					Source:    "v1.4.0",
				},
			},
		},
	}, {
		name: "Tag not specified",
		fields: fields{
			poll:     false,
			token:    os.Getenv("API_KEY"),
			owner:    "slsa-framework",
			repo:     "slsa-github-generator",
			tag:      "",
			interval: time.Millisecond,
		},
		wantErr: false,
	}, {
		name: "No tag or latest release specified",
		fields: fields{
			poll:     false,
			token:    os.Getenv("API_KEY"),
			owner:    "",
			repo:     "",
			interval: time.Millisecond,
		},
		errMessage: errors.New("Error, no tag or release information specified."),
		wantErr:    true,
	}, {
		name: "Poll latest release",
		fields: fields{
			poll:     true,
			token:    os.Getenv("API_KEY"),
			owner:    "slsa-framework",
			repo:     "slsa-github-generator",
			interval: time.Millisecond,
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new githubDocumentCollector
			g := NewGitHubDocumentCollector(ctx, tt.fields.poll, tt.fields.interval, logger, tt.fields.token, tt.fields.owner, tt.fields.repo, tt.fields.tag, tt.fields.tagList)
			// Create a channel to collect the documents emitted by RetrieveArtifacts
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
				case err = <-errChan:
					if err != nil {
						if !tt.wantErr {
							t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.wantErr)
							return
						}
						if !strings.Contains(err.Error(), tt.errMessage.Error()) {
							t.Errorf("g.RetrieveArtifacts() error = %v, wantErr %v", err, tt.errMessage)
							return
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

				if g.Type() != CollectorGitHubDocument {
					t.Errorf("g.Type() = %s, want %s", g.Type(), CollectorGitHubDocument)
				}
			}
		})
	}

}
