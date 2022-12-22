package github

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

// FIXME: Test is not running properly due to a bad credentials error
func Test_github_RetrieveArtifacts(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	type fields struct {
		dir      string
		poll     bool
		token    string
		owner    string
		repo     string
		interval time.Duration
	}
	tests := []struct {
		name                   string
		fields                 fields
		numberOfFilesCollected int
		wantErr                bool
	}{{
		name: "Get assets",
		fields: fields{
			dir:      os.TempDir() + "/guac-data-test",
			poll:     false,
			token:    os.Getenv("API_KEY"),
			owner:    "slsa-framework",
			repo:     "slsa-github-generator",
			interval: time.Millisecond,
		},
		numberOfFilesCollected: 3,
		wantErr:                false,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new githubDocumentCollector
			gitHubCollector := NewGitHubDocumentCollector(ctx, tt.fields.dir, tt.fields.poll, tt.fields.interval, logger, tt.fields.token, tt.fields.owner, tt.fields.repo)
			// Create a channel to collect the documents emitted by RetrieveArtifacts
			docChan := make(chan *processor.Document, 1)
			defer os.RemoveAll(tt.fields.dir) // clean up
			errChan := make(chan error, 1)
			defer close(docChan)
			defer close(errChan)
			go func() {
				errChan <- gitHubCollector.RetrieveArtifacts(ctx, docChan)
			}()

			err := gitHubCollector.RetrieveArtifacts(ctx, docChan)
			if (err != nil) != tt.wantErr {
				t.Errorf("Error calling retrieve artifacts error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// number of documents were collected
			count := 0
			for range docChan {
				count++
			}
			if count != tt.numberOfFilesCollected {
				t.Errorf("Collected %d documents, want %d", count, tt.numberOfFilesCollected)
			}
		})
	}

}
