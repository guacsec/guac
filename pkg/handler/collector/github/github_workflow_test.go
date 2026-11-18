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

package github

import (
	"context"
	"fmt"
	"testing"

	"github.com/guacsec/guac/internal/client"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// workflowMockClient serves a fixed set of workflows, each with a latest run
// that never changes, which is what a repository looks like between two polls
// with no new runs.
type workflowMockClient struct {
	MockGithubClient
	workflows []*client.Workflow
	// runForWorkflow maps a workflow id to the id of its latest run.
	runForWorkflow map[int64]int64
}

func (m *workflowMockClient) GetWorkflow(ctx context.Context, owner, repo, githubWorkflowName string) ([]*client.Workflow, error) {
	return m.workflows, nil
}

func (m *workflowMockClient) GetLatestWorkflowRun(ctx context.Context, owner, repo string, workflowId int64) (*client.WorkflowRun, error) {
	return &client.WorkflowRun{WorkflowId: workflowId, RunId: m.runForWorkflow[workflowId]}, nil
}

func (m *workflowMockClient) GetWorkflowRunArtifacts(ctx context.Context, owner, repo, githubSBOMName string, runID int64) ([]*client.WorkflowArtifactContent, error) {
	return []*client.WorkflowArtifactContent{{
		Name:  fmt.Sprintf("sbom-%d", runID),
		Bytes: []byte(fmt.Sprintf(`{"run":%d}`, runID)),
		RunId: runID,
	}}, nil
}

// drain reads everything currently buffered on the channel.
func drain(ch chan *processor.Document) []*processor.Document {
	var docs []*processor.Document
	for {
		select {
		case d := <-ch:
			docs = append(docs, d)
		default:
			return docs
		}
	}
}

// With no --github-workflow-file the collector walks every workflow in the
// repository, so the "don't re-ingest the same run" check has to be per
// workflow. Polling a repository whose runs have not changed should produce
// nothing on the second pass.
func TestWorkflowRunArtifactsNotReIngestedOnSecondPoll(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		workflows      []*client.Workflow
		runForWorkflow map[int64]int64
		wantFirst      int
	}{
		{
			name:           "single workflow",
			workflows:      []*client.Workflow{{Name: "ci", Id: 1}},
			runForWorkflow: map[int64]int64{1: 101},
			wantFirst:      1,
		},
		{
			name:           "several workflows",
			workflows:      []*client.Workflow{{Name: "ci", Id: 1}, {Name: "release", Id: 2}, {Name: "nightly", Id: 3}},
			runForWorkflow: map[int64]int64{1: 101, 2: 102, 3: 103},
			wantFirst:      3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := NewGithubCollector(
				WithClient(&workflowMockClient{workflows: tt.workflows, runForWorkflow: tt.runForWorkflow}),
				WithMode("workflow"),
				WithOwner("mock"),
				WithRepo("repo"),
			)
			if err != nil {
				t.Fatalf("NewGithubCollector() error = %v", err)
			}

			docChan := make(chan *processor.Document, 64)

			if err := g.RetrieveArtifacts(ctx, docChan); err != nil {
				t.Fatalf("first RetrieveArtifacts() error = %v", err)
			}
			if got := len(drain(docChan)); got != tt.wantFirst {
				t.Fatalf("first poll collected %d documents, want %d", got, tt.wantFirst)
			}

			// Nothing changed in the repository, so a second poll should be a no-op.
			if err := g.RetrieveArtifacts(ctx, docChan); err != nil {
				t.Fatalf("second RetrieveArtifacts() error = %v", err)
			}
			if got := len(drain(docChan)); got != 0 {
				t.Errorf("second poll collected %d documents, want 0", got)
			}
		})
	}
}
