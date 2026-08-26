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

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Khan/genqlient/graphql"
	gql "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/logging"
)

// stubClient returns a single canned Neighbors response.
type stubClient struct{ raw string }

func (c stubClient) MakeRequest(ctx context.Context, req *graphql.Request, resp *graphql.Response) error {
	return json.Unmarshal([]byte(c.raw), resp.Data)
}

type stubNode struct{ id string }

func (n stubNode) GetId() string { return n.id }

// A package name node carries no versions, so neighborToNode maps it to a nil
// node. Before it was filtered out, that nil reached GetId and panicked.
func Test_neighbors_dropsPackageNameNodes(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	client := stubClient{raw: `{"neighbors":[{"__typename":"Package","id":"pkg-name-1",` +
		`"type":"guac","namespaces":[{"id":"ns-1","namespace":"","names":[` +
		`{"id":"name-1","name":"foo","versions":[]}]}]}]}`}

	got, err := neighbors(ctx, client, stubNode{id: "art-1"}, []gql.Edge{gql.EdgeArtifactIsOccurrence})
	if err != nil {
		t.Fatalf("neighbors returned unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected the package name node to be dropped, got %d node(s): %#v", len(got), got)
	}
}

// Sentinel errors reach handleErr wrapped by the retrieval helpers, so identity
// comparison would misreport a backend outage as a client error.
func Test_handleErr_unwrapsSentinels(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name string
		err  error
		want any
	}{
		{"bare 502", helpers.Err502, gen.GetArtifactVulns502JSONResponse{}},
		{"wrapped 502", fmt.Errorf("failed to find artifact: %w", helpers.Err502), gen.GetArtifactVulns502JSONResponse{}},
		{"bare 500", helpers.Err500, gen.GetArtifactVulns500JSONResponse{}},
		{"wrapped 500", fmt.Errorf("failed to find artifact: %w", helpers.Err500), gen.GetArtifactVulns500JSONResponse{}},
		{"other errors stay 400", fmt.Errorf("no artifacts matched the digest"), gen.GetArtifactVulns400JSONResponse{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := handleErr(ctx, tt.err, GetArtifactVulns)
			if fmt.Sprintf("%T", got) != fmt.Sprintf("%T", tt.want) {
				t.Errorf("handleErr returned %T, want %T", got, tt.want)
			}
		})
	}
}
