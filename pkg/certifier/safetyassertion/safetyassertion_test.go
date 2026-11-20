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

package safetyassertion

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Khan/genqlient/graphql"
)

type testClient func(context.Context, *graphql.Request, *graphql.Response) error

func (f testClient) MakeRequest(ctx context.Context, req *graphql.Request, res *graphql.Response) error {
	return f(ctx, req, res)
}

func TestReconcilerPaginationAndFailures(t *testing.T) {
	wantErr := errors.New("mutation failed")
	for _, failure := range []bool{false, true} {
		queries, mutations := 0, 0
		client := testClient(func(ctx context.Context, req *graphql.Request, res *graphql.Response) error {
			if req.OpName == "SafetyAssertionCandidates" {
				queries++
				if queries == 1 {
					return json.Unmarshal([]byte(`{"SafetyAssertionList":{"pageInfo":{"hasNextPage":true,"endCursor":"cursor-1"},"edges":[{"node":{"id":"a"}}]}}`), res.Data)
				}
				return json.Unmarshal([]byte(`{"SafetyAssertionList":{"pageInfo":{"hasNextPage":false,"endCursor":"cursor-2"},"edges":[{"node":{"id":"b"}}]}}`), res.Data)
			}
			if req.OpName != "ReconcileSafetyAssertion" {
				t.Fatalf("unexpected operation %s", req.OpName)
			}
			mutations++
			if failure {
				return wantErr
			}
			return json.Unmarshal([]byte(`{"reconcileSafetyAssertion":{"id":"a","target":{"correlationStatus":"PENDING"}}}`), res.Data)
		})
		r, err := New(client, 1)
		if err != nil {
			t.Fatal(err)
		}
		err = r.RunOnce(context.Background())
		if failure {
			if !errors.Is(err, wantErr) || mutations != 1 || queries != 1 {
				t.Fatalf("mutation error was not propagated: %v", err)
			}
		} else if err != nil || queries != 2 || mutations != 2 {
			t.Fatalf("pagination failed: %d queries %d mutations: %v", queries, mutations, err)
		}
	}
	r, err := New(testClient(func(ctx context.Context, req *graphql.Request, res *graphql.Response) error {
		if req.OpName == "SafetyAssertionCandidates" {
			return json.Unmarshal([]byte(`{"SafetyAssertionList":{"pageInfo":{"hasNextPage":true,"endCursor":"same"},"edges":[]}}`), res.Data)
		}
		return nil
	}), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("non-advancing cursor accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(r.RunOnce(ctx), context.Canceled) {
		t.Fatal("cancellation not propagated")
	}
	if err := r.Run(context.Background(), true, 0); err == nil {
		t.Fatal("zero polling interval accepted")
	}
	if err := r.CertifyComponent(context.Background(), "bad", nil); err == nil {
		t.Fatal("invalid component type accepted")
	}
	if err := r.GetComponents(context.Background(), nil); err == nil {
		t.Fatal("nil channel accepted")
	}
	if _, err := New(nil, 1); err == nil {
		t.Fatal("nil client accepted")
	}
	if _, err := New(r.client, 0); err == nil {
		t.Fatal("nonpositive page size accepted")
	}
}
