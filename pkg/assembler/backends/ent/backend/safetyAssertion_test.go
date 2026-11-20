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

package backend

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/Khan/genqlient/graphql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
)

// This test uses an isolated database and never modifies the supplied database.
func safetyAssertionTestBackend(t *testing.T) *EntBackend {
	t.Helper()
	address := os.Getenv("ENT_TEST_DATABASE_URL")
	if address == "" {
		t.Skip("set ENT_TEST_DATABASE_URL to run PostgreSQL safety assertion integration tests")
	}
	admin, err := sql.Open("postgres", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Error(err)
		}
	})
	name := "safety_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE "` + name + `" WITH (FORCE)`); err != nil {
			t.Error(err)
		}
	})
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	client, err := ent.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &EntBackend{client: client}
}

func safetyAssertionFixture() model.SafetyAssertionInputSpec {
	return model.SafetyAssertionInputSpec{
		AssertionID: "product-a", SafetyRelevance: model.SafetyRelevanceSafetyRelated,
		Rationale: "Externally authored safety context for product A", DecisionStatus: model.SafetyDecisionStatusDraft,
		AssertedAt:  time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC),
		ProductPurl: "pkg:generic/product-a@1.0", ComponentPurl: "pkg:generic/library@2.0",
		Evidence: []*model.SafetyEvidenceReferenceInput{{EvidenceID: "assessment", URI: "https://example.org/assessment"}},
		Origin:   "https://example.org/assertions", Collector: "test", DocumentRef: "blob:test",
		DocumentDigestAlgorithm: "sha256", DocumentDigest: strings.Repeat("ab", 32),
	}
}

func TestSafetyAssertionPostgres(t *testing.T) {
	b := safetyAssertionTestBackend(t)
	ctx := context.Background()
	a := safetyAssertionFixture()
	id, err := b.IngestSafetyAssertion(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("out of order retention and idempotency", func(t *testing.T) {
		retry, err := b.IngestSafetyAssertion(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		if id != retry {
			t.Fatal("retry created another assertion")
		}
		rows, err := b.SafetyAssertions(ctx, &model.SafetyAssertionSpec{ID: &id})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("got %d assertions", len(rows))
		}
		row := rows[0]
		if row.Target.CorrelationStatus != model.SafetyCorrelationStatusPending || row.DecisionStatus != a.DecisionStatus || row.Target.ProductPurl != a.ProductPurl || row.Evidence[0].URI != a.Evidence[0].URI || row.DocumentDigest != a.DocumentDigest {
			t.Fatalf("round-trip lost data: %+v", row)
		}
		if n, err := b.client.PackageVersion.Query().Count(ctx); err != nil || n != 0 {
			t.Fatalf("ingestion created placeholder packages: %d, %v", n, err)
		}
	})
	t.Run("conflicting content and document provenance", func(t *testing.T) {
		changed := a
		changed.Rationale = "replacement"
		if _, err := b.IngestSafetyAssertion(ctx, changed); err == nil {
			t.Fatal("conflicting decision accepted")
		}
		changed = a
		changed.AssertionID = "new-assertion"
		changed.Origin = "https://example.org/different"
		if _, err := b.IngestSafetyAssertion(ctx, changed); err == nil {
			t.Fatal("conflicting provenance accepted")
		}
		rows, err := b.SafetyAssertions(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Rationale != a.Rationale || rows[0].Origin != a.Origin {
			t.Fatal("conflict changed stored content")
		}
	})
	t.Run("concurrent retries", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := b.IngestSafetyAssertion(ctx, a)
				if err != nil {
					t.Error(err)
				} else if got != id {
					t.Errorf("concurrent retry ID %s != %s", got, id)
				}
			}()
		}
		wg.Wait()
	})
	second := a
	second.AssertionID = "product-b"
	second.ProductPurl = "pkg:generic/product-b@1.0"
	second.SafetyRelevance = model.SafetyRelevanceNotSafetyRelated
	if _, err := b.IngestSafetyAssertion(ctx, second); err != nil {
		t.Fatal(err)
	}
	t.Run("two products and version-specific filters", func(t *testing.T) {
		rows, err := b.SafetyAssertions(ctx, &model.SafetyAssertionSpec{ComponentPurl: &a.ComponentPurl})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("got %d product assertions", len(rows))
		}
		rows, err = b.SafetyAssertions(ctx, &model.SafetyAssertionSpec{ComponentPurl: &a.ComponentPurl, SafetyRelevance: &a.SafetyRelevance})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Target.ProductPurl != a.ProductPurl {
			t.Fatal("product-specific relevance was lost")
		}
		differentVersion := "pkg:generic/product-a@2.0"
		rows, err = b.SafetyAssertions(ctx, &model.SafetyAssertionSpec{ProductPurl: &differentVersion})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatal("assertion was rebound to a different product version")
		}
		nameOnly := "pkg:generic/library"
		if _, err := b.SafetyAssertions(ctx, &model.SafetyAssertionSpec{ComponentPurl: &nameOnly}); err == nil {
			t.Fatal("name-only query accepted")
		}
	})
	t.Run("pagination and invalid cursors", func(t *testing.T) {
		one := 1
		first, err := b.SafetyAssertionList(ctx, model.SafetyAssertionSpec{}, nil, &one)
		if err != nil {
			t.Fatal(err)
		}
		if first.TotalCount != 2 || len(first.Edges) != 1 || !first.PageInfo.HasNextPage {
			t.Fatalf("bad first page: %+v", first)
		}
		next, err := b.SafetyAssertionList(ctx, model.SafetyAssertionSpec{}, first.PageInfo.EndCursor, &one)
		if err != nil {
			t.Fatal(err)
		}
		if next.TotalCount != 2 || len(next.Edges) != 1 || next.PageInfo.HasNextPage || first.Edges[0].Cursor == next.Edges[0].Cursor {
			t.Fatalf("bad second page: %+v", next)
		}
		empty, err := b.SafetyAssertionList(ctx, model.SafetyAssertionSpec{}, next.PageInfo.EndCursor, &one)
		if err != nil {
			t.Fatal(err)
		}
		if empty.TotalCount != 2 || len(empty.Edges) != 0 {
			t.Fatal("empty page lost total count")
		}
		for _, bad := range []string{"bad", "artifacts:" + uuid.NewString(), "safety_assertions:bad"} {
			if _, err := b.SafetyAssertionList(ctx, model.SafetyAssertionSpec{}, &bad, &one); err == nil {
				t.Errorf("accepted cursor %q", bad)
			}
		}
		negative := -1
		if _, err := b.SafetyAssertionList(ctx, model.SafetyAssertionSpec{}, nil, &negative); err == nil {
			t.Fatal("negative page size accepted")
		}
	})
	t.Run("GraphQL ingestion and query", func(t *testing.T) {
		server := httptest.NewServer(handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: &resolvers.Resolver{Backend: b}})))
		defer server.Close()
		client := graphql.NewClient(server.URL, server.Client())
		var result struct {
			ID string `json:"ingestSafetyAssertion"`
		}
		err := client.MakeRequest(ctx, &graphql.Request{Query: `mutation($a: SafetyAssertionInputSpec!){ingestSafetyAssertion(assertion:$a)}`, Variables: map[string]any{"a": a}}, &graphql.Response{Data: &result})
		if err != nil {
			t.Fatal(err)
		}
		if result.ID != id {
			t.Fatal("GraphQL retry changed ID")
		}
		var data struct {
			Assertions []model.SafetyAssertion `json:"SafetyAssertion"`
		}
		query := fmt.Sprintf(`{SafetyAssertion(safetyAssertionSpec:{id:%q}){id safetyRelevance decisionStatus target{productPurl componentPurl correlationStatus} evidence{evidenceId uri} origin}}`, id)
		if err := client.MakeRequest(ctx, &graphql.Request{Query: query}, &graphql.Response{Data: &data}); err != nil {
			t.Fatal(err)
		}
		if len(data.Assertions) != 1 || data.Assertions[0].Target.CorrelationStatus != model.SafetyCorrelationStatusPending {
			t.Fatal("GraphQL round-trip failed")
		}
	})
}
