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
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/Khan/genqlient/graphql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler"
	client "github.com/guacsec/guac/pkg/assembler/clients/generated"
	clienthelpers "github.com/guacsec/guac/pkg/assembler/clients/helpers"
	"github.com/guacsec/guac/pkg/assembler/graphql/generated"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/graphql/resolvers"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier/safetyassertion"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor"
	sracparser "github.com/guacsec/guac/pkg/ingestor/parser/srac"
	sracsource "github.com/guacsec/guac/pkg/srac"
	"go.uber.org/zap"
)

func safetyTestServer(t *testing.T, b *EntBackend) (*httptest.Server, graphql.Client) {
	t.Helper()
	server := httptest.NewServer(handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: &resolvers.Resolver{Backend: b}})))
	t.Cleanup(server.Close)
	return server, graphql.NewClient(server.URL, server.Client())
}

func safetyIngestPackage(t *testing.T, b *EntBackend, purl string) *model.PackageIDs {
	t.Helper()
	input, err := helpers.PurlToPkg(purl)
	if err != nil {
		t.Fatal(err)
	}
	converted := &model.PkgInputSpec{Type: input.Type, Namespace: input.Namespace, Name: input.Name, Version: input.Version, Subpath: input.Subpath}
	for _, q := range input.Qualifiers {
		converted.Qualifiers = append(converted.Qualifiers, &model.PackageQualifierInputSpec{Key: q.Key, Value: q.Value})
	}
	ids, err := b.IngestPackage(context.Background(), model.IDorPkgInput{PackageInput: converted})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestSafetySRACPipelinePostgres(t *testing.T) {
	for _, sracFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("SRAC-first=%v", sracFirst), func(t *testing.T) {
			b := safetyAssertionTestBackend(t)
			server, gql := safetyTestServer(t, b)
			ctx := context.Background()
			rec, err := safetyassertion.New(gql, 1)
			if err != nil {
				t.Fatal(err)
			}
			blob, err := os.ReadFile("../../../../../docs/examples/srac/product-context.srac.json")
			if err != nil {
				t.Fatal(err)
			}
			var source sracsource.Document
			if err := json.Unmarshal(blob, &source); err != nil {
				t.Fatal(err)
			}
			source.Assertions[0].Component.Digests = map[string]string{"sha256": strings.Repeat("ab", 32)}
			blob, err = json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			document := func(blob []byte, ref string) *processor.Document {
				return &processor.Document{Blob: blob, Type: processor.DocumentUnknown, Format: processor.FormatUnknown, ChildLogger: zap.NewNop().Sugar(), SourceInformation: processor.SourceInformation{Source: "file:" + ref, Collector: "test", DocumentRef: "blob:" + ref}}
			}
			ingest := func(docs ...*processor.Document) {
				t.Helper()
				if err := ingestor.MergedIngest(ctx, docs, server.URL, server.Client().Transport, nil, false, false, false, false); err != nil {
					t.Fatal(err)
				}
			}
			sbom := func(product, version string) *processor.Document {
				return document([]byte(fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"metadata":{"component":{"type":"application","name":%q,"version":%q,"purl":%q,"bom-ref":"product"}},"components":[{"type":"library","name":"component-l","version":"2.0.0","purl":"pkg:cargo/component-l@2.0.0","bom-ref":"library","hashes":[{"alg":"SHA-256","content":"abababababababababababababababababababababababababababababababab"}]}],"dependencies":[{"ref":"product","dependsOn":["library"]}]}`, product, version, "pkg:generic/"+product+"@"+version)), product+"-"+version+".cdx.json")
			}
			if sracFirst {
				ingest(document(blob, "assertions.json"))
				if n, err := b.client.PackageVersion.Query().Count(ctx); err != nil || n != 0 {
					t.Fatalf("SRAC created placeholder packages: %d %v", n, err)
				}
				if err := rec.RunOnce(ctx); err != nil {
					t.Fatal(err)
				}
				pending := model.SafetyCorrelationStatusPending
				rows, err := b.SafetyAssertions(ctx, &model.SafetyAssertionSpec{CorrelationStatus: &pending})
				if err != nil || len(rows) != 2 {
					t.Fatalf("unresolved assertions not retained: %v", err)
				}
				ingest(sbom("product-a", "1.0"))
				if err := rec.RunOnce(ctx); err != nil {
					t.Fatal(err)
				}
				matched := model.SafetyCorrelationStatusMatched
				rows, err = b.SafetyAssertions(ctx, &model.SafetyAssertionSpec{CorrelationStatus: &matched})
				if err != nil || len(rows) != 1 {
					t.Fatalf("expected one resolved product: %d %v", len(rows), err)
				}
				ingest(sbom("product-b", "1.0"))
			} else {
				ingest(sbom("product-a", "1.0"), sbom("product-b", "1.0"))
				ingest(document(blob, "assertions.json"))
			}
			if err := rec.RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
			rows, err := b.SafetyAssertions(ctx, nil)
			if err != nil || len(rows) != 2 {
				t.Fatalf("expected two product assertions: %v", err)
			}
			resolvedTimes := map[string]time.Time{}
			for _, row := range rows {
				if row.Binding == nil || row.Target.CorrelationStatus != model.SafetyCorrelationStatusMatched || row.DecisionStatus != model.SafetyDecisionStatusReviewed {
					t.Fatalf("missing binding or altered decision: %+v", row)
				}
				resolvedTimes[row.ID] = row.Binding.ResolvedAt
				if row.Binding.Product.Namespaces[0].Names[0].Versions[0].Version != "1.0" {
					t.Fatal("wrong product version")
				}
			}
			if rows[0].SafetyRelevance == rows[1].SafetyRelevance {
				t.Fatal("opposite product-specific relevance was lost")
			}
			// New product versions cannot silently replace an authored version target.
			ingest(sbom("product-a", "2.0"), document(blob, "assertions.json"))
			if err := rec.RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
			rows, err = b.SafetyAssertions(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Binding == nil || !row.Binding.ResolvedAt.Equal(resolvedTimes[row.ID]) || row.Binding.Product.Namespaces[0].Names[0].Versions[0].Version != "1.0" {
					t.Fatal("retry duplicated or rebound a version binding")
				}
			}
			// Exercise the generated typed binding query, not just internal conversion.
			response, err := client.ReconcileSafetyAssertion(ctx, gql, rows[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			if response.ReconcileSafetyAssertion.Binding == nil {
				t.Fatal("GraphQL binding was missing")
			}
			// The non-bulk assembler must retain the new predicate as well.
			plain := sracparser.NewParser()
			raw := document(blob, "assertions.json")
			raw.Type = processor.DocumentSRAC
			raw.Format = processor.FormatJSON
			if err := plain.Parse(ctx, raw); err != nil {
				t.Fatal(err)
			}
			if err := clienthelpers.GetAssembler(ctx, gql)([]assembler.AssemblerInput{*plain.GetPredicates(ctx)}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSafetyReconciliationPostgres(t *testing.T) {
	b := safetyAssertionTestBackend(t)
	ctx := context.Background()
	a := safetyAssertionFixture()
	expected := strings.Repeat("ab", 32)
	algorithm := "sha256"
	a.ComponentDigestAlgorithm = &algorithm
	a.ComponentDigest = &expected
	id, err := b.IngestSafetyAssertion(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	safetyIngestPackage(t, b, a.ProductPurl)
	componentIDs := safetyIngestPackage(t, b, a.ComponentPurl)
	compID, err := uuid.Parse(fromGlobalID(componentIDs.PackageVersionID).id)
	if err != nil {
		t.Fatal(err)
	}
	check := func(status model.SafetyCorrelationStatus, reason string) *model.SafetyAssertion {
		t.Helper()
		row, err := b.ReconcileSafetyAssertion(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if row.Target.CorrelationStatus != status || row.Target.CorrelationReason == nil || *row.Target.CorrelationReason != reason {
			t.Fatalf("got target %+v", row.Target)
		}
		if status != model.SafetyCorrelationStatusMatched && row.Binding != nil {
			t.Fatal("failed correlation retained an active binding")
		}
		return row
	}
	check(model.SafetyCorrelationStatusPending, "COMPONENT_DIGEST_NOT_OBSERVED")
	addDigest := func(digest string) {
		t.Helper()
		art, err := b.client.Artifact.Create().SetAlgorithm(algorithm).SetDigest(digest).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = b.client.Occurrence.Create().SetPackageID(compID).SetArtifactID(art.ID).SetJustification("test").SetOrigin("test").SetCollector("test").SetDocumentRef("test").Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	addDigest(expected)
	row := check(model.SafetyCorrelationStatusMatched, "EXACT_PACKAGE_VERSIONS_RESOLVED")
	if row.Binding == nil || !strings.Contains(row.Binding.MatchedBy, "DIGEST") {
		t.Fatal("digest evidence was not represented")
	}
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.ReconcileSafetyAssertion(ctx, id); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	again := check(model.SafetyCorrelationStatusMatched, "EXACT_PACKAGE_VERSIONS_RESOLVED")
	if !again.Binding.ResolvedAt.Equal(row.Binding.ResolvedAt) {
		t.Fatal("repeated reconciliation replaced the binding")
	}
	addDigest(strings.Repeat("cd", 32))
	check(model.SafetyCorrelationStatusInvalid, "COMPONENT_DIGEST_MISMATCH")
	if n, err := b.client.SafetyAssertion.Query().Count(ctx); err != nil || n != 1 {
		t.Fatal("reconciliation duplicated an assertion")
	}
	// Expired assertions cannot have a binding or change their external decision.
	expired := a
	expired.AssertionID = "expired"
	expiry := a.AssertedAt.Add(time.Hour)
	expired.ValidUntil = &expiry
	expiredID, err := b.IngestSafetyAssertion(ctx, expired)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := b.ReconcileSafetyAssertion(ctx, expiredID)
	if err != nil {
		t.Fatal(err)
	}
	if stale.Target.CorrelationStatus != model.SafetyCorrelationStatusStale || stale.Binding != nil || stale.DecisionStatus != expired.DecisionStatus {
		t.Fatal("expiry changed the external decision or retained a binding")
	}
	// Legacy equivalent representations can produce more than one exact match.
	// Distinct JSON null/[] values and hashes satisfy the existing database indexes.
	original, err := b.client.PackageVersion.Get(ctx, compID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.client.PackageVersion.Create().SetNameID(original.NameID).SetVersion(original.Version).SetSubpath(original.Subpath).SetHash(uuid.NewString()).SetQualifiers([]model.PackageQualifier{}).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check(model.SafetyCorrelationStatusAmbiguous, "MULTIPLE_EXACT_PACKAGE_VERSIONS")
	if _, err := b.ReconcileSafetyAssertion(ctx, "artifacts:"+uuid.NewString()); err == nil {
		t.Fatal("foreign node ID accepted")
	}
	// A different qualifier set must not be treated as an exact identity match.
	q := safetyAssertionFixture()
	q.AssertionID = "qualifiers"
	q.ComponentPurl = "pkg:generic/qualified@1.0?arch=arm64"
	qid, err := b.IngestSafetyAssertion(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	safetyIngestPackage(t, b, "pkg:generic/qualified@1.0?arch=amd64")
	unresolved, err := b.ReconcileSafetyAssertion(ctx, qid)
	if err != nil {
		t.Fatal(err)
	}
	if unresolved.Binding != nil || unresolved.Target.CorrelationStatus != model.SafetyCorrelationStatusPending {
		t.Fatal("different qualifiers were matched")
	}
	safetyIngestPackage(t, b, q.ComponentPurl)
	resolved, err := b.ReconcileSafetyAssertion(ctx, qid)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Binding == nil {
		t.Fatal("exact qualifier set did not match")
	}
	oci := safetyAssertionFixture()
	oci.AssertionID = "oci"
	oci.ComponentPurl = "pkg:oci/library@1.0?repository_url=registry.example/team/library"
	oid, err := b.IngestSafetyAssertion(ctx, oci)
	if err != nil {
		t.Fatal(err)
	}
	safetyIngestPackage(t, b, oci.ComponentPurl)
	image, err := b.ReconcileSafetyAssertion(ctx, oid)
	if err != nil {
		t.Fatal(err)
	}
	if image.Binding == nil {
		t.Fatal("OCI repository namespace conversion did not match")
	}
}
