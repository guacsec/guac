//
// Copyright 2025 The GUAC Authors.
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

package keyvalue

import (
	"context"
	"testing"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Includes are deduped, so two hasSBOMs can point at the same one. Deleting the
// first must not leave the second unqueryable.
func TestDeleteHasSBOMWithSharedIncludes(t *testing.T) {
	ctx := context.Background()
	be, err := getBackend(ctx, nil)
	if err != nil {
		t.Fatalf("could not get backend: %v", err)
	}

	pkgIn := &model.PkgInputSpec{Type: "pypi", Name: "tensorflow", Version: ptrfrom.String("2.11.1")}
	depIn := &model.PkgInputSpec{Type: "pypi", Name: "openssl", Version: ptrfrom.String("3.0.3")}
	artIn := &model.ArtifactInputSpec{Algorithm: "sha256", Digest: "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"}

	if _, err := be.IngestPackage(ctx, model.IDorPkgInput{PackageInput: pkgIn}); err != nil {
		t.Fatalf("could not ingest package: %v", err)
	}
	if _, err := be.IngestPackage(ctx, model.IDorPkgInput{PackageInput: depIn}); err != nil {
		t.Fatalf("could not ingest dependency package: %v", err)
	}
	if _, err := be.IngestArtifact(ctx, &model.IDorArtifactInput{ArtifactInput: artIn}); err != nil {
		t.Fatalf("could not ingest artifact: %v", err)
	}

	depID, err := be.IngestDependency(ctx,
		model.IDorPkgInput{PackageInput: pkgIn},
		model.IDorPkgInput{PackageInput: depIn},
		model.IsDependencyInputSpec{Justification: "test justification"})
	if err != nil {
		t.Fatalf("could not ingest dependency: %v", err)
	}
	occID, err := be.IngestOccurrence(ctx,
		model.PackageOrSourceInput{Package: &model.IDorPkgInput{PackageInput: depIn}},
		model.IDorArtifactInput{ArtifactInput: artIn},
		model.IsOccurrenceInputSpec{Justification: "test justification"})
	if err != nil {
		t.Fatalf("could not ingest occurrence: %v", err)
	}

	includes := model.HasSBOMIncludesInputSpec{
		Dependencies: []string{depID},
		Occurrences:  []string{occID},
	}
	// Same package and includes, different URI.
	first, err := be.IngestHasSbom(ctx,
		model.PackageOrArtifactInput{Package: &model.IDorPkgInput{PackageInput: pkgIn}},
		model.HasSBOMInputSpec{URI: "first uri"}, includes)
	if err != nil {
		t.Fatalf("could not ingest first hasSBOM: %v", err)
	}
	second, err := be.IngestHasSbom(ctx,
		model.PackageOrArtifactInput{Package: &model.IDorPkgInput{PackageInput: pkgIn}},
		model.HasSBOMInputSpec{URI: "second uri"}, includes)
	if err != nil {
		t.Fatalf("could not ingest second hasSBOM: %v", err)
	}

	deleted, err := be.Delete(ctx, first)
	if err != nil {
		t.Fatalf("could not delete hasSBOM: %v", err)
	}
	if !deleted {
		t.Fatal("expected hasSBOM to be deleted")
	}

	got, err := be.HasSBOMList(ctx, model.HasSBOMSpec{}, nil, nil)
	if err != nil {
		t.Fatalf("could not list hasSBOMs after delete: %v", err)
	}
	if got == nil || len(got.Edges) != 1 {
		t.Fatalf("expected exactly one remaining hasSBOM, got: %v", got)
	}
	if uri := got.Edges[0].Node.URI; uri != "second uri" {
		t.Errorf("expected the second hasSBOM to survive, got URI %q", uri)
	}
	if n := len(got.Edges[0].Node.IncludedDependencies); n != 1 {
		t.Errorf("expected the surviving hasSBOM to keep its included dependency, got %d", n)
	}
	if n := len(got.Edges[0].Node.IncludedOccurrences); n != 1 {
		t.Errorf("expected the surviving hasSBOM to keep its included occurrence, got %d", n)
	}

	// These resolve include IDs through the index, so a deleted include breaks
	// them even when the SBOM query itself tolerates it.
	if _, err := be.Neighbors(ctx, second, nil); err != nil {
		t.Errorf("neighbors of the surviving hasSBOM: %v", err)
	}
	if _, err := be.Node(ctx, second); err != nil {
		t.Errorf("node lookup of the surviving hasSBOM: %v", err)
	}
	deps, err := be.IsDependencyList(ctx, model.IsDependencySpec{}, nil, nil)
	if err != nil {
		t.Fatalf("could not list dependencies after delete: %v", err)
	}
	if deps == nil || len(deps.Edges) != 1 {
		t.Errorf("expected the shared dependency to outlive the deleted hasSBOM, got: %v", deps)
	}
}
