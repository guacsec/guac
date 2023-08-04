//
// Copyright 2023 The GUAC Authors.
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

package guacanalytics

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

func ingestIsDependency(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.IsDependency {
		_, err := model.IngestPackage(ctx, client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("error in ingesting package: %s\n", err)
		}

		_, err = model.IngestPackage(ctx, client, *ingest.DepPkg)

		if err != nil {
			return fmt.Errorf("error in ingesting dependent package: %s\n", err)
		}
		_, err = model.IsDependency(ctx, client, *ingest.Pkg, *ingest.DepPkg, *ingest.IsDependency)

		if err != nil {
			return fmt.Errorf("error in ingesting isDependency: %s\n", err)
		}
	}
	return nil
}

func ingestHasSLSA(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.HasSlsa {
		_, err := model.IngestBuilder(ctx, client, *ingest.Builder)

		if err != nil {
			return fmt.Errorf("error in ingesting Builder for HasSlsa: %v\n", err)
		}
		_, err = model.SLSAForArtifact(ctx, client, *ingest.Artifact, ingest.Materials, *ingest.Builder, *ingest.HasSlsa)

		if err != nil {
			return fmt.Errorf("error in ingesting HasSlsa: %v\n", err)
		}
	}
	return nil
}

func ingestHasSourceAt(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.HasSourceAt {
		_, err := model.IngestPackage(ctx, client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("error in ingesting pkg HasSourceAt: %v\n", err)
		}

		_, err = model.IngestSource(ctx, client, *ingest.Src)

		if err != nil {
			return fmt.Errorf("error in ingesting src HasSourceAt: %v\n", err)
		}

		_, err = model.HasSourceAt(ctx, client, *ingest.Pkg, ingest.PkgMatchFlag, *ingest.Src, *ingest.HasSourceAt)

		if err != nil {
			return fmt.Errorf("error in ingesting HasSourceAt: %v\n", err)
		}
	}
	return nil
}

func ingestIsOccurrence(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.IsOccurrence {
		var err error

		if ingest.Src != nil {
			_, err = model.IngestSource(ctx, client, *ingest.Src)
		} else {
			_, err = model.IngestPackage(ctx, client, *ingest.Pkg)

		}

		if err != nil {
			return fmt.Errorf("error in ingesting pkg/src IsOccurrence: %v\n", err)
		}

		_, err = model.IngestArtifact(ctx, client, *ingest.Artifact)

		if err != nil {
			return fmt.Errorf("error in ingesting artifact for IsOccurrence: %v\n", err)
		}

		if ingest.Src != nil {
			_, err = model.IsOccurrenceSrc(ctx, client, *ingest.Src, *ingest.Artifact, *ingest.IsOccurrence)
		} else {
			_, err = model.IsOccurrencePkg(ctx, client, *ingest.Pkg, *ingest.Artifact, *ingest.IsOccurrence)
		}

		if err != nil {
			return fmt.Errorf("error in ingesting isOccurrence: %v\n", err)
		}
	}
	return nil
}

func ingestCertifyGood(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.CertifyGood {
		_, err := model.IngestPackage(ctx, client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("error in ingesting Package for CertifyGood: %v\n", err)
		}

		_, err = model.CertifyGoodPkg(ctx, client, *ingest.Pkg, ingest.PkgMatchFlag, *ingest.CertifyGood)

		if err != nil {
			return fmt.Errorf("error in ingesting CertifyGood: %v\n", err)
		}
	}
	return nil
}

func ingestPkgEqual(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.PkgEqual {
		_, err := model.IngestPackage(ctx, client, *ingest.Pkg)

		if err != nil {
			return fmt.Errorf("error in ingesting Pkg for PkgEqual: %v\n", err)
		}

		_, err = model.IngestPackage(ctx, client, *ingest.EqualPkg)

		if err != nil {
			return fmt.Errorf("error in ingesting EqualPkg for PkgEqual: %v\n", err)
		}

		_, err = model.PkgEqual(ctx, client, *ingest.Pkg, *ingest.EqualPkg, *ingest.PkgEqual)

		if err != nil {
			return fmt.Errorf("error in ingesting PkgEqual: %v\n", err)
		}
	}
	return nil
}

func ingestHashEqual(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.HashEqual {
		_, err := model.IngestArtifact(ctx, client, *ingest.Artifact)

		if err != nil {
			return fmt.Errorf("error in ingesting Artifact for HashEqual: %v\n", err)
		}

		_, err = model.IngestArtifact(ctx, client, *ingest.EqualArtifact)

		if err != nil {
			return fmt.Errorf("error in ingesting EqualArtifact for HashEqual: %v\n", err)
		}

		_, err = model.HashEqual(ctx, client, *ingest.Artifact, *ingest.EqualArtifact, *ingest.HashEqual)

		if err != nil {
			return fmt.Errorf("error in ingesting HashEqual: %v\n", err)
		}
	}
	return nil
}

func ingestPointOfContact(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	for _, ingest := range graph.PointOfContact {
		var err error

		if ingest.Src != nil {
			_, err = model.IngestSource(ctx, client, *ingest.Src)
		} else if ingest.Pkg != nil {
			_, err = model.IngestPackage(ctx, client, *ingest.Pkg)

		} else {
			_, err = model.IngestArtifact(ctx, client, *ingest.Artifact)
		}

		if err != nil {
			return fmt.Errorf("error in ingesting pkg/src/artifact PointOfContact: %v\n", err)
		}

		if ingest.Src != nil {
			_, err = model.PointOfContactSrc(ctx, client, *ingest.Src, *ingest.PointOfContact)
		} else if ingest.Pkg != nil {
			_, err = model.PointOfContactPkg(ctx, client, *ingest.Pkg, ingest.PkgMatchFlag, *ingest.PointOfContact)
		} else {
			_, err = model.PointOfContactArtifact(ctx, client, *ingest.Artifact, *ingest.PointOfContact)
		}

		if err != nil {
			return fmt.Errorf("error in ingesting PointOfContact: %v\n", err)
		}
	}
	return nil
}

func IngestTestData(ctx context.Context, client graphql.Client, graph assembler.IngestPredicates) error {
	if len(graph.IsDependency) > 0 {
		err := ingestIsDependency(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.IsOccurrence) > 0 {
		err := ingestIsOccurrence(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.HasSlsa) > 0 {
		err := ingestHasSLSA(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.CertifyGood) > 0 {
		err := ingestCertifyGood(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.HasSourceAt) > 0 {
		err := ingestHasSourceAt(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.PkgEqual) > 0 {
		err := ingestPkgEqual(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.HashEqual) > 0 {
		err := ingestHashEqual(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	if len(graph.PointOfContact) > 0 {
		err := ingestPointOfContact(ctx, client, graph)
		if err != nil {
			return err
		}
	}

	return nil
}

// This function return matching packageName and/or packageVersion node IDs depending on if you specified to only find name nodes or version nodes
func GetPackageIDs(ctx context.Context, gqlClient graphql.Client, nodeType *string, nodeNamespace string, nodeName string, nodeVersion *string, justFindVersion bool, justFindName bool) ([]*string, error) {
	var pkgFilter model.PkgSpec
	if nodeVersion != nil {
		pkgFilter = model.PkgSpec{
			Type:      nodeType,
			Namespace: &nodeNamespace,
			Name:      &nodeName,
			Version:   nodeVersion,
		}
	} else {
		pkgFilter = model.PkgSpec{
			Type: nodeType,
		}
	}

	pkgResponse, err := model.Packages(ctx, gqlClient, pkgFilter)

	if err != nil {
		return nil, fmt.Errorf("error getting id for test case: %s\n", err)
	}
	var foundIDs []*string

	if len(pkgResponse.Packages[0].Namespaces[0].Names) > 0 && !justFindVersion {
		for _, name := range pkgResponse.Packages[0].Namespaces[0].Names {
			foundIDs = append(foundIDs, &name.Id)
		}
	}

	if len(pkgResponse.Packages[0].Namespaces[0].Names[0].Versions) > 0 && !justFindName {
		for index := range pkgResponse.Packages[0].Namespaces[0].Names[0].Versions {
			foundIDs = append(foundIDs, &pkgResponse.Packages[0].Namespaces[0].Names[0].Versions[index].Id)
		}
	}

	if len(foundIDs) < 1 {
		return nil, fmt.Errorf("no matching nodes found\n")
	}

	return foundIDs, nil
}
