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

package backend

import (
	"context"
	"fmt"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyvex"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/vulnerabilityid"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"golang.org/x/exp/maps"
	"slices"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/backends/ent"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packagename"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// FindSoftware takes in a searchText string and looks for software
// that may be relevant for the input text. This can be seen as fuzzy search
// function for Packages, Sources and Artifacts. findSoftware returns a list
// of Packages, Sources and Artifacts that it determines to be relevant to
// the input searchText.

// Due to the nature of full text search being implemented differently on
// different db platforms, the behavior of findSoftware is not guaranteed
// to be the same. In addition, their statistical nature may result in
// results being different per call and not reproducible.

// All that is asked in the implementation of this API is that it follows
// the spirit of helping to retrieve the right nodes with best effort.

// Warning: This is an EXPERIMENTAL feature. This is subject to change.
// Warning: This is an OPTIONAL feature. Backends are not required to
// implement this API.
func (b *EntBackend) FindSoftware(ctx context.Context, searchText string) ([]model.PackageSourceOrArtifact, error) {
	// Arbitrarily only search if the search text is longer than 2 characters
	// Search Artifacts
	results := make([]model.PackageSourceOrArtifact, 0)
	if len(searchText) <= 2 {
		return results, nil
	}

	// Search by Package Name
	packages, err := b.client.PackageVersion.Query().Where(
		packageversion.HasNameWith(
			packagename.NameContainsFold(searchText),
		),
	).WithName(func(q *ent.PackageNameQuery) {}).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed package version query with err: %w", err)
	}

	results = append(results, collect(packages, func(v *ent.PackageVersion) model.PackageSourceOrArtifact {
		return toModelPackage(backReferencePackageVersion(v))
	})...)

	// Search Sources
	sources, err := b.client.SourceName.Query().Where(
		sourcename.Or(
			sourcename.NameContainsFold(searchText),
			sourcename.NamespaceContainsFold(searchText),
		),
	).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed source name query with err: %w", err)
	}
	results = append(results, collect(sources, func(v *ent.SourceName) model.PackageSourceOrArtifact {
		return toModelSource(v)
	})...)

	artifacts, err := b.client.Artifact.Query().Where(
		artifact.DigestContains(searchText),
	).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed artifact query with err: %w", err)
	}

	results = append(results, collect(artifacts, func(v *ent.Artifact) model.PackageSourceOrArtifact {
		return toModelArtifact(v)
	})...)

	return results, nil
}

func (b *EntBackend) FindSoftwareList(ctx context.Context, searchText string, after *string, first *int) (*model.FindSoftwareConnection, error) {
	return nil, fmt.Errorf("not implemented: FindSoftwareList")
}

func (b *EntBackend) FindTopLevelPackagesRelatedToVulnerability(ctx context.Context, vulnerabilityID string) ([][]model.Node, error) {
	// TODO use directly the query because the EntBackend.HasSBOM is limited to MaxPageSize
	hasSBOMs, err := b.HasSBOM(ctx, &model.HasSBOMSpec{})
	if err != nil {
		return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
	}

	result := [][]model.Node{}
	productIDsCheckedVulnerable := make(map[string]bool, len(hasSBOMs))
	for _, hasSBOM := range hasSBOMs {
		switch v := hasSBOM.Subject.(type) {
		case *model.Artifact:
			productIDsCheckedVulnerable[v.ID] = false
		case *model.Package:
			productIDsCheckedVulnerable[v.Namespaces[0].Names[0].Versions[0].ID] = false
		}
	}

	if len(productIDsCheckedVulnerable) != 0 {
		vexStatements, err := b.client.CertifyVex.Query().
			Where(
				certifyvex.HasVulnerabilityWith(vulnerabilityid.VulnerabilityIDEqualFold(vulnerabilityID)),
				certifyvex.StatusNEQ(model.VexStatusNotAffected.String()),
				certifyvex.PackageIDNotNil(),
			).
			All(ctx)
		if err != nil {
			return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
		}
		packagesAlreadyInvestigated := make([]int, 0)
		vexEdges := make([]model.Edge, 0)
		vexOrder := CertifyVexOrder
		for _, vexStatement := range vexStatements {
			//paths, err := b.bfsFromVulnerablePackage(ctx, *vexStatement.PackageID, &productIDsCheckedVulnerable)
			vexEdges = append(vexEdges, vexStatement)

			paths, err := b.bfs(ctx, "", "", 0, vexEdges) //, &productIDsCheckedVulnerable)
			if err != nil {
				return nil, err
			}
			if len(paths) > 0 {
				for i := range paths {
					paths[i] = append(paths[i], toModelCertifyVEXStatement(vexStatement))
				}
				result = append(result, paths...)
				packagesAlreadyInvestigated = append(packagesAlreadyInvestigated, *vexStatement.PackageID)
			}
		}

		// if no VEX Statements have been found or no path from any VEX statement to product has been found
		// then let's check also for CertifyVuln
		if len(vexStatements) == 0 || slices.Contains(maps.Values(productIDsCheckedVulnerable), false) {
			vulnStatements, err := b.CertifyVuln(ctx, &model.CertifyVulnSpec{
				Vulnerability: &model.VulnerabilitySpec{
					VulnerabilityID: &vulnerabilityID,
				},
			})
			if err != nil {
				return nil, gqlerror.Errorf("FindTopLevelPackagesRelatedToVulnerability failed with err: %v", err)
			}
			for _, vuln := range vulnStatements {
				pkg, err := strconv.Atoi(vuln.Package.Namespaces[0].Names[0].Versions[0].ID)
				if err != nil {
					return nil, err
				}
				if !slices.Contains(packagesAlreadyInvestigated, pkg) {
					products, err := b.bfsFromVulnerablePackage(ctx, pkg, &productIDsCheckedVulnerable)
					if err != nil {
						return nil, err
					}
					for i := range products {
						products[i] = append([]model.Node{vuln}, products[i]...)
					}
					result = append(result, products...)
				}
			}
		}
	}
	return result, nil
}

