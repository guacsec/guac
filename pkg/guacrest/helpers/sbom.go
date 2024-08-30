//
// Copyright 2024 The GUAC Authors.
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

package helpers

import (
	"context"
	"fmt"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/Masterminds/semver"
	"github.com/guacsec/guac/pkg/logging"
)

func LatestSBOMFromID(ctx context.Context, client graphql.Client, IDs []string) (*model.AllHasSBOMTree, error) {
	logger := logging.FromContext(ctx)

	latestSBOM := model.HasSBOMsHasSBOM{}

	for _, ID := range IDs {
		// Define the spec to filter SBOMs by the package version level ID
		spec := model.HasSBOMSpec{
			Subject: &model.PackageOrArtifactSpec{
				Package: &model.PkgSpec{
					Id: &ID,
				},
			},
		}

		// Query for SBOMs as a package
		sboms, err := model.HasSBOMs(ctx, client, spec)
		if err != nil {
			logger.Errorw("Failed to query SBOMs for package", "ID", ID, "error", err)
			return nil, err
		}

		// If no SBOMs found, try querying as an artifact
		if len(sboms.HasSBOM) == 0 {
			spec.Subject = &model.PackageOrArtifactSpec{
				Artifact: &model.ArtifactSpec{
					Id: &ID,
				},
			}
			sboms, err = model.HasSBOMs(ctx, client, spec)
			if err != nil {
				logger.Errorw("Failed to query SBOMs for artifact", "ID", ID, "error", err)
				return nil, err
			}
		}

		if len(sboms.HasSBOM) == 0 {
			logger.Errorf("Failed to find any SBOMs with ID: %v", ID)
			return nil, fmt.Errorf("error getting sboms, no sboms with ID %v found", ID)
		}

		// Find the latest SBOM
		for _, sbom := range sboms.HasSBOM {
			if latestSBOM.Id == "" || compare(&sbom.AllHasSBOMTree, &latestSBOM.AllHasSBOMTree, client) {
				latestSBOM = sbom
			}
		}
	}

	return &latestSBOM.AllHasSBOMTree, nil
}

func compare(a *model.AllHasSBOMTree, b *model.AllHasSBOMTree, gqlClient graphql.Client) bool {
	logger := logging.FromContext(context.Background())

	aVersion, err := findSubjectBasedOnType(a, gqlClient)
	if err != nil {
		return false
	}

	bVersion, err := findSubjectBasedOnType(b, gqlClient)
	if err != nil {
		return true
	}

	if (aVersion == "" && bVersion != "") || (aVersion != "" && bVersion == "") {
		return aVersion != ""
	}

	if strings.HasPrefix(aVersion, "sha256") || aVersion == "" ||
		strings.HasPrefix(bVersion, "sha256") || bVersion == "" || aVersion == bVersion {
		return a.KnownSince.After(b.KnownSince)
	}

	parsedAVersion, err := semver.NewVersion(aVersion)
	if err != nil {
		logger.Warnw("Could not parse version, fallback to time", "version", aVersion, "error", err)
		return a.KnownSince.After(b.KnownSince)
	}
	parsedBVersion, err := semver.NewVersion(bVersion)
	if err != nil {
		logger.Warnw("Could not parse version, fallback to time", "version", bVersion, "error", err)
		return a.KnownSince.After(b.KnownSince)
	}

	return parsedAVersion.Compare(parsedBVersion) > 0
}

func findSubjectBasedOnType(a *model.AllHasSBOMTree, gqlClient graphql.Client) (string, error) {
	var version string
	switch subject := a.Subject.(type) {
	case *model.AllHasSBOMTreeSubjectArtifact:
		// Get the package attached to the artifact via an isOccurrence node
		pkg, err := getPkgFromArtifact(gqlClient, subject.Id)
		if err != nil {
			return "", fmt.Errorf("could not find package for subject: %s, with err: %v", subject.Id, err)
		}
		version = pkg.Namespaces[0].Names[0].Versions[0].Version
	case *model.AllHasSBOMTreeSubjectPackage:
		version = subject.Namespaces[0].Names[0].Versions[0].Version
	default:
		return "", fmt.Errorf("Unknown subject type")
	}
	return version, nil
}

func getPkgFromArtifact(gqlClient graphql.Client, id string) (*model.AllPkgTree, error) {
	rsp, err := model.Occurrences(context.Background(), gqlClient, model.IsOccurrenceSpec{
		Artifact: &model.ArtifactSpec{
			Id: &id,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error getting occurrences from artifact %s: %v", id, err)
	}
	for i := range rsp.GetIsOccurrence() {
		if *rsp.GetIsOccurrence()[i].GetSubject().GetTypename() == "Package" {
			p, ok := rsp.GetIsOccurrence()[i].GetSubject().(*model.AllIsOccurrencesTreeSubjectPackage)
			if !ok {
				return nil, fmt.Errorf("could not convert package %s to type *model.AllIsOccurrencesTreeSubjectPackage", id)
			}
			return &p.AllPkgTree, nil
		}
	}
	return nil, nil
}
