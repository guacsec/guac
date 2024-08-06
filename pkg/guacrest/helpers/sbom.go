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
	"go.uber.org/zap"
	"strings"

	"github.com/Khan/genqlient/graphql"
	"github.com/Masterminds/semver"
	"github.com/guacsec/guac/pkg/logging"
)

func LatestSBOMForAGivenId(ctx context.Context, client graphql.Client, id string) (*model.AllHasSBOMTree, error) {
	logger := logging.FromContext(ctx)

	// Define the spec to filter SBOMs by the package version level ID
	spec := model.HasSBOMSpec{
		Subject: &model.PackageOrArtifactSpec{
			Package: &model.PkgSpec{
				Id: &id,
			},
		},
	}

	// Query for SBOMs as a package
	sboms, err := model.HasSBOMs(ctx, client, spec)
	if err != nil {
		logger.Errorw("Failed to query SBOMs for package", "id", id, "error", err)
		return nil, err
	}

	// If no SBOMs found, try querying as an artifact
	if len(sboms.HasSBOM) == 0 {
		spec.Subject = &model.PackageOrArtifactSpec{
			Artifact: &model.ArtifactSpec{
				Id: &id,
			},
		}
		sboms, err = model.HasSBOMs(ctx, client, spec)
		if err != nil {
			logger.Errorw("Failed to query SBOMs for artifact", "id", id, "error", err)
			return nil, err
		}
	}

	if len(sboms.HasSBOM) == 0 {
		logger.Errorf("Failed to find any SBOMs with id: %v", id)
		return nil, fmt.Errorf("error getting sboms, no sboms with id %v found", id)
	}

	// Find the latest SBOM
	latestSBOM := sboms.HasSBOM[0]
	for _, sbom := range sboms.HasSBOM[1:] {
		if compare(&sbom.AllHasSBOMTree, &latestSBOM.AllHasSBOMTree, client) {
			latestSBOM = sbom
		}
	}

	return &latestSBOM.AllHasSBOMTree, nil
}

func compare(a *model.AllHasSBOMTree, b *model.AllHasSBOMTree, gqlClient graphql.Client) bool {
	logger := logging.FromContext(context.Background())

	aVersion, err := findSubjectBasedOnType(a, gqlClient, logger)
	if err != nil {
		return false
	}

	bVersion, err := findSubjectBasedOnType(b, gqlClient, logger)
	if err != nil {
		return false
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

func findSubjectBasedOnType(a *model.AllHasSBOMTree, gqlClient graphql.Client, logger *zap.SugaredLogger) (string, error) {
	var version string
	switch subject := a.Subject.(type) {
	case *model.AllHasSBOMTreeSubjectArtifact:
		// Get the package attached to the artifact via an isOccurrence node
		pkg, err := getPkgFromArtifact(gqlClient, subject.Id, logger)
		if err != nil {
			return "", fmt.Errorf("could not find package for subject: %s, with err: %v", subject.Id, err)
		}
		version = pkg.Namespaces[0].Names[0].Versions[0].Version
	case *model.AllHasSBOMTreeSubjectPackage:
		version = subject.Namespaces[0].Names[0].Versions[0].Version
	default:
		logger.Error("Unknown subject type")
		return "", fmt.Errorf("Unknown subject type")
	}
	return version, nil
}

func getPkgFromArtifact(gqlClient graphql.Client, id string, logger *zap.SugaredLogger) (*model.AllPkgTree, error) {
	rsp, err := model.Occurrences(context.Background(), gqlClient, model.IsOccurrenceSpec{
		Artifact: &model.ArtifactSpec{
			Id: &id,
		},
	})
	if err != nil {
		logger.Errorw("Failed to get occurrences", "artifactID", id, "error", err)
		return nil, err
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
