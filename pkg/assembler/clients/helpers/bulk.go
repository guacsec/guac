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

package helpers

import (
	"context"
	"fmt"

	"github.com/Khan/genqlient/graphql"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
)

func GetBulkAssembler(ctx context.Context, gqlclient graphql.Client) func([]assembler.AssemblerInput) error {
	logger := logging.FromContext(ctx)
	return func(preds []assembler.IngestPredicates) error {
		for _, p := range preds {
			var packageAndArtifactIDs []string

			packages := p.GetPackages(ctx)
			logger.Infof("assembling Package: %v", len(packages))
			var collectedPackages []model.PkgInputSpec
			collectedPackages = make([]model.PkgInputSpec, 0)
			for _, v := range packages {
				collectedPackages = append(collectedPackages, *v)
			}
			if ids, err := ingestPackages(ctx, gqlclient, collectedPackages); err != nil {
				logger.Errorf("ingestPackages failed with error: %v", err)
			} else {
				packageAndArtifactIDs = append(packageAndArtifactIDs, ids...)
			}

			sources := p.GetSources(ctx)
			logger.Infof("assembling Source: %v", len(sources))

			var collectedSources []model.SourceInputSpec
			collectedSources = make([]model.SourceInputSpec, 0)
			for _, v := range sources {
				collectedSources = append(collectedSources, *v)
			}
			if err := ingestSources(ctx, gqlclient, collectedSources); err != nil {
				logger.Errorf("ingestSources failed with error: %v", err)
			}

			artifacts := p.GetArtifacts(ctx)
			logger.Infof("assembling Artifact: %v", len(artifacts))
			var collectedArtifacts []model.ArtifactInputSpec
			collectedArtifacts = make([]model.ArtifactInputSpec, 0)
			for _, v := range artifacts {
				collectedArtifacts = append(collectedArtifacts, *v)
			}
			if ids, err := ingestArtifacts(ctx, gqlclient, collectedArtifacts); err != nil {
				logger.Errorf("ingestArtifacts failed with error: %v", err)
			} else {
				packageAndArtifactIDs = append(packageAndArtifactIDs, ids...)
			}

			materials := p.GetMaterials(ctx)
			logger.Infof("assembling Materials (Artifact): %v", len(materials))
			if ids, err := ingestArtifacts(ctx, gqlclient, materials); err != nil {
				logger.Errorf("ingestArtifacts failed with error: %v", err)
			} else {
				packageAndArtifactIDs = append(packageAndArtifactIDs, ids...)
			}

			builders := p.GetBuilders(ctx)
			logger.Infof("assembling Builder: %v", len(builders))
			var collectedBuilders []model.BuilderInputSpec
			collectedBuilders = make([]model.BuilderInputSpec, 0)
			for _, v := range builders {
				collectedBuilders = append(collectedBuilders, *v)
			}
			if err := ingestBuilders(ctx, gqlclient, collectedBuilders); err != nil {
				logger.Errorf("ingestBuilders failed with error: %v", err)
			}

			vulns := p.GetVulnerabilities(ctx)
			logger.Infof("assembling Vulnerability: %v", len(vulns))
			var collectedVulns []model.VulnerabilityInputSpec
			collectedVulns = make([]model.VulnerabilityInputSpec, 0)
			for _, v := range vulns {
				collectedVulns = append(collectedVulns, *v)
			}
			if err := ingestVulnerabilities(ctx, gqlclient, collectedVulns); err != nil {
				logger.Errorf("ingestVulnerabilities failed with error: %v", err)
			}

			licenses := p.GetLicenses(ctx)
			logger.Infof("assembling Licenses: %v", len(licenses))
			if err := ingestLicenses(ctx, gqlclient, licenses); err != nil {
				logger.Errorf("ingestLicenses failed with error: %v", err)
			}

			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			if err := ingestCertifyScorecards(ctx, gqlclient, p.CertifyScorecard); err != nil {
				logger.Errorf("ingestCertifyScorecards failed with error: %v", err)
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			isDependenciesIDs := []string{}
			if ingestedIsDependenciesIDs, err := ingestIsDependencies(ctx, gqlclient, p.IsDependency); err != nil {
				logger.Errorf("ingestIsDependencies failed with error: %v", err)
			} else {
				isDependenciesIDs = append(isDependenciesIDs, ingestedIsDependenciesIDs...)
			}

			logger.Infof("assembling IsOccurrence: %v", len(p.IsOccurrence))
			isOccurrencesIDs := []string{}
			if ingestedIsOccurrencesIDs, err := ingestIsOccurrences(ctx, gqlclient, p.IsOccurrence); err != nil {
				logger.Errorf("ingestIsOccurrences failed with error: %v", err)
			} else {
				isOccurrencesIDs = append(isOccurrencesIDs, ingestedIsOccurrencesIDs...)
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			if err := ingestHasSLSAs(ctx, gqlclient, p.HasSlsa); err != nil {
				logger.Errorf("ingestHasSLSAs failed with error: %v", err)
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			if err := ingestCertifyVulns(ctx, gqlclient, p.CertifyVuln); err != nil {
				logger.Errorf("ingestCertifyVulns failed with error: %v", err)
			}

			logger.Infof("assembling VulnMetadata: %v", len(p.VulnMetadata))
			if err := ingestVulnMetadatas(ctx, gqlclient, p.VulnMetadata); err != nil {
				logger.Errorf("ingestVulnMetadatas failed with error: %v", err)
			}

			logger.Infof("assembling VulnEqual: %v", len(p.VulnEqual))
			if err := ingestVulnEquals(ctx, gqlclient, p.VulnEqual); err != nil {
				logger.Errorf("ingestVulnEquals failed with error: %v", err)

			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			if err := ingestHasSourceAts(ctx, gqlclient, p.HasSourceAt); err != nil {
				return fmt.Errorf("ingestHasSourceAts failed with error: %w", err)
			}

			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			if err := ingestCertifyBads(ctx, gqlclient, p.CertifyBad); err != nil {
				logger.Errorf("ingestCertifyBads failed with error: %v", err)

			}

			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			if err := ingestCertifyGoods(ctx, gqlclient, p.CertifyGood); err != nil {
				logger.Errorf("ingestCertifyGoods failed with error: %v", err)

			}

			logger.Infof("assembling PointOfContact: %v", len(p.PointOfContact))
			if err := ingestPointOfContacts(ctx, gqlclient, p.PointOfContact); err != nil {
				logger.Errorf("ingestPointOfContacts failed with error: %v", err)
			}

			logger.Infof("assembling HasMetadata: %v", len(p.HasMetadata))
			if err := ingestBulkHasMetadata(ctx, gqlclient, p.HasMetadata); err != nil {
				logger.Errorf("ingestBulkHasMetadata failed with error: %v", err)
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			if err := ingestHasSBOMs(ctx, gqlclient, p.HasSBOM, model.HasSBOMIncludesInputSpec{
				Software:     packageAndArtifactIDs,
				Dependencies: isDependenciesIDs,
				Occurrences:  isOccurrencesIDs,
			}); err != nil {
				logger.Errorf("ingestHasSBOMs failed with error: %v", err)
			}

			logger.Infof("assembling VEX : %v", len(p.Vex))
			if err := ingestVEXs(ctx, gqlclient, p.Vex); err != nil {
				logger.Errorf("ingestVEXs failed with error: %v", err)
			}

			logger.Infof("assembling HashEqual : %v", len(p.HashEqual))
			if err := ingestHashEquals(ctx, gqlclient, p.HashEqual); err != nil {
				logger.Errorf("ingestHashEquals failed with error: %v", err)
			}

			logger.Infof("assembling PkgEqual : %v", len(p.PkgEqual))
			if err := ingestPkgEquals(ctx, gqlclient, p.PkgEqual); err != nil {
				logger.Errorf("ingestPkgEquals failed with error: %v", err)
			}

			logger.Infof("assembling CertifyLegal : %v", len(p.CertifyLegal))
			if err := ingestCertifyLegals(ctx, gqlclient, p.CertifyLegal); err != nil {
				logger.Errorf("ingestCertifyLegals failed with error: %v", err)
			}
		}
		return nil
	}
}

func ingestPackages(ctx context.Context, client graphql.Client, v []model.PkgInputSpec) ([]string, error) {
	response, err := model.IngestPackages(ctx, client, v)
	if err != nil {
		return nil, fmt.Errorf("ingestPackages failed with error: %w", err)
	}
	var results []string
	for _, pkg := range response.IngestPackages {
		results = append(results, pkg.PackageVersionID)
	}
	return results, nil
}

func ingestSources(ctx context.Context, client graphql.Client, v []model.SourceInputSpec) error {
	_, err := model.IngestSources(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestSources failed with error: %w", err)
	}
	return nil
}

func ingestArtifacts(ctx context.Context, client graphql.Client, v []model.ArtifactInputSpec) ([]string, error) {
	response, err := model.IngestArtifacts(ctx, client, v)
	if err != nil {
		return nil, fmt.Errorf("ingestArtifacts failed with error: %w", err)
	}
	return response.IngestArtifacts, nil
}

func ingestBuilders(ctx context.Context, client graphql.Client, v []model.BuilderInputSpec) error {
	_, err := model.IngestBuilders(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestBuilders failed with error: %w", err)
	}
	return nil
}

func ingestVulnerabilities(ctx context.Context, client graphql.Client, v []model.VulnerabilityInputSpec) error {
	_, err := model.IngestVulnerabilities(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestVulnerabilities failed with error: %w", err)
	}
	return nil
}

func ingestLicenses(ctx context.Context, client graphql.Client, v []model.LicenseInputSpec) error {
	_, err := model.IngestLicenses(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestLicenses failed with error: %w", err)
	}
	return nil
}

func ingestCertifyVulns(ctx context.Context, client graphql.Client, cv []assembler.CertifyVulnIngest) error {
	var pkgs []model.PkgInputSpec
	var vulnerabilities []model.VulnerabilityInputSpec
	var scanMetadataList []model.ScanMetadataInput
	for _, ingest := range cv {
		pkgs = append(pkgs, *ingest.Pkg)
		vulnerabilities = append(vulnerabilities, *ingest.Vulnerability)
		scanMetadataList = append(scanMetadataList, *ingest.VulnData)
	}
	if len(cv) > 0 {
		_, err := model.CertifyVulnPkgs(ctx, client, pkgs, vulnerabilities, scanMetadataList)
		if err != nil {
			return fmt.Errorf("CertifyVulnPkgs failed with error: %w", err)
		}
	}
	return nil
}

func ingestVEXs(ctx context.Context, client graphql.Client, vi []assembler.VexIngest) error {

	var pkgs []model.PkgInputSpec
	var artifacts []model.ArtifactInputSpec
	var pkgVulns []model.VulnerabilityInputSpec
	var artVulns []model.VulnerabilityInputSpec
	var pkgVEXs []model.VexStatementInputSpec
	var artVEXs []model.VexStatementInputSpec
	for _, ingest := range vi {
		if ingest.Pkg != nil && ingest.Artifact != nil {
			return fmt.Errorf("unable to create CertifyVex with both artifact and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Artifact == nil {
			return fmt.Errorf("unable to create CertifyVex without either artifact and Pkg subject specified")
		}

		if ingest.Pkg != nil {
			pkgs = append(pkgs, *ingest.Pkg)
			pkgVulns = append(pkgVulns, *ingest.Vulnerability)
			pkgVEXs = append(pkgVEXs, *ingest.VexData)
		} else {
			artifacts = append(artifacts, *ingest.Artifact)
			artVulns = append(artVulns, *ingest.Vulnerability)
			artVEXs = append(artVEXs, *ingest.VexData)
		}
	}
	if len(artifacts) > 0 {
		_, err := model.CertifyVexArtifacts(ctx, client, artifacts, artVulns, artVEXs)
		if err != nil {
			return fmt.Errorf("CertifyVexArtifacts failed with error: %w", err)
		}
	}
	if len(pkgs) > 0 {
		_, err := model.CertifyVexPkgs(ctx, client, pkgs, pkgVulns, pkgVEXs)
		if err != nil {
			return fmt.Errorf("CertifyVexPkgs failed with error: %w", err)
		}
	}
	return nil
}

func ingestVulnMetadatas(ctx context.Context, client graphql.Client, vm []assembler.VulnMetadataIngest) error {
	var vulnerabilities []model.VulnerabilityInputSpec
	var vulnMetadataList []model.VulnerabilityMetadataInputSpec
	for _, ingest := range vm {
		vulnerabilities = append(vulnerabilities, *ingest.Vulnerability)
		vulnMetadataList = append(vulnMetadataList, *ingest.VulnMetadata)
	}
	if len(vm) > 0 {
		_, err := model.BulkVulnHasMetadata(ctx, client, vulnerabilities, vulnMetadataList)
		if err != nil {
			return fmt.Errorf("VulnHasMetadatas failed with error: %w", err)
		}
	}
	return nil
}

func ingestVulnEquals(ctx context.Context, client graphql.Client, ve []assembler.VulnEqualIngest) error {
	var vulnerabilities []model.VulnerabilityInputSpec
	var equalVulnerabilities []model.VulnerabilityInputSpec
	var vulnEqualList []model.VulnEqualInputSpec
	for _, ingest := range ve {
		vulnerabilities = append(vulnerabilities, *ingest.Vulnerability)
		equalVulnerabilities = append(equalVulnerabilities, *ingest.EqualVulnerability)
		vulnEqualList = append(vulnEqualList, *ingest.VulnEqual)
	}
	if len(ve) > 0 {
		_, err := model.IngestVulnEquals(ctx, client, vulnerabilities, equalVulnerabilities, vulnEqualList)
		if err != nil {
			return fmt.Errorf("IngestVulnEquals failed with error: %w", err)
		}
	}
	return nil
}

func ingestHasSourceAts(ctx context.Context, client graphql.Client, hs []assembler.HasSourceAtIngest) error {
	var pkgVersions []model.PkgInputSpec
	var pkgNames []model.PkgInputSpec
	var pkgVersionSources []model.SourceInputSpec
	var pkgNameSources []model.SourceInputSpec
	var pkgVersionHasSourceAt []model.HasSourceAtInputSpec
	var pkgNameHasSourceAt []model.HasSourceAtInputSpec
	for _, ingest := range hs {
		if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
			pkgVersions = append(pkgVersions, *ingest.Pkg)
			pkgVersionSources = append(pkgVersionSources, *ingest.Src)
			pkgVersionHasSourceAt = append(pkgVersionHasSourceAt, *ingest.HasSourceAt)
		} else {
			pkgNames = append(pkgNames, *ingest.Pkg)
			pkgNameSources = append(pkgNameSources, *ingest.Src)
			pkgNameHasSourceAt = append(pkgNameHasSourceAt, *ingest.HasSourceAt)
		}
	}
	if len(pkgVersions) > 0 {
		_, err := model.IngestHasSourceAts(ctx, client, pkgVersions, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionSources, pkgVersionHasSourceAt)
		if err != nil {
			return fmt.Errorf("IngestHasSourceAts - specific version failed with error: %w", err)
		}
	}
	if len(pkgNames) > 0 {
		_, err := model.IngestHasSourceAts(ctx, client, pkgNames, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNameSources, pkgNameHasSourceAt)
		if err != nil {
			return fmt.Errorf("IngestHasSourceAts - all versions failed with error: %w", err)
		}
	}
	return nil
}

func ingestHasSLSAs(ctx context.Context, client graphql.Client, v []assembler.HasSlsaIngest) error {
	var subjects []model.ArtifactInputSpec
	var slsaAttestations []model.SLSAInputSpec
	var materialList [][]model.ArtifactInputSpec
	var builders []model.BuilderInputSpec
	for _, ingest := range v {
		subjects = append(subjects, *ingest.Artifact)
		slsaAttestations = append(slsaAttestations, *ingest.HasSlsa)
		builders = append(builders, *ingest.Builder)
		materialList = append(materialList, ingest.Materials)
	}
	if len(v) > 0 {
		_, err := model.SLSAForArtifacts(ctx, client, subjects, materialList, builders, slsaAttestations)
		if err != nil {
			return fmt.Errorf("SLSAForArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestCertifyScorecards(ctx context.Context, client graphql.Client, v []assembler.CertifyScorecardIngest) error {
	var srcs []model.SourceInputSpec
	var scorecards []model.ScorecardInputSpec
	for _, ingest := range v {
		srcs = append(srcs, *ingest.Source)
		scorecards = append(scorecards, *ingest.Scorecard)
	}
	if len(v) > 0 {
		_, err := model.CertifyScorecards(ctx, client, srcs, scorecards)
		if err != nil {
			return fmt.Errorf("certifyScorecards failed with error: %w", err)
		}
	}
	return nil
}

func ingestIsDependencies(ctx context.Context, client graphql.Client, v []assembler.IsDependencyIngest) ([]string, error) {

	var depToVersion, depToName struct {
		pkgs            []model.PkgInputSpec
		depPkgs         []model.PkgInputSpec
		depPkgMatchFlag model.MatchFlags
		dependencies    []model.IsDependencyInputSpec
	}

	depToVersion.depPkgMatchFlag = model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
	depToName.depPkgMatchFlag = model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}

	for _, ingest := range v {
		if ingest.DepPkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
			depToVersion.pkgs = append(depToVersion.pkgs, *ingest.Pkg)
			depToVersion.depPkgs = append(depToVersion.depPkgs, *ingest.DepPkg)
			depToVersion.dependencies = append(depToVersion.dependencies, *ingest.IsDependency)
		} else if ingest.DepPkgMatchFlag.Pkg == model.PkgMatchTypeAllVersions {
			depToName.pkgs = append(depToName.pkgs, *ingest.Pkg)
			depToName.depPkgs = append(depToName.depPkgs, *ingest.DepPkg)
			depToName.dependencies = append(depToName.dependencies, *ingest.IsDependency)
		}
	}

	var isDependenciesIDs []string
	if len(depToVersion.pkgs) > 0 {
		isDependencies, err := model.IsDependencies(ctx, client, depToVersion.pkgs, depToVersion.depPkgs, depToVersion.depPkgMatchFlag, depToVersion.dependencies)
		if err != nil {
			return nil, fmt.Errorf("isDependencies failed with error: %w", err)
		}
		isDependenciesIDs = append(isDependenciesIDs, isDependencies.IngestDependencies...)
	}
	if len(depToName.pkgs) > 0 {
		isDependencies, err := model.IsDependencies(ctx, client, depToName.pkgs, depToName.depPkgs, depToName.depPkgMatchFlag, depToName.dependencies)
		if err != nil {
			return nil, fmt.Errorf("isDependencies failed with error: %w", err)
		}
		isDependenciesIDs = append(isDependenciesIDs, isDependencies.IngestDependencies...)
	}

	return isDependenciesIDs, nil
}

func ingestPkgEquals(ctx context.Context, client graphql.Client, v []assembler.PkgEqualIngest) error {
	var packages []model.PkgInputSpec
	var equalPackages []model.PkgInputSpec
	var pkgEquals []model.PkgEqualInputSpec
	for _, ingest := range v {
		packages = append(packages, *ingest.Pkg)
		equalPackages = append(equalPackages, *ingest.EqualPkg)
		pkgEquals = append(pkgEquals, *ingest.PkgEqual)
	}
	if len(v) > 0 {
		_, err := model.IngestPkgEquals(ctx, client, packages, equalPackages, pkgEquals)
		if err != nil {
			return fmt.Errorf("PkgEquals failed with error: %w", err)
		}
	}
	return nil
}

func ingestHashEquals(ctx context.Context, client graphql.Client, v []assembler.HashEqualIngest) error {
	var artifacts []model.ArtifactInputSpec
	var equalArtifacts []model.ArtifactInputSpec
	var hashEquals []model.HashEqualInputSpec
	for _, ingest := range v {
		artifacts = append(artifacts, *ingest.Artifact)
		equalArtifacts = append(equalArtifacts, *ingest.EqualArtifact)
		hashEquals = append(hashEquals, *ingest.HashEqual)
	}
	if len(v) > 0 {
		_, err := model.IngestHashEquals(ctx, client, artifacts, equalArtifacts, hashEquals)
		if err != nil {
			return fmt.Errorf("HashEquals failed with error: %w", err)
		}
	}
	return nil
}

func ingestHasSBOMs(ctx context.Context, client graphql.Client, v []assembler.HasSBOMIngest, includes model.HasSBOMIncludesInputSpec) error {
	var pkgs []model.PkgInputSpec
	var artifacts []model.ArtifactInputSpec
	var pkgSBOMs []model.HasSBOMInputSpec
	var artSBOMs []model.HasSBOMInputSpec
	var pkgIncludes []model.HasSBOMIncludesInputSpec
	var artIncludes []model.HasSBOMIncludesInputSpec
	for _, ingest := range v {
		if ingest.Pkg != nil && ingest.Artifact != nil {
			return fmt.Errorf("unable to create hasSBOM with both artifact and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Artifact == nil {
			return fmt.Errorf("unable to create hasSBOM without either artifact and Pkg subject specified")
		}

		if ingest.Pkg != nil {
			pkgs = append(pkgs, *ingest.Pkg)
			pkgSBOMs = append(pkgSBOMs, *ingest.HasSBOM)
			pkgIncludes = append(pkgIncludes, includes)
		} else {
			artifacts = append(artifacts, *ingest.Artifact)
			artSBOMs = append(artSBOMs, *ingest.HasSBOM)
			artIncludes = append(artIncludes, includes)
		}
	}
	if len(artifacts) > 0 {
		_, err := model.HasSBOMArtifacts(ctx, client, artifacts, artSBOMs, artIncludes)
		if err != nil {
			return fmt.Errorf("hasSBOMArtifacts failed with error: %w", err)
		}
	}
	if len(pkgs) > 0 {
		_, err := model.HasSBOMPkgs(ctx, client, pkgs, pkgSBOMs, pkgIncludes)
		if err != nil {
			return fmt.Errorf("hasSBOMPkgs failed with error: %w", err)
		}
	}
	return nil
}

func ingestPointOfContacts(ctx context.Context, client graphql.Client, poc []assembler.PointOfContactIngest) error {
	var pkgVersions []model.PkgInputSpec
	var pkgNames []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var artifacts []model.ArtifactInputSpec
	var pkgVersionPOC []model.PointOfContactInputSpec
	var pkgNamePOC []model.PointOfContactInputSpec
	var srcPOC []model.PointOfContactInputSpec
	var artPOC []model.PointOfContactInputSpec
	for _, ingest := range poc {
		if err := validatePackageSourceOrArtifactInput(ingest.Pkg, ingest.Src, ingest.Artifact, "ingestPointOfContacts"); err != nil {
			return fmt.Errorf("input validation failed for ingestPointOfContacts: %w", err)
		}
		if ingest.Pkg != nil {
			if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
				pkgVersions = append(pkgVersions, *ingest.Pkg)
				pkgVersionPOC = append(pkgVersionPOC, *ingest.PointOfContact)
			} else {
				pkgNames = append(pkgNames, *ingest.Pkg)
				pkgNamePOC = append(pkgNamePOC, *ingest.PointOfContact)
			}
		} else if ingest.Src != nil {
			sources = append(sources, *ingest.Src)
			srcPOC = append(srcPOC, *ingest.PointOfContact)
		} else {
			artifacts = append(artifacts, *ingest.Artifact)
			artPOC = append(artPOC, *ingest.PointOfContact)
		}
	}
	if len(pkgVersions) > 0 {
		_, err := model.PointOfContactPkgs(ctx, client, pkgVersions, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionPOC)
		if err != nil {
			return fmt.Errorf("HasMetadataPkgs - specific version failed with error: %w", err)
		}
	}
	if len(pkgNames) > 0 {
		_, err := model.PointOfContactPkgs(ctx, client, pkgNames, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNamePOC)
		if err != nil {
			return fmt.Errorf("HasMetadataPkgs - all versions failed with error: %w", err)
		}
	}
	if len(sources) > 0 {
		_, err := model.PointOfContactSrcs(ctx, client, sources, srcPOC)
		if err != nil {
			return fmt.Errorf("HasMetadataSrcs failed with error: %w", err)
		}
	}
	if len(artifacts) > 0 {
		_, err := model.PointOfContactArtifacts(ctx, client, artifacts, artPOC)
		if err != nil {
			return fmt.Errorf("HasMetadataArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestBulkHasMetadata(ctx context.Context, client graphql.Client, v []assembler.HasMetadataIngest) error {
	var pkgVersions []model.PkgInputSpec
	var pkgNames []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var artifacts []model.ArtifactInputSpec
	var pkgVersionHasMetadata []model.HasMetadataInputSpec
	var pkgNameHasMetadata []model.HasMetadataInputSpec
	var srcHasMetadata []model.HasMetadataInputSpec
	var artHasMetadata []model.HasMetadataInputSpec
	for _, ingest := range v {
		if err := validatePackageSourceOrArtifactInput(ingest.Pkg, ingest.Src, ingest.Artifact, "ingestBulkHasMetadata"); err != nil {
			return fmt.Errorf("input validation failed for ingestBulkHasMetadata: %w", err)
		}
		if ingest.Pkg != nil {
			if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
				pkgVersions = append(pkgVersions, *ingest.Pkg)
				pkgVersionHasMetadata = append(pkgVersionHasMetadata, *ingest.HasMetadata)
			} else {
				pkgNames = append(pkgNames, *ingest.Pkg)
				pkgNameHasMetadata = append(pkgNameHasMetadata, *ingest.HasMetadata)
			}
		} else if ingest.Src != nil {
			sources = append(sources, *ingest.Src)
			srcHasMetadata = append(srcHasMetadata, *ingest.HasMetadata)
		} else {
			artifacts = append(artifacts, *ingest.Artifact)
			artHasMetadata = append(artHasMetadata, *ingest.HasMetadata)
		}
	}
	if len(pkgVersions) > 0 {
		_, err := model.HasMetadataPkgs(ctx, client, pkgVersions, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionHasMetadata)
		if err != nil {
			return fmt.Errorf("HasMetadataPkgs - specific version failed with error: %w", err)
		}
	}
	if len(pkgNames) > 0 {
		_, err := model.HasMetadataPkgs(ctx, client, pkgNames, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNameHasMetadata)
		if err != nil {
			return fmt.Errorf("HasMetadataPkgs - all versions failed with error: %w", err)
		}
	}
	if len(sources) > 0 {
		_, err := model.HasMetadataSrcs(ctx, client, sources, srcHasMetadata)
		if err != nil {
			return fmt.Errorf("HasMetadataSrcs failed with error: %w", err)
		}
	}
	if len(artifacts) > 0 {
		_, err := model.HasMetadataArtifacts(ctx, client, artifacts, artHasMetadata)
		if err != nil {
			return fmt.Errorf("HasMetadataArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestCertifyGoods(ctx context.Context, client graphql.Client, v []assembler.CertifyGoodIngest) error {
	var pkgVersions []model.PkgInputSpec
	var pkgNames []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var artifacts []model.ArtifactInputSpec
	var pkgVersionCertifyGoods []model.CertifyGoodInputSpec
	var pkgNameCertifyGoods []model.CertifyGoodInputSpec
	var srcCertifyGoods []model.CertifyGoodInputSpec
	var artCertifyGoods []model.CertifyGoodInputSpec
	for _, ingest := range v {
		if err := validatePackageSourceOrArtifactInput(ingest.Pkg, ingest.Src, ingest.Artifact, "ingestCertifyGoods"); err != nil {
			return fmt.Errorf("input validation failed for ingestCertifyGoods: %w", err)
		}
		if ingest.Pkg != nil {
			if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
				pkgVersions = append(pkgVersions, *ingest.Pkg)
				pkgVersionCertifyGoods = append(pkgVersionCertifyGoods, *ingest.CertifyGood)
			} else {
				pkgNames = append(pkgNames, *ingest.Pkg)
				pkgNameCertifyGoods = append(pkgNameCertifyGoods, *ingest.CertifyGood)
			}
		} else if ingest.Src != nil {
			sources = append(sources, *ingest.Src)
			srcCertifyGoods = append(srcCertifyGoods, *ingest.CertifyGood)
		} else {
			artifacts = append(artifacts, *ingest.Artifact)
			artCertifyGoods = append(artCertifyGoods, *ingest.CertifyGood)
		}
	}
	if len(pkgVersions) > 0 {
		_, err := model.CertifyGoodPkgs(ctx, client, pkgVersions, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionCertifyGoods)
		if err != nil {
			return fmt.Errorf("CertifyGoodPkgs - specific version failed with error: %w", err)
		}
	}
	if len(pkgNames) > 0 {
		_, err := model.CertifyGoodPkgs(ctx, client, pkgNames, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNameCertifyGoods)
		if err != nil {
			return fmt.Errorf("CertifyGoodPkgs - all versions failed with error: %w", err)
		}
	}
	if len(sources) > 0 {
		_, err := model.CertifyGoodSrcs(ctx, client, sources, srcCertifyGoods)
		if err != nil {
			return fmt.Errorf("CertifyGoodSrcs failed with error: %w", err)
		}
	}
	if len(artifacts) > 0 {
		_, err := model.CertifyGoodArtifacts(ctx, client, artifacts, artCertifyGoods)
		if err != nil {
			return fmt.Errorf("CertifyGoodArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestCertifyBads(ctx context.Context, client graphql.Client, v []assembler.CertifyBadIngest) error {
	var pkgVersions []model.PkgInputSpec
	var pkgNames []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var artifacts []model.ArtifactInputSpec
	var pkgVersionCertifyBads []model.CertifyBadInputSpec
	var pkgNameCertifyBads []model.CertifyBadInputSpec
	var srcCertifyBads []model.CertifyBadInputSpec
	var artCertifyBads []model.CertifyBadInputSpec
	for _, ingest := range v {
		if err := validatePackageSourceOrArtifactInput(ingest.Pkg, ingest.Src, ingest.Artifact, "ingestCertifyBads"); err != nil {
			return fmt.Errorf("input validation failed for ingestCertifyBads: %w", err)
		}
		if ingest.Pkg != nil {
			if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
				pkgVersions = append(pkgVersions, *ingest.Pkg)
				pkgVersionCertifyBads = append(pkgVersionCertifyBads, *ingest.CertifyBad)
			} else {
				pkgNames = append(pkgNames, *ingest.Pkg)
				pkgNameCertifyBads = append(pkgNameCertifyBads, *ingest.CertifyBad)
			}
		} else if ingest.Src != nil {
			sources = append(sources, *ingest.Src)
			srcCertifyBads = append(srcCertifyBads, *ingest.CertifyBad)
		} else {
			artifacts = append(artifacts, *ingest.Artifact)
			artCertifyBads = append(artCertifyBads, *ingest.CertifyBad)
		}
	}
	if len(pkgVersions) > 0 {
		_, err := model.CertifyBadPkgs(ctx, client, pkgVersions, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionCertifyBads)
		if err != nil {
			return fmt.Errorf("certifyBadPkgs - specific version failed with error: %w", err)
		}
	}
	if len(pkgNames) > 0 {
		_, err := model.CertifyBadPkgs(ctx, client, pkgNames, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNameCertifyBads)
		if err != nil {
			return fmt.Errorf("certifyBadPkgs - all versions failed with error: %w", err)
		}
	}
	if len(sources) > 0 {
		_, err := model.CertifyBadSrcs(ctx, client, sources, srcCertifyBads)
		if err != nil {
			return fmt.Errorf("CertifyBadSrcs failed with error: %w", err)
		}
	}
	if len(artifacts) > 0 {
		_, err := model.CertifyBadArtifacts(ctx, client, artifacts, artCertifyBads)
		if err != nil {
			return fmt.Errorf("CertifyBadArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestIsOccurrences(ctx context.Context, client graphql.Client, v []assembler.IsOccurrenceIngest) ([]string, error) {
	var pkgs []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var pkgArtifacts []model.ArtifactInputSpec
	var pkgOccurrences []model.IsOccurrenceInputSpec
	var srcArtifacts []model.ArtifactInputSpec
	var srcOccurrences []model.IsOccurrenceInputSpec
	for _, ingest := range v {

		if ingest.Pkg != nil && ingest.Src != nil {
			return nil, fmt.Errorf("unable to create IsOccurrence with both Src and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Src == nil {
			return nil, fmt.Errorf("unable to create IsOccurrence without either Src and Pkg subject specified")
		}

		if ingest.Pkg != nil {
			pkgs = append(pkgs, *ingest.Pkg)
			pkgArtifacts = append(pkgArtifacts, *ingest.Artifact)
			pkgOccurrences = append(pkgOccurrences, *ingest.IsOccurrence)
		} else {
			sources = append(sources, *ingest.Src)
			srcArtifacts = append(srcArtifacts, *ingest.Artifact)
			srcOccurrences = append(srcOccurrences, *ingest.IsOccurrence)
		}
	}
	var isOccurrencesIDs []string
	if len(sources) > 0 {
		isOccurrences, err := model.IsOccurrencesSrc(ctx, client, sources, srcArtifacts, srcOccurrences)
		if err != nil {
			return nil, fmt.Errorf("isOccurrencesSrc failed with error: %w", err)
		}
		isOccurrencesIDs = append(isOccurrencesIDs, isOccurrences.IngestOccurrences...)
	}
	if len(pkgs) > 0 {
		isOccurrences, err := model.IsOccurrencesPkg(ctx, client, pkgs, pkgArtifacts, pkgOccurrences)
		if err != nil {
			return nil, fmt.Errorf("isOccurrencesPkg failed with error: %w", err)
		}
		isOccurrencesIDs = append(isOccurrencesIDs, isOccurrences.IngestOccurrences...)
	}
	return isOccurrencesIDs, nil
}

func ingestCertifyLegals(ctx context.Context, client graphql.Client, v []assembler.CertifyLegalIngest) error {
	var pkgs []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var pkgDec [][]model.LicenseInputSpec
	var pkgDis [][]model.LicenseInputSpec
	var pkgCL []model.CertifyLegalInputSpec
	var srcDec [][]model.LicenseInputSpec
	var srcDis [][]model.LicenseInputSpec
	var srcCL []model.CertifyLegalInputSpec
	for _, ingest := range v {

		if ingest.Pkg != nil && ingest.Src != nil {
			return fmt.Errorf("unable to create CertifyLegal with both Src and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Src == nil {
			return fmt.Errorf("unable to create CertifyLegal without either Src and Pkg subject specified")
		}

		if ingest.Pkg != nil {
			pkgs = append(pkgs, *ingest.Pkg)
			pkgDec = append(pkgDec, ingest.Declared)
			pkgDis = append(pkgDis, ingest.Discovered)
			pkgCL = append(pkgCL, *ingest.CertifyLegal)
		} else {
			sources = append(sources, *ingest.Src)
			srcDec = append(srcDec, ingest.Declared)
			srcDis = append(srcDis, ingest.Discovered)
			srcCL = append(srcCL, *ingest.CertifyLegal)
		}
	}
	if len(sources) > 0 {
		_, err := model.CertifyLegalSrcs(ctx, client, sources, srcDec, srcDis, srcCL)
		if err != nil {
			return fmt.Errorf("certifyLegalSrc failed with error: %w", err)
		}
	}
	if len(pkgs) > 0 {
		_, err := model.CertifyLegalPkgs(ctx, client, pkgs, pkgDec, pkgDis, pkgCL)
		if err != nil {
			return fmt.Errorf("certifyLegalPkg failed with error: %w", err)
		}
	}
	return nil
}
