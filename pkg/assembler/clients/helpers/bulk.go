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
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/logging"
)

func GetBulkAssembler(ctx context.Context, gqlclient graphql.Client) func([]assembler.AssemblerInput) error {
	logger := logging.FromContext(ctx)
	return func(preds []assembler.IngestPredicates) error {
		for _, p := range preds {

			// Ingest Packages
			packageIDs := make([]string, 0)

			packages := p.GetPackages(ctx)
			logger.Infof("assembling Package: %v", len(packages))

			collectedIDorPkgInputs, err := ingestPackages(ctx, gqlclient, packages)
			if err != nil {
				return fmt.Errorf("ingestPackages failed with error: %v", err)
			}

			var pkgVersionIDs []string
			for _, pkgVersionID := range collectedIDorPkgInputs {
				pkgVersionIDs = append(pkgVersionIDs, *pkgVersionID.PackageVersionID)
			}
			packageIDs = append(packageIDs, pkgVersionIDs...)

			// Ingest sources
			sources := p.GetSources(ctx)
			logger.Infof("assembling Source: %v", len(sources))

			collectedIDorSrcInputs, err := ingestSources(ctx, gqlclient, sources)
			if err != nil {
				return fmt.Errorf("ingestSources failed with error: %v", err)
			}

			// Ingest Artifacts
			artifactIDs := make([]string, 0)
			artifacts := p.GetArtifacts(ctx)
			logger.Infof("assembling Artifact: %v", len(artifacts))

			collectedIDorArtInputs, err := ingestArtifacts(ctx, gqlclient, artifacts)
			if err != nil {
				return fmt.Errorf("ingestArtifacts failed with error: %v", err)
			}
			var artIDs []string
			for _, artID := range collectedIDorArtInputs {
				artIDs = append(artIDs, *artID.ArtifactID)
			}
			artifactIDs = append(artifactIDs, artIDs...)

			// Ingest Materials
			materials := p.GetMaterials(ctx)
			logger.Infof("assembling Materials (Artifact): %v", len(materials))

			collectedIDorMatInputs, err := ingestArtifacts(ctx, gqlclient, materials)
			if err != nil {
				return fmt.Errorf("ingestArtifacts failed with error: %v", err)
			}

			// Ingest Builders
			builders := p.GetBuilders(ctx)
			logger.Infof("assembling Builder: %v", len(builders))

			collectedIDorBuilderInputs, err := ingestBuilders(ctx, gqlclient, builders)
			if err != nil {
				return fmt.Errorf("ingestBuilders failed with error: %v", err)
			}

			// Ingest Vulnerabilities
			vulns := p.GetVulnerabilities(ctx)
			logger.Infof("assembling Vulnerability: %v", len(vulns))

			collectedIDorVulnInputs, err := ingestVulnerabilities(ctx, gqlclient, vulns)
			if err != nil {
				return fmt.Errorf("ingestVulnerabilities failed with error: %v", err)
			}

			// Ingest Licenses
			licenses := p.GetLicenses(ctx)
			logger.Infof("assembling Licenses: %v", len(licenses))

			collectedIDorLicenseInputs, err := ingestLicenses(ctx, gqlclient, licenses)
			if err != nil {
				return fmt.Errorf("ingestLicenses failed with error: %v", err)
			}

			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			if err := ingestCertifyScorecards(ctx, gqlclient, p.CertifyScorecard, collectedIDorSrcInputs); err != nil {
				logger.Errorf("ingestCertifyScorecards failed with error: %v", err)
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			isDependenciesIDs := make([]string, 0)
			if ingestedIsDependenciesIDs, err := ingestIsDependencies(ctx, gqlclient, p.IsDependency, collectedIDorPkgInputs); err != nil {
				logger.Errorf("ingestIsDependencies failed with error: %v", err)
			} else {
				isDependenciesIDs = append(isDependenciesIDs, ingestedIsDependenciesIDs...)
			}

			logger.Infof("assembling IsOccurrence: %v", len(p.IsOccurrence))
			isOccurrencesIDs := make([]string, 0)
			if ingestedIsOccurrencesIDs, err := ingestIsOccurrences(ctx, gqlclient, p.IsOccurrence, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
				logger.Errorf("ingestIsOccurrences failed with error: %v", err)
			} else {
				isOccurrencesIDs = append(isOccurrencesIDs, ingestedIsOccurrencesIDs...)
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			if err := ingestHasSLSAs(ctx, gqlclient, p.HasSlsa, collectedIDorArtInputs, collectedIDorMatInputs, collectedIDorBuilderInputs); err != nil {
				logger.Errorf("ingestHasSLSAs failed with error: %v", err)
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			if err := ingestCertifyVulns(ctx, gqlclient, p.CertifyVuln, collectedIDorPkgInputs, collectedIDorVulnInputs); err != nil {
				logger.Errorf("ingestCertifyVulns failed with error: %v", err)
			}

			logger.Infof("assembling VulnMetadata: %v", len(p.VulnMetadata))
			if err := ingestVulnMetadatas(ctx, gqlclient, p.VulnMetadata, collectedIDorVulnInputs); err != nil {
				logger.Errorf("ingestVulnMetadatas failed with error: %v", err)
			}

			logger.Infof("assembling VulnEqual: %v", len(p.VulnEqual))
			if err := ingestVulnEquals(ctx, gqlclient, p.VulnEqual, collectedIDorVulnInputs); err != nil {
				logger.Errorf("ingestVulnEquals failed with error: %v", err)

			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			if err := ingestHasSourceAts(ctx, gqlclient, p.HasSourceAt, collectedIDorPkgInputs, collectedIDorSrcInputs); err != nil {
				return fmt.Errorf("ingestHasSourceAts failed with error: %w", err)
			}

			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			if err := ingestCertifyBads(ctx, gqlclient, p.CertifyBad, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
				logger.Errorf("ingestCertifyBads failed with error: %v", err)

			}

			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			if err := ingestCertifyGoods(ctx, gqlclient, p.CertifyGood, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
				logger.Errorf("ingestCertifyGoods failed with error: %v", err)

			}

			logger.Infof("assembling PointOfContact: %v", len(p.PointOfContact))
			if err := ingestPointOfContacts(ctx, gqlclient, p.PointOfContact, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
				logger.Errorf("ingestPointOfContacts failed with error: %v", err)
			}

			logger.Infof("assembling HasMetadata: %v", len(p.HasMetadata))
			if err := ingestBulkHasMetadata(ctx, gqlclient, p.HasMetadata, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
				logger.Errorf("ingestBulkHasMetadata failed with error: %v", err)
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			if err := ingestHasSBOMs(ctx, gqlclient, p.HasSBOM, model.HasSBOMIncludesInputSpec{
				Packages:     packageIDs,
				Artifacts:    artifactIDs,
				Dependencies: isDependenciesIDs,
				Occurrences:  isOccurrencesIDs,
			}, collectedIDorPkgInputs, collectedIDorArtInputs); err != nil {
				logger.Errorf("ingestHasSBOMs failed with error: %v", err)
			}

			logger.Infof("assembling VEX : %v", len(p.Vex))
			if err := ingestVEXs(ctx, gqlclient, p.Vex, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorVulnInputs); err != nil {
				logger.Errorf("ingestVEXs failed with error: %v", err)
			}

			logger.Infof("assembling HashEqual : %v", len(p.HashEqual))
			if err := ingestHashEquals(ctx, gqlclient, p.HashEqual, collectedIDorArtInputs); err != nil {
				logger.Errorf("ingestHashEquals failed with error: %v", err)
			}

			logger.Infof("assembling PkgEqual : %v", len(p.PkgEqual))
			if err := ingestPkgEquals(ctx, gqlclient, p.PkgEqual, collectedIDorPkgInputs); err != nil {
				logger.Errorf("ingestPkgEquals failed with error: %v", err)
			}

			logger.Infof("assembling CertifyLegal : %v", len(p.CertifyLegal))
			if err := ingestCertifyLegals(ctx, gqlclient, p.CertifyLegal, collectedIDorPkgInputs, collectedIDorSrcInputs, collectedIDorLicenseInputs); err != nil {
				logger.Errorf("ingestCertifyLegals failed with error: %v", err)
			}
		}
		return nil
	}
}

// ingestPackages takes in the map of IDorPkgInput which contains the pkgInputSpec and outputs a map that contains the pkgIDs to be used for verb ingestion
func ingestPackages(ctx context.Context, client graphql.Client, packageInputMap map[string]*model.IDorPkgInput) (map[string]*model.IDorPkgInput, error) {
	var keys []string
	var pkgInputs []model.IDorPkgInput
	pkgInputs = make([]model.IDorPkgInput, 0)
	for key, pkgInput := range packageInputMap {
		keys = append(keys, key)
		pkgInputs = append(pkgInputs, *pkgInput)
	}
	response, err := model.IngestPackages(ctx, client, pkgInputs)
	if err != nil {
		return nil, fmt.Errorf("IngestPackages failed with error: %w", err)
	}

	results := make(map[string]*model.IDorPkgInput)

	for i := range response.IngestPackages {
		pkgIDs := response.IngestPackages[i]
		results[keys[i]] = &model.IDorPkgInput{
			PackageInput:       pkgInputs[i].PackageInput,
			PackageTypeID:      &pkgIDs.PackageTypeID,
			PackageNamespaceID: &pkgIDs.PackageNamespaceID,
			PackageNameID:      &pkgIDs.PackageNameID,
			PackageVersionID:   &pkgIDs.PackageVersionID,
		}
	}
	return results, nil
}

// ingestSources takes in the map of IDorSourceInput which contains the sourceInputSpec and outputs a map that contains the srcIDs to be used for verb ingestion
func ingestSources(ctx context.Context, client graphql.Client, sourceInputMap map[string]*model.IDorSourceInput) (map[string]*model.IDorSourceInput, error) {
	var keys []string
	var srcInputs []model.IDorSourceInput
	srcInputs = make([]model.IDorSourceInput, 0)
	for key, srcInput := range sourceInputMap {
		keys = append(keys, key)
		srcInputs = append(srcInputs, *srcInput)
	}
	response, err := model.IngestSources(ctx, client, srcInputs)
	if err != nil {
		return nil, fmt.Errorf("IngestSources failed with error: %w", err)
	}
	results := make(map[string]*model.IDorSourceInput)

	for i := range response.IngestSources {
		srcIDs := response.IngestSources[i]
		results[keys[i]] = &model.IDorSourceInput{
			SourceInput:       srcInputs[i].SourceInput,
			SourceTypeID:      &srcIDs.SourceTypeID,
			SourceNamespaceID: &srcIDs.SourceNamespaceID,
			SourceNameID:      &srcIDs.SourceNameID,
		}
	}
	return results, nil
}

// ingestArtifacts takes in the map of IDorArtifactInput which contains the artifactInputSpec and outputs a map that contains the artifactID to be used for verb ingestion
func ingestArtifacts(ctx context.Context, client graphql.Client, artInputMap map[string]*model.IDorArtifactInput) (map[string]*model.IDorArtifactInput, error) {
	var keys []string
	var artInputs []model.IDorArtifactInput
	artInputs = make([]model.IDorArtifactInput, 0)
	for key, artInput := range artInputMap {
		keys = append(keys, key)
		artInputs = append(artInputs, *artInput)
	}
	response, err := model.IngestArtifacts(ctx, client, artInputs)
	if err != nil {
		return nil, fmt.Errorf("IngestArtifacts failed with error: %w", err)
	}
	results := make(map[string]*model.IDorArtifactInput)

	for i := range response.IngestArtifacts {
		artID := response.IngestArtifacts[i]
		results[keys[i]] = &model.IDorArtifactInput{
			ArtifactInput: artInputs[i].ArtifactInput,
			ArtifactID:    &artID,
		}
	}
	return results, nil
}

// ingestBuilders takes in the map of IDorBuilderInput which contains the builderInput and outputs a map that contains the builderID to be used for verb ingestion
func ingestBuilders(ctx context.Context, client graphql.Client, buildInputMap map[string]*model.IDorBuilderInput) (map[string]*model.IDorBuilderInput, error) {
	var keys []string
	var buildInputs []model.IDorBuilderInput
	buildInputs = make([]model.IDorBuilderInput, 0)
	for key, srcInput := range buildInputMap {
		keys = append(keys, key)
		buildInputs = append(buildInputs, *srcInput)
	}
	response, err := model.IngestBuilders(ctx, client, buildInputs)
	if err != nil {
		return nil, fmt.Errorf("IngestBuilders failed with error: %w", err)
	}

	results := make(map[string]*model.IDorBuilderInput)

	for i := range response.IngestBuilders {
		buildID := response.IngestBuilders[i]
		results[keys[i]] = &model.IDorBuilderInput{
			BuilderInput: buildInputs[i].BuilderInput,
			BuilderID:    &buildID,
		}
	}
	return results, nil
}

// ingestVulnerabilities takes in the map of IDorVulnerabilityInput which contains the vulnerabilityInput and outputs a map that contains the vulnerabilityIDs to be used for verb ingestion
func ingestVulnerabilities(ctx context.Context, client graphql.Client, vulnInputMap map[string]*model.IDorVulnerabilityInput) (map[string]*model.IDorVulnerabilityInput, error) {
	var keys []string
	var vulnInputs []model.IDorVulnerabilityInput
	vulnInputs = make([]model.IDorVulnerabilityInput, 0)
	for key, vulnInput := range vulnInputMap {
		keys = append(keys, key)
		vulnInputs = append(vulnInputs, *vulnInput)
	}
	response, err := model.IngestVulnerabilities(ctx, client, vulnInputs)
	if err != nil {
		return nil, fmt.Errorf("IngestVulnerabilities failed with error: %w", err)
	}
	results := make(map[string]*model.IDorVulnerabilityInput)

	for i := range response.IngestVulnerabilities {
		vulnIDs := response.IngestVulnerabilities[i]
		results[keys[i]] = &model.IDorVulnerabilityInput{
			VulnerabilityInput:  vulnInputs[i].VulnerabilityInput,
			VulnerabilityTypeID: &vulnIDs.VulnerabilityTypeID,
			VulnerabilityNodeID: &vulnIDs.VulnerabilityNodeID,
		}
	}
	return results, nil
}

// ingestLicenses takes in the map of IDorLicenseInput which contains the licenseInput and outputs a map that contains the licenseID to be used for verb ingestion
func ingestLicenses(ctx context.Context, client graphql.Client, licenseInputMap map[string]*model.IDorLicenseInput) (map[string]*model.IDorLicenseInput, error) {
	var keys []string
	var licenseInputs []model.IDorLicenseInput
	licenseInputs = make([]model.IDorLicenseInput, 0)
	for key, licenseInput := range licenseInputMap {
		keys = append(keys, key)
		licenseInputs = append(licenseInputs, *licenseInput)
	}
	response, err := model.IngestLicenses(ctx, client, licenseInputs)
	if err != nil {
		return nil, fmt.Errorf("IngestLicenses failed with error: %w", err)
	}
	results := make(map[string]*model.IDorLicenseInput)

	for i := range response.IngestLicenses {
		licenseID := response.IngestLicenses[i]
		results[keys[i]] = &model.IDorLicenseInput{
			LicenseInput: licenseInputs[i].LicenseInput,
			LicenseID:    &licenseID,
		}
	}
	return results, nil
}

func ingestCertifyVulns(ctx context.Context, client graphql.Client, cv []assembler.CertifyVulnIngest, packageInputMap map[string]*model.IDorPkgInput, vulnInputMap map[string]*model.IDorVulnerabilityInput) error {
	var pkgIDs []model.IDorPkgInput
	var vulnerabilityIDs []model.IDorVulnerabilityInput
	var scanMetadataList []model.ScanMetadataInput

	for _, ingest := range cv {
		if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
			pkgIDs = append(pkgIDs, *pkgID)
		} else {
			return fmt.Errorf("failed to find ingested Package ID for certifyVuln: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
		}
		if vulnID, found := vulnInputMap[helpers.VulnInputToVURI(ingest.Vulnerability)]; found {
			vulnerabilityIDs = append(vulnerabilityIDs, *vulnID)
		} else {
			return fmt.Errorf("failed to find ingested vulnerability ID for certifyVuln: %s", helpers.VulnInputToVURI(ingest.Vulnerability))
		}
		scanMetadataList = append(scanMetadataList, *ingest.VulnData)
	}
	if len(cv) > 0 {
		_, err := model.IngestCertifyVulnPkgs(ctx, client, pkgIDs, vulnerabilityIDs, scanMetadataList)
		if err != nil {
			return fmt.Errorf("CertifyVulnPkgs failed with error: %w", err)
		}
	}
	return nil
}

func ingestVEXs(ctx context.Context, client graphql.Client, vi []assembler.VexIngest, packageInputMap map[string]*model.IDorPkgInput, artInputMap map[string]*model.IDorArtifactInput, vulnInputMap map[string]*model.IDorVulnerabilityInput) error {
	var pkgIDs []model.IDorPkgInput
	var artifactIDs []model.IDorArtifactInput
	var pkgVulns []model.IDorVulnerabilityInput
	var artVulns []model.IDorVulnerabilityInput
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
			if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
				pkgIDs = append(pkgIDs, *pkgID)
			} else {
				return fmt.Errorf("failed to find ingested Package ID for Vex: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
			}
			if vulnID, found := vulnInputMap[helpers.VulnInputToVURI(ingest.Vulnerability)]; found {
				pkgVulns = append(pkgVulns, *vulnID)
			} else {
				return fmt.Errorf("failed to find ingested vulnerability ID for Vex: %s", helpers.VulnInputToVURI(ingest.Vulnerability))
			}
			pkgVEXs = append(pkgVEXs, *ingest.VexData)
		} else {
			if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
				artifactIDs = append(artifactIDs, *artID)
			} else {
				return fmt.Errorf("failed to find ingested artifact ID for Vex: %s", helpers.ArtifactKey(ingest.Artifact))
			}
			if vulnID, found := vulnInputMap[helpers.VulnInputToVURI(ingest.Vulnerability)]; found {
				artVulns = append(artVulns, *vulnID)
			} else {
				return fmt.Errorf("failed to find ingested vulnerability ID for Vex: %s", helpers.VulnInputToVURI(ingest.Vulnerability))
			}
			artVEXs = append(artVEXs, *ingest.VexData)
		}
	}
	if len(artifactIDs) > 0 {
		_, err := model.IngestCertifyVexArtifacts(ctx, client, artifactIDs, artVulns, artVEXs)
		if err != nil {
			return fmt.Errorf("CertifyVexArtifacts failed with error: %w", err)
		}
	}
	if len(pkgIDs) > 0 {
		_, err := model.IngestCertifyVexPkgs(ctx, client, pkgIDs, pkgVulns, pkgVEXs)
		if err != nil {
			return fmt.Errorf("CertifyVexPkgs failed with error: %w", err)
		}
	}
	return nil
}

func ingestVulnMetadatas(ctx context.Context, client graphql.Client, vm []assembler.VulnMetadataIngest, vulnInputMap map[string]*model.IDorVulnerabilityInput) error {
	var vulnIDs []model.IDorVulnerabilityInput
	var vulnMetadataList []model.VulnerabilityMetadataInputSpec
	for _, ingest := range vm {
		if vulnID, found := vulnInputMap[helpers.VulnInputToVURI(ingest.Vulnerability)]; found {
			vulnIDs = append(vulnIDs, *vulnID)
		} else {
			return fmt.Errorf("failed to find ingested vulnerability ID for vulnMetadata: %s", helpers.VulnInputToVURI(ingest.Vulnerability))
		}
		vulnMetadataList = append(vulnMetadataList, *ingest.VulnMetadata)
	}
	if len(vm) > 0 {
		_, err := model.IngestBulkVulnHasMetadata(ctx, client, vulnIDs, vulnMetadataList)
		if err != nil {
			return fmt.Errorf("VulnHasMetadatas failed with error: %w", err)
		}
	}
	return nil
}

func ingestVulnEquals(ctx context.Context, client graphql.Client, ve []assembler.VulnEqualIngest, vulnInputMap map[string]*model.IDorVulnerabilityInput) error {
	var vulnIDs []model.IDorVulnerabilityInput
	var equalVulnIDs []model.IDorVulnerabilityInput
	var vulnEqualList []model.VulnEqualInputSpec
	for _, ingest := range ve {
		if vulnID, found := vulnInputMap[helpers.VulnInputToVURI(ingest.Vulnerability)]; found {
			vulnIDs = append(vulnIDs, *vulnID)
		} else {
			return fmt.Errorf("failed to find ingested vulnerability ID for vulnMetadata: %s", helpers.VulnInputToVURI(ingest.Vulnerability))
		}
		if equalVulnID, found := vulnInputMap[helpers.VulnInputToVURI(ingest.EqualVulnerability)]; found {
			equalVulnIDs = append(equalVulnIDs, *equalVulnID)
		} else {
			return fmt.Errorf("failed to find ingested equal vulnerability ID for vulnMetadata: %s", helpers.VulnInputToVURI(ingest.EqualVulnerability))
		}
		vulnEqualList = append(vulnEqualList, *ingest.VulnEqual)
	}
	if len(ve) > 0 {
		_, err := model.IngestVulnEquals(ctx, client, vulnIDs, equalVulnIDs, vulnEqualList)
		if err != nil {
			return fmt.Errorf("IngestVulnEquals failed with error: %w", err)
		}
	}
	return nil
}

func ingestHasSourceAts(ctx context.Context, client graphql.Client, hs []assembler.HasSourceAtIngest, packageInputMap map[string]*model.IDorPkgInput, sourceInputMap map[string]*model.IDorSourceInput) error {
	var specificVersionPkgIDs []model.IDorPkgInput
	var allVersionPkgIDs []model.IDorPkgInput
	var specificVersionSrcIDs []model.IDorSourceInput
	var allVersionSrcIDs []model.IDorSourceInput
	var pkgVersionHasSourceAt []model.HasSourceAtInputSpec
	var pkgNameHasSourceAt []model.HasSourceAtInputSpec
	for _, ingest := range hs {
		if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
			if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
				specificVersionPkgIDs = append(specificVersionPkgIDs, *pkgID)
			} else {
				return fmt.Errorf("failed to find ingested Package ID for hasSourceAt: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
			}
			if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Src)]; found {
				specificVersionSrcIDs = append(specificVersionSrcIDs, *srcID)
			} else {
				return fmt.Errorf("failed to find ingested Source ID for hasSourceAt: %s", helpers.ConcatenateSourceInput(ingest.Src))
			}
			pkgVersionHasSourceAt = append(pkgVersionHasSourceAt, *ingest.HasSourceAt)
		} else {
			if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
				allVersionPkgIDs = append(allVersionPkgIDs, *pkgID)
			} else {
				return fmt.Errorf("failed to find ingested Package ID for hasSourceAt: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
			}
			if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Src)]; found {
				allVersionSrcIDs = append(allVersionSrcIDs, *srcID)
			} else {
				return fmt.Errorf("failed to find ingested Source ID for hasSourceAt: %s", helpers.ConcatenateSourceInput(ingest.Src))
			}
			pkgNameHasSourceAt = append(pkgNameHasSourceAt, *ingest.HasSourceAt)
		}
	}
	if len(specificVersionPkgIDs) > 0 {
		_, err := model.IngestHasSourcesAt(ctx, client, specificVersionPkgIDs, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, specificVersionSrcIDs, pkgVersionHasSourceAt)
		if err != nil {
			return fmt.Errorf("IngestHasSourceAts - specific version failed with error: %w", err)
		}
	}
	if len(allVersionPkgIDs) > 0 {
		_, err := model.IngestHasSourcesAt(ctx, client, allVersionPkgIDs, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, allVersionSrcIDs, pkgNameHasSourceAt)
		if err != nil {
			return fmt.Errorf("IngestHasSourceAts - all versions failed with error: %w", err)
		}
	}
	return nil
}

func ingestHasSLSAs(ctx context.Context, client graphql.Client, hs []assembler.HasSlsaIngest, artInputMap map[string]*model.IDorArtifactInput,
	matInputSpec map[string]*model.IDorArtifactInput, builderInputMap map[string]*model.IDorBuilderInput) error {

	var subjectIDs []model.IDorArtifactInput
	var slsaAttestations []model.SLSAInputSpec
	var materialIDs [][]model.IDorArtifactInput
	var builderIDs []model.IDorBuilderInput
	for _, ingest := range hs {
		if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
			subjectIDs = append(subjectIDs, *artID)
		} else {
			return fmt.Errorf("failed to find ingested artifact ID for hasSLSA: %s", helpers.ArtifactKey(ingest.Artifact))
		}
		if buildID, found := builderInputMap[ingest.Builder.Uri]; found {
			builderIDs = append(builderIDs, *buildID)
		} else {
			return fmt.Errorf("failed to find ingested builder ID for hasSLSA: %s", ingest.Builder.Uri)
		}
		var matIDList []model.IDorArtifactInput
		for _, mat := range ingest.Materials {
			if matID, found := matInputSpec[helpers.ArtifactKey(&mat)]; found {
				matIDList = append(matIDList, *matID)
			} else {
				return fmt.Errorf("failed to find ingested material ID for hasSLSA: %s", helpers.ArtifactKey(&mat))
			}
		}
		materialIDs = append(materialIDs, matIDList)
		slsaAttestations = append(slsaAttestations, *ingest.HasSlsa)
	}
	if len(hs) > 0 {
		_, err := model.IngestSLSAForArtifacts(ctx, client, subjectIDs, materialIDs, builderIDs, slsaAttestations)
		if err != nil {
			return fmt.Errorf("SLSAForArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestCertifyScorecards(ctx context.Context, client graphql.Client, cs []assembler.CertifyScorecardIngest, sourceInputMap map[string]*model.IDorSourceInput) error {
	var sourceIDs []model.IDorSourceInput
	var scorecards []model.ScorecardInputSpec
	for _, ingest := range cs {
		if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Source)]; found {
			sourceIDs = append(sourceIDs, *srcID)
		} else {
			return fmt.Errorf("failed to find ingested Source ID for certifyScorecard: %s", helpers.ConcatenateSourceInput(ingest.Source))
		}
		scorecards = append(scorecards, *ingest.Scorecard)
	}
	if len(cs) > 0 {
		_, err := model.IngestCertifyScorecards(ctx, client, sourceIDs, scorecards)
		if err != nil {
			return fmt.Errorf("certifyScorecards failed with error: %w", err)
		}
	}
	return nil
}

func ingestIsDependencies(ctx context.Context, client graphql.Client, deps []assembler.IsDependencyIngest, packageInputMap map[string]*model.IDorPkgInput) ([]string, error) {

	var depToSpecificVersion, depToAllVersions struct {
		pkgs            []model.IDorPkgInput
		depPkgs         []model.IDorPkgInput
		depPkgMatchFlag model.MatchFlags
		dependencies    []model.IsDependencyInputSpec
	}

	depToSpecificVersion.depPkgMatchFlag = model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
	depToAllVersions.depPkgMatchFlag = model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}

	for _, ingest := range deps {
		if ingest.DepPkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
			if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
				depToSpecificVersion.pkgs = append(depToSpecificVersion.pkgs, *pkgID)
			} else {
				return nil, fmt.Errorf("failed to find ingested Package ID for isDependency: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
			}
			if depPkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.DepPkg)]; found {
				depToSpecificVersion.depPkgs = append(depToSpecificVersion.depPkgs, *depPkgID)
			} else {
				return nil, fmt.Errorf("failed to find ingested dependency Package ID for isDependency: %s", helpers.PkgInputSpecToPurl(ingest.DepPkg))
			}
			depToSpecificVersion.dependencies = append(depToSpecificVersion.dependencies, *ingest.IsDependency)
		} else if ingest.DepPkgMatchFlag.Pkg == model.PkgMatchTypeAllVersions {
			if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
				depToAllVersions.pkgs = append(depToAllVersions.pkgs, *pkgID)
			} else {
				return nil, fmt.Errorf("failed to find ingested Package ID for isDependency: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
			}
			if depPkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.DepPkg)]; found {
				depToAllVersions.depPkgs = append(depToAllVersions.depPkgs, *depPkgID)
			} else {
				return nil, fmt.Errorf("failed to find ingested dependency Package ID for isDependency: %s", helpers.PkgInputSpecToPurl(ingest.DepPkg))
			}
			depToAllVersions.dependencies = append(depToAllVersions.dependencies, *ingest.IsDependency)
		}
	}

	var isDependenciesIDs []string
	if len(depToSpecificVersion.pkgs) > 0 {
		isDependencies, err := model.IngestIsDependencies(ctx, client, depToSpecificVersion.pkgs, depToSpecificVersion.depPkgs, depToSpecificVersion.depPkgMatchFlag, depToSpecificVersion.dependencies)
		if err != nil {
			return nil, fmt.Errorf("isDependencies failed with error: %w", err)
		}
		isDependenciesIDs = append(isDependenciesIDs, isDependencies.IngestDependencies...)
	}
	if len(depToAllVersions.pkgs) > 0 {
		isDependencies, err := model.IngestIsDependencies(ctx, client, depToAllVersions.pkgs, depToAllVersions.depPkgs, depToAllVersions.depPkgMatchFlag, depToAllVersions.dependencies)
		if err != nil {
			return nil, fmt.Errorf("isDependencies failed with error: %w", err)
		}
		isDependenciesIDs = append(isDependenciesIDs, isDependencies.IngestDependencies...)
	}

	return isDependenciesIDs, nil
}

func ingestPkgEquals(ctx context.Context, client graphql.Client, pe []assembler.PkgEqualIngest, packageInputMap map[string]*model.IDorPkgInput) error {
	var pkgIDs []model.IDorPkgInput
	var equalPkgIDs []model.IDorPkgInput
	var pkgEquals []model.PkgEqualInputSpec
	for _, ingest := range pe {
		if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
			pkgIDs = append(pkgIDs, *pkgID)
		} else {
			return fmt.Errorf("failed to find ingested Package ID for pkgEqual: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
		}
		if equalPkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.EqualPkg)]; found {
			equalPkgIDs = append(equalPkgIDs, *equalPkgID)
		} else {
			return fmt.Errorf("failed to find ingested equal Package ID for pkgEqual: %s", helpers.PkgInputSpecToPurl(ingest.EqualPkg))
		}
		pkgEquals = append(pkgEquals, *ingest.PkgEqual)
	}
	if len(pe) > 0 {
		_, err := model.IngestPkgEquals(ctx, client, pkgIDs, equalPkgIDs, pkgEquals)
		if err != nil {
			return fmt.Errorf("PkgEquals failed with error: %w", err)
		}
	}
	return nil
}

func ingestHashEquals(ctx context.Context, client graphql.Client, he []assembler.HashEqualIngest, artInputMap map[string]*model.IDorArtifactInput) error {
	var artIDs []model.IDorArtifactInput
	var equalArtIDs []model.IDorArtifactInput
	var hashEquals []model.HashEqualInputSpec
	for _, ingest := range he {
		if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
			artIDs = append(artIDs, *artID)
		} else {
			return fmt.Errorf("failed to find ingested artifact ID for hashEqual: %s", helpers.ArtifactKey(ingest.Artifact))
		}
		if equalArtID, found := artInputMap[helpers.ArtifactKey(ingest.EqualArtifact)]; found {
			equalArtIDs = append(equalArtIDs, *equalArtID)
		} else {
			return fmt.Errorf("failed to find ingested artifact ID for hashEqual: %s", helpers.ArtifactKey(ingest.EqualArtifact))
		}
		hashEquals = append(hashEquals, *ingest.HashEqual)
	}
	if len(he) > 0 {
		_, err := model.IngestHashEquals(ctx, client, artIDs, equalArtIDs, hashEquals)
		if err != nil {
			return fmt.Errorf("HashEquals failed with error: %w", err)
		}
	}
	return nil
}

func ingestHasSBOMs(ctx context.Context, client graphql.Client, hs []assembler.HasSBOMIngest, includes model.HasSBOMIncludesInputSpec, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput) error {

	var pkgIDs []model.IDorPkgInput
	var artIDs []model.IDorArtifactInput
	var pkgSBOMs []model.HasSBOMInputSpec
	var artSBOMs []model.HasSBOMInputSpec
	var pkgIncludes []model.HasSBOMIncludesInputSpec
	var artIncludes []model.HasSBOMIncludesInputSpec
	for _, ingest := range hs {
		if ingest.Pkg != nil && ingest.Artifact != nil {
			return fmt.Errorf("unable to create hasSBOM with both artifact and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Artifact == nil {
			return fmt.Errorf("unable to create hasSBOM without either artifact and Pkg subject specified")
		}

		if ingest.Pkg != nil {
			if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
				pkgIDs = append(pkgIDs, *pkgID)
			} else {
				return fmt.Errorf("failed to find ingested Package ID for hasSBOM: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
			}
			pkgSBOMs = append(pkgSBOMs, *ingest.HasSBOM)
			pkgIncludes = append(pkgIncludes, includes)
		} else {
			if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
				artIDs = append(artIDs, *artID)
			} else {
				return fmt.Errorf("failed to find ingested artifact ID for hasSBOM: %s", helpers.ArtifactKey(ingest.Artifact))
			}
			artSBOMs = append(artSBOMs, *ingest.HasSBOM)
			artIncludes = append(artIncludes, includes)
		}
	}
	if len(artIDs) > 0 {
		_, err := model.IngestHasSBOMArtifacts(ctx, client, artIDs, artSBOMs, artIncludes)
		if err != nil {
			return fmt.Errorf("hasSBOMArtifacts failed with error: %w", err)
		}
	}
	if len(pkgIDs) > 0 {
		_, err := model.IngestHasSBOMPkgs(ctx, client, pkgIDs, pkgSBOMs, pkgIncludes)
		if err != nil {
			return fmt.Errorf("hasSBOMPkgs failed with error: %w", err)
		}
	}
	return nil
}

func ingestPointOfContacts(ctx context.Context, client graphql.Client, poc []assembler.PointOfContactIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) error {

	var pkgSpecificVersionIDs []model.IDorPkgInput
	var pkgAllVersionsIDs []model.IDorPkgInput
	var sourceIDs []model.IDorSourceInput
	var artIDs []model.IDorArtifactInput
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
				if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
					pkgSpecificVersionIDs = append(pkgSpecificVersionIDs, *pkgID)
				} else {
					return fmt.Errorf("failed to find ingested Package ID for point of contact: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
				}
				pkgVersionPOC = append(pkgVersionPOC, *ingest.PointOfContact)
			} else {
				if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
					pkgAllVersionsIDs = append(pkgAllVersionsIDs, *pkgID)
				} else {
					return fmt.Errorf("failed to find ingested Package ID for point of contact: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
				}
				pkgNamePOC = append(pkgNamePOC, *ingest.PointOfContact)
			}
		} else if ingest.Src != nil {
			if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Src)]; found {
				sourceIDs = append(sourceIDs, *srcID)
			} else {
				return fmt.Errorf("failed to find ingested Source ID for point of contact: %s", helpers.ConcatenateSourceInput(ingest.Src))
			}
			srcPOC = append(srcPOC, *ingest.PointOfContact)
		} else {
			if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
				artIDs = append(artIDs, *artID)
			} else {
				return fmt.Errorf("failed to find ingested artifact ID for point of contact: %s", helpers.ArtifactKey(ingest.Artifact))
			}
			artPOC = append(artPOC, *ingest.PointOfContact)
		}
	}
	if len(pkgSpecificVersionIDs) > 0 {
		_, err := model.IngestPointOfContactPkgs(ctx, client, pkgSpecificVersionIDs, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionPOC)
		if err != nil {
			return fmt.Errorf("HasMetadataPkgs - specific version failed with error: %w", err)
		}
	}
	if len(pkgAllVersionsIDs) > 0 {
		_, err := model.IngestPointOfContactPkgs(ctx, client, pkgAllVersionsIDs, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNamePOC)
		if err != nil {
			return fmt.Errorf("HasMetadataPkgs - all versions failed with error: %w", err)
		}
	}
	if len(sourceIDs) > 0 {
		_, err := model.IngestPointOfContactSrcs(ctx, client, sourceIDs, srcPOC)
		if err != nil {
			return fmt.Errorf("HasMetadataSrcs failed with error: %w", err)
		}
	}
	if len(artIDs) > 0 {
		_, err := model.IngestPointOfContactArtifacts(ctx, client, artIDs, artPOC)
		if err != nil {
			return fmt.Errorf("HasMetadataArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestBulkHasMetadata(ctx context.Context, client graphql.Client, hm []assembler.HasMetadataIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) error {

	var pkgSpecificVersionIDs []model.IDorPkgInput
	var pkgAllVersionsIDs []model.IDorPkgInput
	var sourceIDs []model.IDorSourceInput
	var artIDs []model.IDorArtifactInput
	var pkgVersionHasMetadata []model.HasMetadataInputSpec
	var pkgNameHasMetadata []model.HasMetadataInputSpec
	var srcHasMetadata []model.HasMetadataInputSpec
	var artHasMetadata []model.HasMetadataInputSpec
	for _, ingest := range hm {
		if err := validatePackageSourceOrArtifactInput(ingest.Pkg, ingest.Src, ingest.Artifact, "ingestBulkHasMetadata"); err != nil {
			return fmt.Errorf("input validation failed for ingestBulkHasMetadata: %w", err)
		}
		if ingest.Pkg != nil {
			if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
				if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
					pkgSpecificVersionIDs = append(pkgSpecificVersionIDs, *pkgID)
				} else {
					return fmt.Errorf("failed to find ingested Package ID for hasMetadata: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
				}
				pkgVersionHasMetadata = append(pkgVersionHasMetadata, *ingest.HasMetadata)
			} else {
				if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
					pkgAllVersionsIDs = append(pkgAllVersionsIDs, *pkgID)
				} else {
					return fmt.Errorf("failed to find ingested Package ID for hasMetadata: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
				}
				pkgNameHasMetadata = append(pkgNameHasMetadata, *ingest.HasMetadata)
			}
		} else if ingest.Src != nil {
			if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Src)]; found {
				sourceIDs = append(sourceIDs, *srcID)
			} else {
				return fmt.Errorf("failed to find ingested Source ID for point of contact: %s", helpers.ConcatenateSourceInput(ingest.Src))
			}
			srcHasMetadata = append(srcHasMetadata, *ingest.HasMetadata)
		} else {
			if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
				artIDs = append(artIDs, *artID)
			} else {
				return fmt.Errorf("failed to find ingested artifact ID for point of contact: %s", helpers.ArtifactKey(ingest.Artifact))
			}
			artHasMetadata = append(artHasMetadata, *ingest.HasMetadata)
		}
	}
	if len(pkgSpecificVersionIDs) > 0 {
		_, err := model.IngestHasMetadataPkgs(ctx, client, pkgSpecificVersionIDs, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionHasMetadata)
		if err != nil {
			return fmt.Errorf("HasMetadataPkgs - specific version failed with error: %w", err)
		}
	}
	if len(pkgAllVersionsIDs) > 0 {
		_, err := model.IngestHasMetadataPkgs(ctx, client, pkgAllVersionsIDs, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNameHasMetadata)
		if err != nil {
			return fmt.Errorf("HasMetadataPkgs - all versions failed with error: %w", err)
		}
	}
	if len(sourceIDs) > 0 {
		_, err := model.IngestHasMetadataSrcs(ctx, client, sourceIDs, srcHasMetadata)
		if err != nil {
			return fmt.Errorf("HasMetadataSrcs failed with error: %w", err)
		}
	}
	if len(artIDs) > 0 {
		_, err := model.IngestHasMetadataArtifacts(ctx, client, artIDs, artHasMetadata)
		if err != nil {
			return fmt.Errorf("HasMetadataArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestCertifyGoods(ctx context.Context, client graphql.Client, cg []assembler.CertifyGoodIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) error {

	var pkgSpecificVersionIDs []model.IDorPkgInput
	var pkgAllVersionsIDs []model.IDorPkgInput
	var sourceIDs []model.IDorSourceInput
	var artIDs []model.IDorArtifactInput
	var pkgVersionCertifyGoods []model.CertifyGoodInputSpec
	var pkgNameCertifyGoods []model.CertifyGoodInputSpec
	var srcCertifyGoods []model.CertifyGoodInputSpec
	var artCertifyGoods []model.CertifyGoodInputSpec
	for _, ingest := range cg {
		if err := validatePackageSourceOrArtifactInput(ingest.Pkg, ingest.Src, ingest.Artifact, "ingestCertifyGoods"); err != nil {
			return fmt.Errorf("input validation failed for ingestCertifyGoods: %w", err)
		}
		if ingest.Pkg != nil {
			if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
				if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
					pkgSpecificVersionIDs = append(pkgSpecificVersionIDs, *pkgID)
				} else {
					return fmt.Errorf("failed to find ingested Package ID for certifyGood: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
				}
				pkgVersionCertifyGoods = append(pkgVersionCertifyGoods, *ingest.CertifyGood)
			} else {
				if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
					pkgAllVersionsIDs = append(pkgAllVersionsIDs, *pkgID)
				} else {
					return fmt.Errorf("failed to find ingested Package ID for certifyGood: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
				}
				pkgNameCertifyGoods = append(pkgNameCertifyGoods, *ingest.CertifyGood)
			}
		} else if ingest.Src != nil {
			if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Src)]; found {
				sourceIDs = append(sourceIDs, *srcID)
			} else {
				return fmt.Errorf("failed to find ingested Source ID for certifyGood: %s", helpers.ConcatenateSourceInput(ingest.Src))
			}
			srcCertifyGoods = append(srcCertifyGoods, *ingest.CertifyGood)
		} else {
			if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
				artIDs = append(artIDs, *artID)
			} else {
				return fmt.Errorf("failed to find ingested artifact ID for certifyGood: %s", helpers.ArtifactKey(ingest.Artifact))
			}
			artCertifyGoods = append(artCertifyGoods, *ingest.CertifyGood)
		}
	}
	if len(pkgSpecificVersionIDs) > 0 {
		_, err := model.IngestCertifyGoodPkgs(ctx, client, pkgSpecificVersionIDs, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionCertifyGoods)
		if err != nil {
			return fmt.Errorf("CertifyGoodPkgs - specific version failed with error: %w", err)
		}
	}
	if len(pkgAllVersionsIDs) > 0 {
		_, err := model.IngestCertifyGoodPkgs(ctx, client, pkgAllVersionsIDs, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNameCertifyGoods)
		if err != nil {
			return fmt.Errorf("CertifyGoodPkgs - all versions failed with error: %w", err)
		}
	}
	if len(sourceIDs) > 0 {
		_, err := model.IngestCertifyGoodSrcs(ctx, client, sourceIDs, srcCertifyGoods)
		if err != nil {
			return fmt.Errorf("CertifyGoodSrcs failed with error: %w", err)
		}
	}
	if len(artIDs) > 0 {
		_, err := model.IngestCertifyGoodArtifacts(ctx, client, artIDs, artCertifyGoods)
		if err != nil {
			return fmt.Errorf("CertifyGoodArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestCertifyBads(ctx context.Context, client graphql.Client, cb []assembler.CertifyBadIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) error {

	var pkgSpecificVersionIDs []model.IDorPkgInput
	var pkgAllVersionsIDs []model.IDorPkgInput
	var sourceIDs []model.IDorSourceInput
	var artIDs []model.IDorArtifactInput
	var pkgVersionCertifyBads []model.CertifyBadInputSpec
	var pkgNameCertifyBads []model.CertifyBadInputSpec
	var srcCertifyBads []model.CertifyBadInputSpec
	var artCertifyBads []model.CertifyBadInputSpec
	for _, ingest := range cb {
		if err := validatePackageSourceOrArtifactInput(ingest.Pkg, ingest.Src, ingest.Artifact, "ingestCertifyBads"); err != nil {
			return fmt.Errorf("input validation failed for ingestCertifyBads: %w", err)
		}
		if ingest.Pkg != nil {
			if ingest.PkgMatchFlag.Pkg == model.PkgMatchTypeSpecificVersion {
				if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
					pkgSpecificVersionIDs = append(pkgSpecificVersionIDs, *pkgID)
				} else {
					return fmt.Errorf("failed to find ingested Package ID for certifyBad: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
				}
				pkgVersionCertifyBads = append(pkgVersionCertifyBads, *ingest.CertifyBad)
			} else {
				if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
					pkgAllVersionsIDs = append(pkgAllVersionsIDs, *pkgID)
				} else {
					return fmt.Errorf("failed to find ingested Package ID for certifyBad: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
				}
				pkgNameCertifyBads = append(pkgNameCertifyBads, *ingest.CertifyBad)
			}
		} else if ingest.Src != nil {
			if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Src)]; found {
				sourceIDs = append(sourceIDs, *srcID)
			} else {
				return fmt.Errorf("failed to find ingested Source ID for certifyBad: %s", helpers.ConcatenateSourceInput(ingest.Src))
			}
			srcCertifyBads = append(srcCertifyBads, *ingest.CertifyBad)
		} else {
			if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
				artIDs = append(artIDs, *artID)
			} else {
				return fmt.Errorf("failed to find ingested artifact ID for certifyBad: %s", helpers.ArtifactKey(ingest.Artifact))
			}
			artCertifyBads = append(artCertifyBads, *ingest.CertifyBad)
		}
	}
	if len(pkgSpecificVersionIDs) > 0 {
		_, err := model.IngestCertifyBadPkgs(ctx, client, pkgSpecificVersionIDs, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}, pkgVersionCertifyBads)
		if err != nil {
			return fmt.Errorf("certifyBadPkgs - specific version failed with error: %w", err)
		}
	}
	if len(pkgAllVersionsIDs) > 0 {
		_, err := model.IngestCertifyBadPkgs(ctx, client, pkgAllVersionsIDs, model.MatchFlags{Pkg: model.PkgMatchTypeAllVersions}, pkgNameCertifyBads)
		if err != nil {
			return fmt.Errorf("certifyBadPkgs - all versions failed with error: %w", err)
		}
	}
	if len(sourceIDs) > 0 {
		_, err := model.IngestCertifyBadSrcs(ctx, client, sourceIDs, srcCertifyBads)
		if err != nil {
			return fmt.Errorf("CertifyBadSrcs failed with error: %w", err)
		}
	}
	if len(artIDs) > 0 {
		_, err := model.IngestCertifyBadArtifacts(ctx, client, artIDs, artCertifyBads)
		if err != nil {
			return fmt.Errorf("CertifyBadArtifacts failed with error: %w", err)
		}
	}
	return nil
}

func ingestIsOccurrences(ctx context.Context, client graphql.Client, io []assembler.IsOccurrenceIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) ([]string, error) {

	var pkgIDs []model.IDorPkgInput
	var sourceIDs []model.IDorSourceInput
	var pkgArtIDs []model.IDorArtifactInput
	var pkgOccurrences []model.IsOccurrenceInputSpec
	var srcArtIDs []model.IDorArtifactInput
	var srcOccurrences []model.IsOccurrenceInputSpec
	for _, ingest := range io {

		if ingest.Pkg != nil && ingest.Src != nil {
			return nil, fmt.Errorf("unable to create IsOccurrence with both Src and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Src == nil {
			return nil, fmt.Errorf("unable to create IsOccurrence without either Src and Pkg subject specified")
		}

		if ingest.Pkg != nil {
			if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
				pkgIDs = append(pkgIDs, *pkgID)
			} else {
				return nil, fmt.Errorf("failed to find ingested Package ID for isOccurrence: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
			}
			if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
				pkgArtIDs = append(pkgArtIDs, *artID)
			} else {
				return nil, fmt.Errorf("failed to find ingested artifact ID for isOccurrence: %s", helpers.ArtifactKey(ingest.Artifact))
			}
			pkgOccurrences = append(pkgOccurrences, *ingest.IsOccurrence)
		} else {
			if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Src)]; found {
				sourceIDs = append(sourceIDs, *srcID)
			} else {
				return nil, fmt.Errorf("failed to find ingested Source ID for isOccurrence: %s", helpers.ConcatenateSourceInput(ingest.Src))
			}
			if artID, found := artInputMap[helpers.ArtifactKey(ingest.Artifact)]; found {
				srcArtIDs = append(srcArtIDs, *artID)
			} else {
				return nil, fmt.Errorf("failed to find ingested artifact ID for isOccurrence: %s", helpers.ArtifactKey(ingest.Artifact))
			}
			srcOccurrences = append(srcOccurrences, *ingest.IsOccurrence)
		}
	}
	var isOccurrencesIDs []string
	if len(sourceIDs) > 0 {
		isOccurrences, err := model.IngestIsOccurrencesSrc(ctx, client, sourceIDs, srcArtIDs, srcOccurrences)
		if err != nil {
			return nil, fmt.Errorf("isOccurrencesSrc failed with error: %w", err)
		}
		isOccurrencesIDs = append(isOccurrencesIDs, isOccurrences.IngestOccurrences...)
	}
	if len(pkgIDs) > 0 {
		isOccurrences, err := model.IngestIsOccurrencesPkg(ctx, client, pkgIDs, pkgArtIDs, pkgOccurrences)
		if err != nil {
			return nil, fmt.Errorf("isOccurrencesPkg failed with error: %w", err)
		}
		isOccurrencesIDs = append(isOccurrencesIDs, isOccurrences.IngestOccurrences...)
	}
	return isOccurrencesIDs, nil
}

func ingestCertifyLegals(ctx context.Context, client graphql.Client, v []assembler.CertifyLegalIngest, packageInputMap map[string]*model.IDorPkgInput,
	sourceInputMap map[string]*model.IDorSourceInput, licenseInputMap map[string]*model.IDorLicenseInput) error {

	var pkgIDs []model.IDorPkgInput
	var sourceIDs []model.IDorSourceInput
	var pkgDecIDs [][]model.IDorLicenseInput
	var pkgDisIDs [][]model.IDorLicenseInput
	var pkgCL []model.CertifyLegalInputSpec
	var srcDecIDs [][]model.IDorLicenseInput
	var srcDisIDs [][]model.IDorLicenseInput
	var srcCL []model.CertifyLegalInputSpec
	for _, ingest := range v {

		if ingest.Pkg != nil && ingest.Src != nil {
			return fmt.Errorf("unable to create CertifyLegal with both Src and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Src == nil {
			return fmt.Errorf("unable to create CertifyLegal without either Src and Pkg subject specified")
		}

		if ingest.Pkg != nil {
			if pkgID, found := packageInputMap[helpers.PkgInputSpecToPurl(ingest.Pkg)]; found {
				pkgIDs = append(pkgIDs, *pkgID)
			} else {
				return fmt.Errorf("failed to find ingested Package ID for certifyLegal: %s", helpers.PkgInputSpecToPurl(ingest.Pkg))
			}

			// Declared Licenses
			var pkgDecList []model.IDorLicenseInput
			for _, dec := range ingest.Declared {
				if licID, found := licenseInputMap[helpers.LicenseKey(&dec)]; found {
					pkgDecList = append(pkgDecList, *licID)
				} else {
					return fmt.Errorf("failed to find ingested license ID for certifyLegal: %s", helpers.LicenseKey(&dec))
				}
			}
			pkgDecIDs = append(pkgDecIDs, pkgDecList)

			// Discovered Licenses
			var pkgDisList []model.IDorLicenseInput
			for _, dis := range ingest.Discovered {
				if licID, found := licenseInputMap[helpers.LicenseKey(&dis)]; found {
					pkgDisList = append(pkgDisList, *licID)
				} else {
					return fmt.Errorf("failed to find ingested license ID for certifyLegal: %s", helpers.LicenseKey(&dis))
				}
			}
			pkgDisIDs = append(pkgDisIDs, pkgDisList)
			pkgCL = append(pkgCL, *ingest.CertifyLegal)
		} else {
			if srcID, found := sourceInputMap[helpers.ConcatenateSourceInput(ingest.Src)]; found {
				sourceIDs = append(sourceIDs, *srcID)
			} else {
				return fmt.Errorf("failed to find ingested Source ID for certifyLegal: %s", helpers.ConcatenateSourceInput(ingest.Src))
			}

			// Declared Licenses
			var srcDecList []model.IDorLicenseInput
			for _, dec := range ingest.Declared {
				if licID, found := licenseInputMap[helpers.LicenseKey(&dec)]; found {
					srcDecList = append(srcDecList, *licID)
				} else {
					return fmt.Errorf("failed to find ingested license ID for certifyLegal: %s", helpers.LicenseKey(&dec))
				}
			}
			srcDecIDs = append(srcDecIDs, srcDecList)

			// Discovered Licenses
			var srcDisList []model.IDorLicenseInput
			for _, dis := range ingest.Discovered {
				if licID, found := licenseInputMap[helpers.LicenseKey(&dis)]; found {
					srcDisList = append(srcDisList, *licID)
				} else {
					return fmt.Errorf("failed to find ingested license ID for certifyLegal: %s", helpers.LicenseKey(&dis))
				}
			}
			srcDisIDs = append(srcDisIDs, srcDisList)
			srcCL = append(srcCL, *ingest.CertifyLegal)
		}
	}
	if len(sourceIDs) > 0 {
		_, err := model.IngestCertifyLegalSrcs(ctx, client, sourceIDs, srcDecIDs, srcDisIDs, srcCL)
		if err != nil {
			return fmt.Errorf("certifyLegalSrc failed with error: %w", err)
		}
	}
	if len(pkgIDs) > 0 {
		_, err := model.IngestCertifyLegalPkgs(ctx, client, pkgIDs, pkgDecIDs, pkgDisIDs, pkgCL)
		if err != nil {
			return fmt.Errorf("certifyLegalPkg failed with error: %w", err)
		}
	}
	return nil
}
