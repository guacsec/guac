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

func GetAssembler(ctx context.Context, gqlclient graphql.Client) func([]assembler.AssemblerInput) error {
	logger := logging.FromContext(ctx)
	return func(preds []assembler.IngestPredicates) error {
		for _, p := range preds {
			packageIDs := make([]string, 0)
			collectedIDorPkgInputs := make(map[string]*model.IDorPkgInput)
			packages := p.GetPackages(ctx)
			logger.Infof("assembling Package: %v", len(packages))
			for _, p := range packages {
				if id, err := ingestPackage(ctx, gqlclient, p); err != nil {
					return fmt.Errorf("failed package ingest with error: %w", err)
				} else {
					collectedIDorPkgInputs[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](p.PackageInput, helpers.PkgClientKey).VersionId] = id
					packageIDs = append(packageIDs, *id.PackageVersionID)
				}
			}

			collectedIDorSrcInputs := make(map[string]*model.IDorSourceInput)
			sources := p.GetSources(ctx)
			logger.Infof("assembling Source: %v", len(sources))
			for _, s := range sources {
				if id, err := ingestSource(ctx, gqlclient, s); err != nil {
					return fmt.Errorf("failed source ingest with error: %w", err)
				} else {
					collectedIDorSrcInputs[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](s.SourceInput, helpers.SrcClientKey).NameId] = id
				}
			}

			artifactIDs := make([]string, 0)
			collectedIDorArtInputs := make(map[string]*model.IDorArtifactInput)
			artifacts := p.GetArtifacts(ctx)
			logger.Infof("assembling Artifact: %v", len(artifacts))
			for _, a := range artifacts {
				if id, err := ingestArtifact(ctx, gqlclient, a); err != nil {
					return fmt.Errorf("failed artifact ingest with error: %w", err)
				} else {
					collectedIDorArtInputs[helpers.GetKey[*model.ArtifactInputSpec, string](a.ArtifactInput, helpers.ArtifactClientKey)] = id
					artifactIDs = append(artifactIDs, *id.ArtifactID)
				}
			}

			materials := p.GetMaterials(ctx)
			logger.Infof("assembling Materials (Artifact): %v", len(materials))
			collectedIDorMatInputs, err := ingestArtifacts(ctx, gqlclient, materials)
			if err != nil {
				return fmt.Errorf("failed materials (artifacts) ingest with error: %w", err)
			}

			collectedIDorBuilderInputs := make(map[string]*model.IDorBuilderInput)
			builders := p.GetBuilders(ctx)
			logger.Infof("assembling Builder: %v", len(builders))
			for _, v := range builders {
				if id, err := ingestBuilder(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("failed builder ingest with error: %w", err)
				} else {
					collectedIDorBuilderInputs[v.BuilderInput.Uri] = id
				}
			}

			collectedIDorVulnInputs := make(map[string]*model.IDorVulnerabilityInput)
			vulns := p.GetVulnerabilities(ctx)
			logger.Infof("assembling Vulnerability: %v", len(vulns))
			for _, v := range vulns {
				if id, err := ingestVulnerability(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("failed vulnerability ingest with error: %w", err)
				} else {
					collectedIDorVulnInputs[helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](v.VulnerabilityInput, helpers.VulnClientKey).VulnerabilityID] = id
				}
			}

			collectedIDorLicenseInputs := make(map[string]*model.IDorLicenseInput)
			licenses := p.GetLicenses(ctx)
			logger.Infof("assembling License: %v", len(licenses))
			for _, l := range licenses {
				if id, err := ingestLicense(ctx, gqlclient, l); err != nil {
					return fmt.Errorf("failed license ingest with error: %w", err)
				} else {
					collectedIDorLicenseInputs[helpers.GetKey[*model.LicenseInputSpec, string](l.LicenseInput, helpers.LicenseClientKey)] = id
				}
			}

			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			for _, v := range p.CertifyScorecard {
				if err := ingestCertifyScorecard(ctx, gqlclient, v, collectedIDorSrcInputs); err != nil {
					return err
				}
			}

			isDependenciesIDs := make([]string, 0)
			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			for _, v := range p.IsDependency {
				if id, err := ingestIsDependency(ctx, gqlclient, v, collectedIDorPkgInputs); err != nil {
					return err
				} else {
					isDependenciesIDs = append(isDependenciesIDs, *id)
				}
			}

			isOccurrencesIDs := make([]string, 0)
			logger.Infof("assembling IsOccurrence: %v", len(p.IsOccurrence))
			for _, v := range p.IsOccurrence {
				if id, err := ingestIsOccurrence(ctx, gqlclient, v, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
					return err
				} else {
					isOccurrencesIDs = append(isOccurrencesIDs, *id)
				}
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			for _, v := range p.HasSlsa {
				if err := ingestHasSlsa(ctx, gqlclient, v, collectedIDorArtInputs, collectedIDorMatInputs, collectedIDorBuilderInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			for _, cv := range p.CertifyVuln {
				if err := ingestCertifyVuln(ctx, gqlclient, cv, collectedIDorPkgInputs, collectedIDorVulnInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling VulnMetadata: %v", len(p.VulnMetadata))
			for _, vm := range p.VulnMetadata {
				if err := ingestVulnMetadata(ctx, gqlclient, vm, collectedIDorVulnInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling VulnEqual: %v", len(p.VulnEqual))
			for _, ve := range p.VulnEqual {
				if err := ingestVulnEqual(ctx, gqlclient, ve, collectedIDorVulnInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			for _, hsa := range p.HasSourceAt {
				if err := hasSourceAt(ctx, gqlclient, hsa, collectedIDorPkgInputs, collectedIDorSrcInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			for _, bad := range p.CertifyBad {
				if err := ingestCertifyBad(ctx, gqlclient, bad, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			for _, good := range p.CertifyGood {
				if err := ingestCertifyGood(ctx, gqlclient, good, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling PointOfContact: %v", len(p.PointOfContact))
			for _, poc := range p.PointOfContact {
				if err := ingestPointOfContact(ctx, gqlclient, poc, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasMetadata: %v", len(p.HasMetadata))
			for _, hm := range p.HasMetadata {
				if err := ingestHasMetadata(ctx, gqlclient, hm, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorSrcInputs); err != nil {
					return err
				}
			}

			includes := model.HasSBOMIncludesInputSpec{
				Packages:     packageIDs,
				Artifacts:    artifactIDs,
				Dependencies: isDependenciesIDs,
				Occurrences:  isOccurrencesIDs,
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			for _, hb := range p.HasSBOM {
				hb.Includes = &includes
				if err := ingestHasSBOM(ctx, gqlclient, hb, collectedIDorPkgInputs, collectedIDorArtInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling VEX : %v", len(p.Vex))
			for _, v := range p.Vex {
				if err := ingestVex(ctx, gqlclient, v, collectedIDorPkgInputs, collectedIDorArtInputs, collectedIDorVulnInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling HashEqual : %v", len(p.HashEqual))
			for _, equal := range p.HashEqual {
				if err := ingestHashEqual(ctx, gqlclient, equal, collectedIDorArtInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling PkgEqual : %v", len(p.PkgEqual))
			for _, equal := range p.PkgEqual {
				if err := ingestPkgEqual(ctx, gqlclient, equal, collectedIDorPkgInputs); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyLegal : %v", len(p.CertifyLegal))
			for _, cl := range p.CertifyLegal {
				if err := ingestCertifyLegal(ctx, gqlclient, cl, collectedIDorPkgInputs, collectedIDorSrcInputs, collectedIDorLicenseInputs); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

// ingestPackages takes in IDorPkgInput which contains the pkgInputSpec and outputs IDorPkgInput that contains the pkgIDs to be used for verb ingestion
func ingestPackage(ctx context.Context, client graphql.Client, p *model.IDorPkgInput) (*model.IDorPkgInput, error) {
	if result, err := model.IngestPackage(ctx, client, *p); err != nil {
		return nil, fmt.Errorf("IngestPackage failed with error: %w", err)
	} else {
		return &model.IDorPkgInput{
			PackageInput:       p.PackageInput,
			PackageTypeID:      &result.IngestPackage.PackageTypeID,
			PackageNamespaceID: &result.IngestPackage.PackageNamespaceID,
			PackageNameID:      &result.IngestPackage.PackageNameID,
			PackageVersionID:   &result.IngestPackage.PackageVersionID,
		}, nil
	}
}

func ingestSource(ctx context.Context, client graphql.Client, s *model.IDorSourceInput) (*model.IDorSourceInput, error) {
	if result, err := model.IngestSource(ctx, client, *s); err != nil {
		return nil, fmt.Errorf("IngestSource failed with error: %w", err)
	} else {
		return &model.IDorSourceInput{
			SourceInput:       s.SourceInput,
			SourceTypeID:      &result.IngestSource.SourceTypeID,
			SourceNamespaceID: &result.IngestSource.SourceNamespaceID,
			SourceNameID:      &result.IngestSource.SourceNameID,
		}, nil
	}
}

func ingestArtifact(ctx context.Context, client graphql.Client, a *model.IDorArtifactInput) (*model.IDorArtifactInput, error) {
	if result, err := model.IngestArtifact(ctx, client, *a); err != nil {
		return nil, fmt.Errorf("IngestArtifact failed with error: %w", err)
	} else {
		return &model.IDorArtifactInput{ArtifactID: &result.IngestArtifact, ArtifactInput: a.ArtifactInput}, err
	}
}

func ingestBuilder(ctx context.Context, client graphql.Client, b *model.IDorBuilderInput) (*model.IDorBuilderInput, error) {
	if result, err := model.IngestBuilder(ctx, client, *b); err != nil {
		return nil, fmt.Errorf("IngestBuilder failed with error: %w", err)
	} else {
		return &model.IDorBuilderInput{BuilderID: &result.IngestBuilder, BuilderInput: b.BuilderInput}, err
	}
}

func ingestVulnerability(ctx context.Context, client graphql.Client, v *model.IDorVulnerabilityInput) (*model.IDorVulnerabilityInput, error) {
	if result, err := model.IngestVulnerability(ctx, client, *v); err != nil {
		return nil, fmt.Errorf("IngestVulnerability failed with error: %w", err)
	} else {
		return &model.IDorVulnerabilityInput{
			VulnerabilityInput:  v.VulnerabilityInput,
			VulnerabilityTypeID: &result.IngestVulnerability.VulnerabilityTypeID,
			VulnerabilityNodeID: &result.IngestVulnerability.VulnerabilityNodeID,
		}, err
	}
}

func ingestLicense(ctx context.Context, client graphql.Client, l *model.IDorLicenseInput) (*model.IDorLicenseInput, error) {
	if result, err := model.IngestLicense(ctx, client, *l); err != nil {
		return nil, fmt.Errorf("IngestLicense failed with error: %w", err)
	} else {
		return &model.IDorLicenseInput{
			LicenseInput: l.LicenseInput,
			LicenseID:    &result.IngestLicense,
		}, err
	}
}

func ingestCertifyScorecard(ctx context.Context, client graphql.Client, cs assembler.CertifyScorecardIngest, sourceInputMap map[string]*model.IDorSourceInput) error {
	srcID, found := sourceInputMap[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](cs.Source, helpers.SrcClientKey).NameId]
	if !found {
		return fmt.Errorf("failed to find ingested Source ID for scorecard: %s", helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](cs.Source, helpers.SrcClientKey).NameId)
	}

	_, err := model.IngestCertifyScorecard(ctx, client, *srcID, *cs.Scorecard)
	return err
}

func ingestIsDependency(ctx context.Context, client graphql.Client, d assembler.IsDependencyIngest, packageInputMap map[string]*model.IDorPkgInput) (*string, error) {
	pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](d.Pkg, helpers.PkgClientKey).VersionId]
	if !found {
		return nil, fmt.Errorf("failed to find ingested Source ID for isDependency: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](d.Pkg, helpers.PkgClientKey).VersionId)
	}

	depPkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](d.DepPkg, helpers.PkgClientKey).VersionId]
	if !found {
		return nil, fmt.Errorf("failed to find ingested Source ID for isDependency: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](d.DepPkg, helpers.PkgClientKey).VersionId)
	}

	if response, err := model.IngestIsDependency(ctx, client, *pkgID, *depPkgID, d.DepPkgMatchFlag, *d.IsDependency); err != nil {
		return nil, err
	} else {
		return &response.IngestDependency, nil
	}
}

func ingestIsOccurrence(ctx context.Context, client graphql.Client, o assembler.IsOccurrenceIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) (*string, error) {

	if o.Pkg != nil && o.Src != nil {
		return nil, fmt.Errorf("unable to create IsOccurrence with both Src and Pkg subject specified")
	}
	if o.Pkg == nil && o.Src == nil {
		return nil, fmt.Errorf("unable to create IsOccurrence without either Src and Pkg subject specified")
	}

	if o.Src != nil {
		srcID, found := sourceInputMap[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](o.Src, helpers.SrcClientKey).NameId]
		if !found {
			return nil, fmt.Errorf("failed to find ingested Source ID for isOccurrence: %s", helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](o.Src, helpers.SrcClientKey).NameId)
		}

		artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](o.Artifact, helpers.ArtifactClientKey)]
		if !found {
			return nil, fmt.Errorf("failed to find ingested artifact ID for isOccurrence: %s", helpers.GetKey[*model.ArtifactInputSpec, string](o.Artifact, helpers.ArtifactClientKey))
		}

		if result, err := model.IngestIsOccurrenceSrc(ctx, client, *srcID, *artID, *o.IsOccurrence); err != nil {
			return nil, err
		} else {
			return &result.IngestOccurrence, nil
		}
	}
	if o.Pkg != nil {

		pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](o.Pkg, helpers.PkgClientKey).VersionId]
		if !found {
			return nil, fmt.Errorf("failed to find ingested package ID for isOccurrence: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](o.Pkg, helpers.PkgClientKey).VersionId)
		}

		artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](o.Artifact, helpers.ArtifactClientKey)]
		if !found {
			return nil, fmt.Errorf("failed to find ingested artifact ID for isOccurrence: %s", helpers.GetKey[*model.ArtifactInputSpec, string](o.Artifact, helpers.ArtifactClientKey))
		}

		if result, err := model.IngestIsOccurrencePkg(ctx, client, *pkgID, *artID, *o.IsOccurrence); err != nil {
			return nil, err
		} else {
			return &result.IngestOccurrence, err
		}
	}
	return nil, nil
}

func ingestHasSlsa(ctx context.Context, client graphql.Client, hs assembler.HasSlsaIngest, artInputMap map[string]*model.IDorArtifactInput,
	matInputSpec map[string]*model.IDorArtifactInput, builderInputMap map[string]*model.IDorBuilderInput) error {

	var matIDList []model.IDorArtifactInput
	for _, mat := range hs.Materials {
		if matID, found := matInputSpec[helpers.GetKey[*model.ArtifactInputSpec, string](&mat, helpers.ArtifactClientKey)]; found {
			matIDList = append(matIDList, *matID)
		} else {
			return fmt.Errorf("failed to find ingested material ID for hasSLSA: %s", helpers.GetKey[*model.ArtifactInputSpec, string](&mat, helpers.ArtifactClientKey))
		}
	}

	artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](hs.Artifact, helpers.ArtifactClientKey)]
	if !found {
		return fmt.Errorf("failed to find ingested artifact ID for hasSLSA: %s", helpers.GetKey[*model.ArtifactInputSpec, string](hs.Artifact, helpers.ArtifactClientKey))
	}

	buildID, found := builderInputMap[hs.Builder.Uri]
	if !found {
		return fmt.Errorf("failed to find ingested artifact ID for hasSLSA: %s", hs.Builder.Uri)
	}

	_, err := model.IngestSLSAForArtifact(ctx, client, *artID, matIDList, *buildID, *hs.HasSlsa)
	return err
}

func ingestCertifyVuln(ctx context.Context, client graphql.Client, cv assembler.CertifyVulnIngest, packageInputMap map[string]*model.IDorPkgInput,
	vulnInputMap map[string]*model.IDorVulnerabilityInput) error {

	pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](cv.Pkg, helpers.PkgClientKey).VersionId]
	if !found {
		return fmt.Errorf("failed to find ingested package ID for certifyVuln: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](cv.Pkg, helpers.PkgClientKey).VersionId)
	}
	vulnID, found := vulnInputMap[helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](cv.Vulnerability, helpers.VulnClientKey).VulnerabilityID]
	if !found {
		return fmt.Errorf("failed to find ingested vulnerability ID for certifyVuln: %s", helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](cv.Vulnerability, helpers.VulnClientKey).VulnerabilityID)
	}

	_, err := model.IngestCertifyVulnPkg(ctx, client, *pkgID, *vulnID, *cv.VulnData)
	return err
}

func ingestVulnEqual(ctx context.Context, client graphql.Client, ve assembler.VulnEqualIngest, vulnInputMap map[string]*model.IDorVulnerabilityInput) error {
	if ve.Vulnerability == nil {
		return fmt.Errorf("unable to create VulnEqual without vulnerability")
	}
	if ve.EqualVulnerability == nil {
		return fmt.Errorf("unable to create VulnEqual without equal vulnerability")
	}

	vulnID, found := vulnInputMap[helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](ve.Vulnerability, helpers.VulnClientKey).VulnerabilityID]
	if !found {
		return fmt.Errorf("failed to find ingested vulnerability ID for vulnEqual: %s", helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](ve.Vulnerability, helpers.VulnClientKey).VulnerabilityID)
	}

	equalVulnID, found := vulnInputMap[helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](ve.EqualVulnerability, helpers.VulnClientKey).VulnerabilityID]
	if !found {
		return fmt.Errorf("failed to find ingested vulnerability ID for vulnEqual: %s", helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](ve.EqualVulnerability, helpers.VulnClientKey).VulnerabilityID)
	}

	_, err := model.IngestVulnEqual(ctx, client, *vulnID, *equalVulnID, *ve.VulnEqual)
	return err
}

func hasSourceAt(ctx context.Context, client graphql.Client, hsa assembler.HasSourceAtIngest, packageInputMap map[string]*model.IDorPkgInput,
	sourceInputMap map[string]*model.IDorSourceInput) error {

	pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](hsa.Pkg, helpers.PkgClientKey).VersionId]
	if !found {
		return fmt.Errorf("failed to find ingested package ID for hasSourceAt: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](hsa.Pkg, helpers.PkgClientKey).VersionId)
	}

	srcID, found := sourceInputMap[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](hsa.Src, helpers.SrcClientKey).NameId]
	if !found {
		return fmt.Errorf("failed to find ingested Source ID for hasSourceAt: %s", helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](hsa.Src, helpers.SrcClientKey).NameId)
	}

	_, err := model.IngestHasSourceAt(ctx, client, *pkgID, hsa.PkgMatchFlag, *srcID, *hsa.HasSourceAt)
	return err
}

func ingestCertifyBad(ctx context.Context, client graphql.Client, bad assembler.CertifyBadIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) error {

	if err := validatePackageSourceOrArtifactInput(bad.Pkg, bad.Src, bad.Artifact, "certifyBad"); err != nil {
		return fmt.Errorf("input validation failed for certifyBad: %w", err)
	}

	if bad.Pkg != nil {
		pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](bad.Pkg, helpers.PkgClientKey).VersionId]
		if !found {
			return fmt.Errorf("failed to find ingested package ID for certifyBad: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](bad.Pkg, helpers.PkgClientKey).VersionId)
		}
		_, err := model.IngestCertifyBadPkg(ctx, client, *pkgID, bad.PkgMatchFlag, *bad.CertifyBad)
		return err
	}
	if bad.Src != nil {
		srcID, found := sourceInputMap[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](bad.Src, helpers.SrcClientKey).NameId]
		if !found {
			return fmt.Errorf("failed to find ingested Source ID for certifyBad: %s", helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](bad.Src, helpers.SrcClientKey).NameId)
		}
		_, err := model.IngestCertifyBadSrc(ctx, client, *srcID, *bad.CertifyBad)
		return err
	}
	if bad.Artifact != nil {
		artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](bad.Artifact, helpers.ArtifactClientKey)]
		if !found {
			return fmt.Errorf("failed to find ingested artifact ID for certifyBad: %s", helpers.GetKey[*model.ArtifactInputSpec, string](bad.Artifact, helpers.ArtifactClientKey))
		}
		_, err := model.IngestCertifyBadArtifact(ctx, client, *artID, *bad.CertifyBad)
		return err
	}
	return nil
}

func ingestCertifyGood(ctx context.Context, client graphql.Client, good assembler.CertifyGoodIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) error {

	if err := validatePackageSourceOrArtifactInput(good.Pkg, good.Src, good.Artifact, "certifyGood"); err != nil {
		return fmt.Errorf("input validation failed for certifyGood: %w", err)
	}

	if good.Pkg != nil {
		pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](good.Pkg, helpers.PkgClientKey).VersionId]
		if !found {
			return fmt.Errorf("failed to find ingested package ID for certifyGood: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](good.Pkg, helpers.PkgClientKey).VersionId)
		}
		_, err := model.IngestCertifyGoodPkg(ctx, client, *pkgID, good.PkgMatchFlag, *good.CertifyGood)
		return err
	}
	if good.Src != nil {
		srcID, found := sourceInputMap[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](good.Src, helpers.SrcClientKey).NameId]
		if !found {
			return fmt.Errorf("failed to find ingested Source ID for certifyGood: %s", helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](good.Src, helpers.SrcClientKey).NameId)
		}
		_, err := model.IngestCertifyGoodSrc(ctx, client, *srcID, *good.CertifyGood)
		return err
	}
	if good.Artifact != nil {
		artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](good.Artifact, helpers.ArtifactClientKey)]
		if !found {
			return fmt.Errorf("failed to find ingested artifact ID for certifyGood: %s", helpers.GetKey[*model.ArtifactInputSpec, string](good.Artifact, helpers.ArtifactClientKey))
		}
		_, err := model.IngestCertifyGoodArtifact(ctx, client, *artID, *good.CertifyGood)
		return err
	}
	return nil
}

func ingestPointOfContact(ctx context.Context, client graphql.Client, poc assembler.PointOfContactIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) error {

	if err := validatePackageSourceOrArtifactInput(poc.Pkg, poc.Src, poc.Artifact, "pointOfContact"); err != nil {
		return fmt.Errorf("input validation failed for pointOfContact: %w", err)
	}

	if poc.Pkg != nil {
		pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](poc.Pkg, helpers.PkgClientKey).VersionId]
		if !found {
			return fmt.Errorf("failed to find ingested package ID for pointOfContact: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](poc.Pkg, helpers.PkgClientKey).VersionId)
		}
		_, err := model.IngestPointOfContactPkg(ctx, client, *pkgID, poc.PkgMatchFlag, *poc.PointOfContact)
		return err
	}
	if poc.Src != nil {
		srcID, found := sourceInputMap[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](poc.Src, helpers.SrcClientKey).NameId]
		if !found {
			return fmt.Errorf("failed to find ingested Source ID for pointOfContact: %s", helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](poc.Src, helpers.SrcClientKey).NameId)
		}
		_, err := model.IngestPointOfContactSrc(ctx, client, *srcID, *poc.PointOfContact)
		return err
	}
	if poc.Artifact != nil {
		artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](poc.Artifact, helpers.ArtifactClientKey)]
		if !found {
			return fmt.Errorf("failed to find ingested artifact ID for pointOfContact: %s", helpers.GetKey[*model.ArtifactInputSpec, string](poc.Artifact, helpers.ArtifactClientKey))
		}
		_, err := model.IngestPointOfContactArtifact(ctx, client, *artID, *poc.PointOfContact)
		return err
	}
	return nil
}

func ingestHasMetadata(ctx context.Context, client graphql.Client, hm assembler.HasMetadataIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, sourceInputMap map[string]*model.IDorSourceInput) error {

	if err := validatePackageSourceOrArtifactInput(hm.Pkg, hm.Src, hm.Artifact, "hasMetadata"); err != nil {
		return fmt.Errorf("input validation failed for hasMetadata: %w", err)
	}

	if hm.Pkg != nil {
		pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](hm.Pkg, helpers.PkgClientKey).VersionId]
		if !found {
			return fmt.Errorf("failed to find ingested package ID for hasMetadata: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](hm.Pkg, helpers.PkgClientKey).VersionId)
		}
		_, err := model.IngestHasMetadataPkg(ctx, client, *pkgID, hm.PkgMatchFlag, *hm.HasMetadata)
		return err
	}
	if hm.Src != nil {
		srcID, found := sourceInputMap[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](hm.Src, helpers.SrcClientKey).NameId]
		if !found {
			return fmt.Errorf("failed to find ingested Source ID for hasMetadata: %s", helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](hm.Src, helpers.SrcClientKey).NameId)
		}
		_, err := model.IngestHasMetadataSrc(ctx, client, *srcID, *hm.HasMetadata)
		return err
	}
	if hm.Artifact != nil {
		artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](hm.Artifact, helpers.ArtifactClientKey)]
		if !found {
			return fmt.Errorf("failed to find ingested artifact ID for hasMetadata: %s", helpers.GetKey[*model.ArtifactInputSpec, string](hm.Artifact, helpers.ArtifactClientKey))
		}
		_, err := model.IngestHasMetadataArtifact(ctx, client, *artID, *hm.HasMetadata)
		return err
	}
	return nil
}

func ingestHasSBOM(ctx context.Context, client graphql.Client, hb assembler.HasSBOMIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput) error {

	if hb.Pkg != nil && hb.Artifact != nil {
		return fmt.Errorf("unable to create hasSBOM with both Pkg and Src subject specified")
	}
	if hb.Pkg == nil && hb.Artifact == nil {
		return fmt.Errorf("unable to create hasSBOM without either Pkg and Src subject specified")
	}

	if hb.Pkg != nil {
		pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](hb.Pkg, helpers.PkgClientKey).VersionId]
		if !found {
			return fmt.Errorf("failed to find ingested package ID for hasSBOM: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](hb.Pkg, helpers.PkgClientKey).VersionId)
		}
		_, err := model.IngestHasSBOMPkg(ctx, client, *pkgID, *hb.HasSBOM, *hb.Includes)
		return err
	}
	if hb.Artifact != nil {
		artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](hb.Artifact, helpers.ArtifactClientKey)]
		if !found {
			return fmt.Errorf("failed to find ingested artifact ID for hasMetadata: %s", helpers.GetKey[*model.ArtifactInputSpec, string](hb.Artifact, helpers.ArtifactClientKey))
		}
		_, err := model.IngestHasSBOMArtifact(ctx, client, *artID, *hb.HasSBOM, *hb.Includes)
		return err
	}
	return nil
}

func ingestVulnMetadata(ctx context.Context, client graphql.Client, vi assembler.VulnMetadataIngest, vulnInputMap map[string]*model.IDorVulnerabilityInput) error {
	vulnID, found := vulnInputMap[helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](vi.Vulnerability, helpers.VulnClientKey).VulnerabilityID]
	if !found {
		return fmt.Errorf("failed to find ingested vulnerability ID for vulnEqual: %s", helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](vi.Vulnerability, helpers.VulnClientKey).VulnerabilityID)
	}

	_, err := model.IngestVulnHasMetadata(ctx, client, *vulnID, *vi.VulnMetadata)
	if err != nil {
		return err
	}
	return nil
}

func ingestVex(ctx context.Context, client graphql.Client, vi assembler.VexIngest, packageInputMap map[string]*model.IDorPkgInput,
	artInputMap map[string]*model.IDorArtifactInput, vulnInputMap map[string]*model.IDorVulnerabilityInput) error {
	if vi.Artifact != nil && vi.Pkg != nil {
		return fmt.Errorf("unable to create VexIngest with both Pkg and Artifact specified")
	}

	if vi.Artifact == nil && vi.Pkg == nil {
		return fmt.Errorf("unable to create VexIngest without either Pkg or Artifact specified")
	}

	vulnID, found := vulnInputMap[helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](vi.Vulnerability, helpers.VulnClientKey).VulnerabilityID]
	if !found {
		return fmt.Errorf("failed to find ingested vulnerability ID for VexIngest: %s", helpers.GetKey[*model.VulnerabilityInputSpec, helpers.VulnIds](vi.Vulnerability, helpers.VulnClientKey).VulnerabilityID)
	}

	if vi.Pkg != nil {
		pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](vi.Pkg, helpers.PkgClientKey).VersionId]
		if !found {
			return fmt.Errorf("failed to find ingested package ID for VexIngest: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](vi.Pkg, helpers.PkgClientKey).VersionId)
		}
		_, err := model.IngestCertifyVexPkg(ctx, client, *pkgID, *vulnID, *vi.VexData)
		if err != nil {
			return err
		}
	}

	if vi.Artifact != nil {
		artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](vi.Artifact, helpers.ArtifactClientKey)]
		if !found {
			return fmt.Errorf("failed to find ingested artifact ID for hasMetadata: %s", helpers.GetKey[*model.ArtifactInputSpec, string](vi.Artifact, helpers.ArtifactClientKey))
		}
		_, err := model.IngestCertifyVexArtifact(ctx, client, *artID, *vulnID, *vi.VexData)
		if err != nil {
			return err
		}
	}
	return nil
}

func ingestPkgEqual(ctx context.Context, client graphql.Client, pe assembler.PkgEqualIngest, packageInputMap map[string]*model.IDorPkgInput) error {
	if pe.Pkg == nil {
		return fmt.Errorf("unable to create pkgEqual without Pkg")
	}
	if pe.EqualPkg == nil {
		return fmt.Errorf("unable to create pkgEqual without EqualPkg")
	}

	pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](pe.Pkg, helpers.PkgClientKey).VersionId]
	if !found {
		return fmt.Errorf("failed to find ingested package ID for pkgEqual: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](pe.Pkg, helpers.PkgClientKey).VersionId)
	}

	equalPkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](pe.EqualPkg, helpers.PkgClientKey).VersionId]
	if !found {
		return fmt.Errorf("failed to find ingested package ID for pkgEqual: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](pe.EqualPkg, helpers.PkgClientKey).VersionId)
	}

	_, err := model.IngestPkgEqual(ctx, client, *pkgID, *equalPkgID, *pe.PkgEqual)
	return err
}

func ingestHashEqual(ctx context.Context, client graphql.Client, he assembler.HashEqualIngest, artInputMap map[string]*model.IDorArtifactInput) error {
	if he.Artifact == nil {
		return fmt.Errorf("unable to create HashEqual without artifact")
	}
	if he.EqualArtifact == nil {
		return fmt.Errorf("unable to create HashEqual without equal artifact")
	}

	artID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](he.Artifact, helpers.ArtifactClientKey)]
	if !found {
		return fmt.Errorf("failed to find ingested artifact ID for HashEqual: %s", helpers.GetKey[*model.ArtifactInputSpec, string](he.Artifact, helpers.ArtifactClientKey))
	}
	equalArtID, found := artInputMap[helpers.GetKey[*model.ArtifactInputSpec, string](he.Artifact, helpers.ArtifactClientKey)]
	if !found {
		return fmt.Errorf("failed to find ingested artifact ID for HashEqual: %s", helpers.GetKey[*model.ArtifactInputSpec, string](he.Artifact, helpers.ArtifactClientKey))
	}

	_, err := model.IngestHashEqual(ctx, client, *artID, *equalArtID, *he.HashEqual)
	return err
}

func ingestCertifyLegal(ctx context.Context, client graphql.Client, cl assembler.CertifyLegalIngest, packageInputMap map[string]*model.IDorPkgInput,
	sourceInputMap map[string]*model.IDorSourceInput, licenseInputMap map[string]*model.IDorLicenseInput) error {

	if cl.Pkg != nil && cl.Src != nil {
		return fmt.Errorf("unable to create CertifyLegal with both Src and Pkg subject specified")
	}
	if cl.Pkg == nil && cl.Src == nil {
		return fmt.Errorf("unable to create CertifyLegal without either Src and Pkg subject specified")
	}

	// Declared Licenses
	var decList []model.IDorLicenseInput
	for _, dec := range cl.Declared {
		if licID, found := licenseInputMap[helpers.GetKey[*model.LicenseInputSpec, string](&dec, helpers.LicenseClientKey)]; found {
			decList = append(decList, *licID)
		} else {
			return fmt.Errorf("failed to find ingested license ID for certifyLegal: %s", helpers.GetKey[*model.LicenseInputSpec, string](&dec, helpers.LicenseClientKey))
		}
	}

	// Discovered Licenses
	var disList []model.IDorLicenseInput
	for _, dis := range cl.Discovered {
		if licID, found := licenseInputMap[helpers.GetKey[*model.LicenseInputSpec, string](&dis, helpers.LicenseClientKey)]; found {
			disList = append(disList, *licID)
		} else {
			return fmt.Errorf("failed to find ingested license ID for certifyLegal: %s", helpers.GetKey[*model.LicenseInputSpec, string](&dis, helpers.LicenseClientKey))
		}
	}

	if cl.Src != nil {
		srcID, found := sourceInputMap[helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](cl.Src, helpers.SrcClientKey).NameId]
		if !found {
			return fmt.Errorf("failed to find ingested Source ID for CertifyLegal: %s", helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](cl.Src, helpers.SrcClientKey).NameId)
		}
		_, err := model.IngestCertifyLegalSrc(ctx, client, *srcID, decList, disList, *cl.CertifyLegal)
		return err
	}
	if cl.Pkg != nil {
		pkgID, found := packageInputMap[helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](cl.Pkg, helpers.PkgClientKey).VersionId]
		if !found {
			return fmt.Errorf("failed to find ingested package ID for CertifyLegal: %s", helpers.GetKey[*model.PkgInputSpec, helpers.PkgIds](cl.Pkg, helpers.PkgClientKey).VersionId)
		}
		_, err := model.IngestCertifyLegalPkg(ctx, client, *pkgID, decList, disList, *cl.CertifyLegal)
		return err
	}
	return nil
}

func validatePackageSourceOrArtifactInput(pkg *model.PkgInputSpec, src *model.SourceInputSpec, artifact *model.ArtifactInputSpec, path string) error {
	valuesDefined := 0
	if pkg != nil {
		valuesDefined = valuesDefined + 1
	}
	if src != nil {
		valuesDefined = valuesDefined + 1
	}
	if artifact != nil {
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return fmt.Errorf("must specify at most one package, source, or artifact for %v", path)
	}

	return nil
}

// TODO(lumjjb): add more ingestion verbs as they come up
