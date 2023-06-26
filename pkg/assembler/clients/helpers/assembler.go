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

func GetAssembler(ctx context.Context, gqlclient graphql.Client) func([]assembler.AssemblerInput) error {
	logger := logging.FromContext(ctx)
	return func(preds []assembler.IngestPredicates) error {
		for _, p := range preds {
			packages := p.GetPackages(ctx)
			logger.Infof("assembling Package: %v", len(packages))
			for _, v := range packages {
				if err := ingestPackage(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			sources := p.GetSources(ctx)
			logger.Infof("assembling Source: %v", len(sources))
			for _, v := range sources {
				if err := ingestSource(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			artifacts := p.GetArtifacts(ctx)
			logger.Infof("assembling Artifact: %v", len(artifacts))
			for _, v := range artifacts {
				if err := ingestArtifact(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			builders := p.GetBuilders(ctx)
			logger.Infof("assembling Builder: %v", len(builders))
			for _, v := range builders {
				if err := ingestBuilder(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			materials := p.GetMaterials(ctx)
			logger.Infof("assembling Materials (Artifact): %v", len(materials))
			if err := ingestMaterials(ctx, gqlclient, materials); err != nil {
				return err
			}

			cves := p.GetCVEs(ctx)
			logger.Infof("assembling CVE: %v", len(cves))
			for _, v := range cves {
				if err := ingestCVE(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			osvs := p.GetOSVs(ctx)
			logger.Infof("assembling OSV: %v", len(osvs))
			for _, v := range osvs {
				if err := ingestOSV(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			ghsas := p.GetGHSAs(ctx)
			logger.Infof("assembling GHSA: %v", len(ghsas))
			for _, v := range ghsas {
				if err := ingestGHSA(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			for _, v := range p.CertifyScorecard {
				if err := ingestCertifyScorecards(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			for _, v := range p.IsDependency {
				if err := ingestIsDependency(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling IsOccurence: %v", len(p.IsOccurrence))
			for _, v := range p.IsOccurrence {
				if err := ingestIsOccurrence(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			for _, v := range p.HasSlsa {
				if err := ingestHasSlsa(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			for _, cv := range p.CertifyVuln {
				if err := ingestCertifyVuln(ctx, gqlclient, cv); err != nil {
					return err
				}
			}

			logger.Infof("assembling IsVuln: %v", len(p.IsVuln))
			for _, iv := range p.IsVuln {
				if err := ingestIsVuln(ctx, gqlclient, iv); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			for _, hsa := range p.HasSourceAt {
				if err := hasSourceAt(ctx, gqlclient, hsa); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			for _, bad := range p.CertifyBad {
				if err := ingestCertifyBad(ctx, gqlclient, bad); err != nil {
					return err
				}
			}

			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			for _, good := range p.CertifyGood {
				if err := ingestCertifyGood(ctx, gqlclient, good); err != nil {
					return err
				}
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			for _, hb := range p.HasSBOM {
				if err := ingestHasSBOM(ctx, gqlclient, hb); err != nil {
					return err
				}
			}

			logger.Infof("assembling VEX : %v", len(p.Vex))
			for _, v := range p.Vex {
				if err := ingestVex(ctx, gqlclient, v); err != nil {
					return err
				}
			}

			logger.Infof("assembling HashEqual : %v", len(p.HashEqual))
			for _, equal := range p.HashEqual {
				if err := ingestHashEqual(ctx, gqlclient, equal); err != nil {
					return err
				}
			}

			logger.Infof("assembling PkgEqual : %v", len(p.PkgEqual))
			for _, equal := range p.PkgEqual {
				if err := ingestPkgEqual(ctx, gqlclient, equal); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func ingestPackage(ctx context.Context, client graphql.Client, v *model.PkgInputSpec) error {
	_, err := model.IngestPackage(ctx, client, *v)
	return err
}

func ingestSource(ctx context.Context, client graphql.Client, v *model.SourceInputSpec) error {
	_, err := model.IngestSource(ctx, client, *v)
	return err
}

func ingestArtifact(ctx context.Context, client graphql.Client, v *model.ArtifactInputSpec) error {
	_, err := model.IngestArtifact(ctx, client, *v)
	return err
}

func ingestMaterials(ctx context.Context, client graphql.Client, v []model.ArtifactInputSpec) error {
	_, err := model.IngestMaterials(ctx, client, v)
	return err
}

func ingestBuilder(ctx context.Context, client graphql.Client, v *model.BuilderInputSpec) error {
	_, err := model.IngestBuilder(ctx, client, *v)
	return err
}

func ingestCVE(ctx context.Context, client graphql.Client, v *model.CVEInputSpec) error {
	_, err := model.IngestCVE(ctx, client, *v)
	return err
}

func ingestOSV(ctx context.Context, client graphql.Client, v *model.OSVInputSpec) error {
	_, err := model.IngestOSV(ctx, client, *v)
	return err
}

func ingestGHSA(ctx context.Context, client graphql.Client, v *model.GHSAInputSpec) error {
	_, err := model.IngestGHSA(ctx, client, *v)
	return err
}

func ingestCertifyScorecards(ctx context.Context, client graphql.Client, v assembler.CertifyScorecardIngest) error {
	_, err := model.Scorecard(ctx, client, *v.Source, *v.Scorecard)
	return err
}

func ingestIsDependency(ctx context.Context, client graphql.Client, v assembler.IsDependencyIngest) error {
	_, err := model.IsDependency(ctx, client, *v.Pkg, *v.DepPkg, *v.IsDependency)
	return err
}

func ingestIsDependencies(ctx context.Context, client graphql.Client, v []assembler.IsDependencyIngest) error {
	var pkgs []model.PkgInputSpec
	var depPkgs []model.PkgInputSpec
	var dependencies []model.IsDependencyInputSpec
	for _, ingest := range v {
		pkgs = append(pkgs, *ingest.Pkg)
		depPkgs = append(depPkgs, *ingest.DepPkg)
		dependencies = append(dependencies, *ingest.IsDependency)
	}
	_, err := model.IsDependencies(ctx, client, pkgs, depPkgs, dependencies)
	return err
}

func ingestIsOccurrence(ctx context.Context, client graphql.Client, v assembler.IsOccurrenceIngest) error {
	if v.Pkg != nil && v.Src != nil {
		return fmt.Errorf("unable to create IsOccurrence with both Src and Pkg subject specified")
	}
	if v.Pkg == nil && v.Src == nil {
		return fmt.Errorf("unable to create IsOccurrence without either Src and Pkg subject specified")
	}

	if v.Src != nil {
		_, err := model.IsOccurrenceSrc(ctx, client, *v.Src, *v.Artifact, *v.IsOccurrence)
		return err
	}
	_, err := model.IsOccurrencePkg(ctx, client, *v.Pkg, *v.Artifact, *v.IsOccurrence)
	return err
}

func ingestIsOccurrences(ctx context.Context, client graphql.Client, v []assembler.IsOccurrenceIngest) error {
	var pkgs []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var artifacts []model.ArtifactInputSpec
	var occurrences []model.IsOccurrenceInputSpec
	for _, ingest := range v {
		if ingest.Pkg != nil {
			pkgs = append(pkgs, *ingest.Pkg)
		} else {
			sources = append(sources, *ingest.Src)
		}
		artifacts = append(artifacts, *ingest.Artifact)
		occurrences = append(occurrences, *ingest.IsOccurrence)
	}
	if len(sources) > 0 {
		_, err := model.IsOccurrencesSrc(ctx, client, sources, artifacts, occurrences)
		return err
	}
	_, err := model.IsOccurrencesPkg(ctx, client, pkgs, artifacts, occurrences)
	return err
}

func ingestHasSlsa(ctx context.Context, client graphql.Client, v assembler.HasSlsaIngest) error {
	_, err := model.SLSAForArtifact(ctx, client, *v.Artifact, v.Materials, *v.Builder, *v.HasSlsa)
	return err
}

func ingestCertifyVuln(ctx context.Context, client graphql.Client, cv assembler.CertifyVulnIngest) error {
	if err := ValidateVulnerabilityInput(cv.OSV, cv.CVE, cv.GHSA, "certifyVulnerability"); err != nil {
		return fmt.Errorf("input validation failed for certifyVulnerability: %w", err)
	}

	if cv.OSV != nil {
		_, err := model.CertifyOSV(ctx, client, *cv.Pkg, *cv.OSV, *cv.VulnData)
		return err
	}
	if cv.CVE != nil {
		_, err := model.CertifyCVE(ctx, client, *cv.Pkg, *cv.CVE, *cv.VulnData)
		return err
	}
	if cv.GHSA != nil {
		_, err := model.CertifyGHSA(ctx, client, *cv.Pkg, *cv.GHSA, *cv.VulnData)
		return err
	}
	_, err := model.CertifyNoKnownVuln(ctx, client, *cv.Pkg, *cv.VulnData)
	return err
}

func ingestIsVuln(ctx context.Context, client graphql.Client, iv assembler.IsVulnIngest) error {
	if iv.CVE != nil && iv.GHSA != nil {
		return fmt.Errorf("unable to create IsVuln with both CVE and GHSA specified")
	}
	if iv.CVE == nil && iv.GHSA == nil {
		return fmt.Errorf("unable to create IsVuln without either CVE or GHSA specified")
	}

	if iv.CVE != nil {
		_, err := model.IsVulnerabilityCVE(ctx, client, *iv.OSV, *iv.CVE, *iv.IsVuln)
		return err
	}
	_, err := model.IsVulnerabilityGHSA(ctx, client, *iv.OSV, *iv.GHSA, *iv.IsVuln)
	return err
}

func hasSourceAt(ctx context.Context, client graphql.Client, hsa assembler.HasSourceAtIngest) error {
	_, err := model.HasSourceAt(ctx, client, *hsa.Pkg, hsa.PkgMatchFlag, *hsa.Src, *hsa.HasSourceAt)
	return err
}

func ingestCertifyBad(ctx context.Context, client graphql.Client, bad assembler.CertifyBadIngest) error {
	if err := validatePackageSourceOrArtifactInput(bad.Pkg, bad.Src, bad.Artifact, "certifyBad"); err != nil {
		return fmt.Errorf("input validation failed for certifyBad: %w", err)
	}

	if bad.Pkg != nil {
		_, err := model.CertifyBadPkg(ctx, client, *bad.Pkg, &bad.PkgMatchFlag, *bad.CertifyBad)
		return err
	}
	if bad.Src != nil {
		_, err := model.CertifyBadSrc(ctx, client, *bad.Src, *bad.CertifyBad)
		return err
	}
	_, err := model.CertifyBadArtifact(ctx, client, *bad.Artifact, *bad.CertifyBad)
	return err
}

func ingestCertifyGood(ctx context.Context, client graphql.Client, good assembler.CertifyGoodIngest) error {
	if err := validatePackageSourceOrArtifactInput(good.Pkg, good.Src, good.Artifact, "certifyGood"); err != nil {
		return fmt.Errorf("input validation failed for certifyBad: %w", err)
	}

	if good.Pkg != nil {
		_, err := model.CertifyGoodPkg(ctx, client, *good.Pkg, &good.PkgMatchFlag, *good.CertifyGood)
		return err
	}
	if good.Src != nil {
		_, err := model.CertifyGoodSrc(ctx, client, *good.Src, *good.CertifyGood)
		return err
	}
	_, err := model.CertifyGoodArtifact(ctx, client, *good.Artifact, *good.CertifyGood)
	return err
}

func ingestHasSBOM(ctx context.Context, client graphql.Client, hb assembler.HasSBOMIngest) error {
	if hb.Pkg != nil && hb.Artifact != nil {
		return fmt.Errorf("unable to create hasSBOM with both Pkg and Src subject specified")
	}
	if hb.Pkg == nil && hb.Artifact == nil {
		return fmt.Errorf("unable to create hasSBOM without either Pkg and Src ssubject specified")
	}

	if hb.Pkg != nil {
		_, err := model.HasSBOMPkg(ctx, client, *hb.Pkg, *hb.HasSBOM)
		return err
	}
	_, err := model.HasSBOMArtifact(ctx, client, *hb.Artifact, *hb.HasSBOM)
	return err
}

func ingestVex(ctx context.Context, client graphql.Client, vi assembler.VexIngest) error {
	if err := ValidateVulnerabilityInput(vi.OSV, vi.CVE, vi.GHSA, "VexIngest"); err != nil {
		return fmt.Errorf("input validation failed for VexIngest: %w", err)
	}

	if vi.Artifact != nil && vi.Pkg != nil {
		return fmt.Errorf("unable to create VexIngest with both Pkg and Artifact specified")
	}

	if vi.Artifact == nil && vi.Pkg == nil {
		return fmt.Errorf("unable to create VexIngest without either Pkg or Artifact specified")
	}

	if vi.CVE != nil {
		if vi.Pkg != nil {
			_, err := model.VexPackageAndCve(ctx, client, *vi.Pkg, *vi.CVE, *vi.VexData)
			if err != nil {
				return err
			}
		}

		if vi.Artifact != nil {
			_, err := model.VexArtifactAndCve(ctx, client, *vi.Artifact, *vi.CVE, *vi.VexData)
			if err != nil {
				return err
			}
		}
	}

	if vi.GHSA != nil {
		if vi.Pkg != nil {
			_, err := model.VEXPackageAndGhsa(ctx, client, *vi.Pkg, *vi.GHSA, *vi.VexData)
			if err != nil {
				return err
			}
		}

		if vi.Artifact != nil {
			_, err := model.VexArtifactAndGhsa(ctx, client, *vi.Artifact, *vi.GHSA, *vi.VexData)
			if err != nil {
				return err
			}
		}
	}

	if vi.OSV != nil {
		if vi.Pkg != nil {
			_, err := model.VexPackageAndOsv(ctx, client, *vi.Pkg, *vi.OSV, *vi.VexData)
			if err != nil {
				return err
			}
		}

		if vi.Artifact != nil {
			_, err := model.VexArtifactAndOsv(ctx, client, *vi.Artifact, *vi.OSV, *vi.VexData)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func ingestPkgEqual(ctx context.Context, client graphql.Client, v assembler.PkgEqualIngest) error {
	if v.Pkg == nil {
		return fmt.Errorf("unable to create pkgEqual without Pkg")
	}
	if v.EqualPkg == nil {
		return fmt.Errorf("unable to create pkgEqual without EqualPkg")
	}
	_, err := model.PkgEqual(ctx, client, *v.Pkg, *v.EqualPkg, *v.PkgEqual)
	return err
}

func ingestHashEqual(ctx context.Context, client graphql.Client, v assembler.HashEqualIngest) error {
	if v.Artifact == nil {
		return fmt.Errorf("unable to create HashEqual without artifact")
	}
	if v.EqualArtifact == nil {
		return fmt.Errorf("unable to create HashEqual without equal artifact")
	}
	_, err := model.HashEqual(ctx, client, *v.Artifact, *v.EqualArtifact, *v.HashEqual)
	return err
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

func ValidateVulnerabilityInput(osv *model.OSVInputSpec, cve *model.CVEInputSpec, ghsa *model.GHSAInputSpec, path string) error {
	vulnDefined := 0
	if osv != nil {
		vulnDefined = vulnDefined + 1
	}
	if ghsa != nil {
		vulnDefined = vulnDefined + 1
	}
	if cve != nil {
		vulnDefined = vulnDefined + 1
	}
	if vulnDefined > 2 {
		return fmt.Errorf("must specify at most one vulnerability (cve, osv, or ghsa) for %v", path)
	}
	return nil
}

// TODO(lumjjb): add more ingestion verbs as they come up
