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
			packages := p.GetPackages(ctx)
			logger.Infof("assembling Package: %v", len(packages))
			var collectedPackages []model.PkgInputSpec
			collectedPackages = make([]model.PkgInputSpec, 0)
			for _, v := range packages {
				collectedPackages = append(collectedPackages, *v)
			}
			if err := ingestPackages(ctx, gqlclient, collectedPackages); err != nil {
				return fmt.Errorf("ingestPackages failed with error: %w", err)
			}

			sources := p.GetSources(ctx)
			logger.Infof("assembling Source: %v", len(sources))

			var collectedSources []model.SourceInputSpec
			collectedSources = make([]model.SourceInputSpec, 0)
			for _, v := range sources {
				collectedSources = append(collectedSources, *v)
			}
			if err := ingestSources(ctx, gqlclient, collectedSources); err != nil {
				return fmt.Errorf("ingestSources failed with error: %w", err)
			}

			artifacts := p.GetArtifacts(ctx)
			logger.Infof("assembling Artifact: %v", len(artifacts))
			var collectedArtifacts []model.ArtifactInputSpec
			collectedArtifacts = make([]model.ArtifactInputSpec, 0)
			for _, v := range artifacts {
				collectedArtifacts = append(collectedArtifacts, *v)
			}
			if err := ingestArtifacts(ctx, gqlclient, collectedArtifacts); err != nil {
				return fmt.Errorf("ingestArtifacts failed with error: %w", err)
			}

			materials := p.GetMaterials(ctx)
			logger.Infof("assembling Materials (Artifact): %v", len(materials))
			if err := ingestArtifacts(ctx, gqlclient, materials); err != nil {
				return fmt.Errorf("ingestArtifacts failed with error: %w", err)
			}

			builders := p.GetBuilders(ctx)
			logger.Infof("assembling Builder: %v", len(builders))
			var collectedBuilders []model.BuilderInputSpec
			collectedBuilders = make([]model.BuilderInputSpec, 0)
			for _, v := range builders {
				collectedBuilders = append(collectedBuilders, *v)
			}
			if err := ingestBuilders(ctx, gqlclient, collectedBuilders); err != nil {
				return fmt.Errorf("ingestBuilders failed with error: %w", err)
			}

			cves := p.GetCVEs(ctx)
			logger.Infof("assembling CVE: %v", len(cves))
			var collectedCVEs []model.CVEInputSpec
			collectedCVEs = make([]model.CVEInputSpec, 0)
			for _, v := range cves {
				collectedCVEs = append(collectedCVEs, *v)
			}
			if err := ingestCVEs(ctx, gqlclient, collectedCVEs); err != nil {
				return fmt.Errorf("ingestCVEs failed with error: %w", err)
			}

			osvs := p.GetOSVs(ctx)
			logger.Infof("assembling OSV: %v", len(osvs))
			var collectedOSVs []model.OSVInputSpec
			collectedOSVs = make([]model.OSVInputSpec, 0)
			for _, v := range osvs {
				collectedOSVs = append(collectedOSVs, *v)
			}
			if err := ingestOSVs(ctx, gqlclient, collectedOSVs); err != nil {
				return fmt.Errorf("ingestOSVs failed with error: %w", err)
			}

			// TODO(pxp928): add bulk ingestion for ghsas
			ghsas := p.GetGHSAs(ctx)
			logger.Infof("assembling GHSA: %v", len(ghsas))
			var collectedGHSAs []model.GHSAInputSpec
			collectedGHSAs = make([]model.GHSAInputSpec, 0)
			for _, v := range ghsas {
				collectedGHSAs = append(collectedGHSAs, *v)
			}
			if err := ingestGHSAs(ctx, gqlclient, collectedGHSAs); err != nil {
				return fmt.Errorf("ingestGHSAs failed with error: %w", err)
			}

			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			if err := ingestCertifyScorecards(ctx, gqlclient, p.CertifyScorecard); err != nil {
				return fmt.Errorf("ingestCertifyScorecards failed with error: %w", err)
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			if err := ingestIsDependencies(ctx, gqlclient, p.IsDependency); err != nil {
				return fmt.Errorf("ingestIsDependencies failed with error: %w", err)
			}

			logger.Infof("assembling IsOccurrence: %v", len(p.IsOccurrence))
			if err := ingestIsOccurrences(ctx, gqlclient, p.IsOccurrence); err != nil {
				return fmt.Errorf("ingestIsOccurrences failed with error: %w", err)
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			if err := ingestHasSLSAs(ctx, gqlclient, p.HasSlsa); err != nil {
				return fmt.Errorf("ingestHasSLSAs failed with error: %w", err)
			}

			// TODO(pxp928): add bulk ingestion for CertifyVuln
			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			for _, cv := range p.CertifyVuln {
				if err := ingestCertifyVuln(ctx, gqlclient, cv); err != nil {
					return fmt.Errorf("ingestCertifyVuln failed with error: %w", err)
				}
			}

			// TODO(pxp928): add bulk ingestion for IsVuln
			logger.Infof("assembling IsVuln: %v", len(p.IsVuln))
			for _, iv := range p.IsVuln {
				if err := ingestIsVuln(ctx, gqlclient, iv); err != nil {
					return fmt.Errorf("ingestIsVuln failed with error: %w", err)

				}
			}

			// TODO(pxp928): add bulk ingestion for HasSourceAt
			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			for _, hsa := range p.HasSourceAt {
				if err := hasSourceAt(ctx, gqlclient, hsa); err != nil {
					return fmt.Errorf("hasSourceAt failed with error: %w", err)

				}
			}

			// TODO(pxp928): add bulk ingestion for CertifyBad
			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			for _, bad := range p.CertifyBad {
				if err := ingestCertifyBad(ctx, gqlclient, bad); err != nil {
					return fmt.Errorf("ingestCertifyBad failed with error: %w", err)

				}
			}

			// TODO(pxp928): add bulk ingestion for CertifyGood
			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			for _, good := range p.CertifyGood {
				if err := ingestCertifyGood(ctx, gqlclient, good); err != nil {
					return fmt.Errorf("ingestCertifyGood failed with error: %w", err)

				}
			}

			// TODO: add bulk ingestion for PointOfContact
			logger.Infof("assembling PointOfContact: %v", len(p.CertifyGood))
			for _, poc := range p.PointOfContact {
				if err := ingestPointOfContact(ctx, gqlclient, poc); err != nil {
					return fmt.Errorf("ingestPointOfContact failed with error: %w", err)

				}
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			if err := ingestHasSBOMs(ctx, gqlclient, p.HasSBOM); err != nil {
				return fmt.Errorf("ingestHasSBOMs failed with error: %w", err)
			}

			// TODO(pxp928): add bulk ingestion for VEX
			logger.Infof("assembling VEX : %v", len(p.Vex))
			for _, v := range p.Vex {
				if err := ingestVex(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("ingestVex failed with error: %w", err)

				}
			}

			logger.Infof("assembling HashEqual : %v", len(p.HashEqual))
			if err := ingestHashEquals(ctx, gqlclient, p.HashEqual); err != nil {
				return fmt.Errorf("ingestHashEquals failed with error: %w", err)
			}

			// TODO(pxp928): add bulk ingestion for PkgEqual
			logger.Infof("assembling PkgEqual : %v", len(p.PkgEqual))
			for _, equal := range p.PkgEqual {
				if err := ingestPkgEqual(ctx, gqlclient, equal); err != nil {
					return fmt.Errorf("ingestPkgEqual failed with error: %w", err)

				}
			}
		}
		return nil
	}
}

func ingestPackages(ctx context.Context, client graphql.Client, v []model.PkgInputSpec) error {
	_, err := model.IngestPackages(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestPackages failed with error: %w", err)
	}
	return nil
}

func ingestSources(ctx context.Context, client graphql.Client, v []model.SourceInputSpec) error {
	_, err := model.IngestSources(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestSources failed with error: %w", err)
	}
	return nil
}

func ingestArtifacts(ctx context.Context, client graphql.Client, v []model.ArtifactInputSpec) error {
	_, err := model.IngestArtifacts(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestArtifacts failed with error: %w", err)
	}
	return nil
}

func ingestBuilders(ctx context.Context, client graphql.Client, v []model.BuilderInputSpec) error {
	_, err := model.IngestBuilders(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestBuilders failed with error: %w", err)
	}
	return nil
}

func ingestCVEs(ctx context.Context, client graphql.Client, v []model.CVEInputSpec) error {
	_, err := model.IngestCVEs(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestCVEs failed with error: %w", err)
	}
	return nil
}

func ingestOSVs(ctx context.Context, client graphql.Client, v []model.OSVInputSpec) error {
	_, err := model.IngestOSVs(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestOSVs failed with error: %w", err)
	}
	return nil
}

func ingestGHSAs(ctx context.Context, client graphql.Client, v []model.GHSAInputSpec) error {
	_, err := model.IngestGHSAs(ctx, client, v)
	if err != nil {
		return fmt.Errorf("ingestGHSAs failed with error: %w", err)
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

func ingestIsDependencies(ctx context.Context, client graphql.Client, v []assembler.IsDependencyIngest) error {
	var pkgs []model.PkgInputSpec
	var depPkgs []model.PkgInputSpec
	var dependencies []model.IsDependencyInputSpec
	for _, ingest := range v {
		pkgs = append(pkgs, *ingest.Pkg)
		depPkgs = append(depPkgs, *ingest.DepPkg)
		dependencies = append(dependencies, *ingest.IsDependency)
	}
	if len(v) > 0 {
		_, err := model.IsDependencies(ctx, client, pkgs, depPkgs, dependencies)
		if err != nil {
			return fmt.Errorf("isDependencies failed with error: %w", err)
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
		_, err := model.HashEquals(ctx, client, artifacts, equalArtifacts, hashEquals)
		if err != nil {
			return fmt.Errorf("HashEquals failed with error: %w", err)
		}
	}
	return nil
}

func ingestHasSBOMs(ctx context.Context, client graphql.Client, v []assembler.HasSBOMIngest) error {
	var pkgs []model.PkgInputSpec
	var artifacts []model.ArtifactInputSpec
	var pkgSBOMs []model.HasSBOMInputSpec
	var artSBOMs []model.HasSBOMInputSpec
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
		} else {
			artifacts = append(artifacts, *ingest.Artifact)
			artSBOMs = append(artSBOMs, *ingest.HasSBOM)
		}
	}
	if len(artifacts) > 0 {
		_, err := model.HasSBOMArtifacts(ctx, client, artifacts, artSBOMs)
		if err != nil {
			return fmt.Errorf("hasSBOMArtifacts failed with error: %w", err)
		}
	}
	if len(pkgs) > 0 {
		_, err := model.HasSBOMPkgs(ctx, client, pkgs, pkgSBOMs)
		if err != nil {
			return fmt.Errorf("hasSBOMPkgs failed with error: %w", err)
		}
	}
	return nil
}

func ingestIsOccurrences(ctx context.Context, client graphql.Client, v []assembler.IsOccurrenceIngest) error {
	var pkgs []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var pkgArtifacts []model.ArtifactInputSpec
	var pkgOccurrences []model.IsOccurrenceInputSpec
	var srcArtifacts []model.ArtifactInputSpec
	var srcOccurrences []model.IsOccurrenceInputSpec
	for _, ingest := range v {

		if ingest.Pkg != nil && ingest.Src != nil {
			return fmt.Errorf("unable to create IsOccurrence with both Src and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Src == nil {
			return fmt.Errorf("unable to create IsOccurrence without either Src and Pkg subject specified")
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
	if len(sources) > 0 {
		_, err := model.IsOccurrencesSrc(ctx, client, sources, srcArtifacts, srcOccurrences)
		if err != nil {
			return fmt.Errorf("isOccurrencesSrc failed with error: %w", err)
		}
	}
	if len(pkgs) > 0 {
		_, err := model.IsOccurrencesPkg(ctx, client, pkgs, pkgArtifacts, pkgOccurrences)
		if err != nil {
			return fmt.Errorf("isOccurrencesPkg failed with error: %w", err)
		}
	}
	return nil
}
