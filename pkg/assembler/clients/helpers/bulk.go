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

			// TODO(pxp928): add bulk ingestion for sources
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

			// TODO(pxp928): add bulk ingestion for builders
			builders := p.GetBuilders(ctx)
			logger.Infof("assembling Builder: %v", len(builders))
			for _, v := range builders {
				if err := ingestBuilder(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("ingestBuilder failed with error: %w", err)
				}
			}

			// TODO(pxp928): add bulk ingestion for materials
			materials := p.GetMaterials(ctx)
			logger.Infof("assembling Materials (Artifact): %v", len(materials))
			if err := ingestMaterials(ctx, gqlclient, materials); err != nil {
				return fmt.Errorf("ingestMaterials failed with error: %w", err)
			}

			// TODO(pxp928): add bulk ingestion for cves
			cves := p.GetCVEs(ctx)
			logger.Infof("assembling CVE: %v", len(cves))
			for _, v := range cves {
				if err := ingestCVE(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("ingestCVE failed with error: %w", err)
				}
			}

			// TODO(pxp928): add bulk ingestion for osvs
			osvs := p.GetOSVs(ctx)
			logger.Infof("assembling OSV: %v", len(osvs))
			for _, v := range osvs {
				if err := ingestOSV(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("ingestOSV failed with error: %w", err)
				}
			}

			// TODO(pxp928): add bulk ingestion for ghsas
			ghsas := p.GetGHSAs(ctx)
			logger.Infof("assembling GHSA: %v", len(ghsas))
			for _, v := range ghsas {
				if err := ingestGHSA(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("ingestGHSA failed with error: %w", err)
				}
			}

			// TODO(pxp928): add bulk ingestion for CertifyScorecard
			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			for _, v := range p.CertifyScorecard {
				if err := ingestCertifyScorecards(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("ingestCertifyScorecards failed with error: %w", err)
				}
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			if err := ingestIsDependencies(ctx, gqlclient, p.IsDependency); err != nil {
				return fmt.Errorf("ingestIsDependencies failed with error: %w", err)
			}

			logger.Infof("assembling IsOccurrence: %v", len(p.IsOccurrence))
			if err := ingestIsOccurrences(ctx, gqlclient, p.IsOccurrence); err != nil {
				return fmt.Errorf("ingestIsOccurrences failed with error: %w", err)
			}

			// TODO(pxp928): add bulk ingestion for HasSLSA
			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			for _, v := range p.HasSlsa {
				if err := ingestHasSlsa(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("ingestHasSlsa failed with error: %w", err)
				}
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

			// TODO(pxp928): add bulk ingestion for HasSBOM
			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			for _, hb := range p.HasSBOM {
				if err := ingestHasSBOM(ctx, gqlclient, hb); err != nil {
					return fmt.Errorf("ingestHasSBOM failed with error: %w", err)

				}
			}

			// TODO(pxp928): add bulk ingestion for VEX
			logger.Infof("assembling VEX : %v", len(p.Vex))
			for _, v := range p.Vex {
				if err := ingestVex(ctx, gqlclient, v); err != nil {
					return fmt.Errorf("ingestVex failed with error: %w", err)

				}
			}

			// TODO(pxp928): add bulk ingestion for HashEqual
			logger.Infof("assembling HashEqual : %v", len(p.HashEqual))
			for _, equal := range p.HashEqual {
				if err := ingestHashEqual(ctx, gqlclient, equal); err != nil {
					return fmt.Errorf("ingestHashEqual failed with error: %w", err)

				}
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

func ingestIsOccurrences(ctx context.Context, client graphql.Client, v []assembler.IsOccurrenceIngest) error {
	var pkgs []model.PkgInputSpec
	var sources []model.SourceInputSpec
	var artifacts []model.ArtifactInputSpec
	var occurrences []model.IsOccurrenceInputSpec
	for _, ingest := range v {

		if ingest.Pkg != nil && ingest.Src != nil {
			return fmt.Errorf("unable to create IsOccurrence with both Src and Pkg subject specified")
		}
		if ingest.Pkg == nil && ingest.Src == nil {
			return fmt.Errorf("unable to create IsOccurrence without either Src and Pkg subject specified")
		}

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
		if err != nil {
			return fmt.Errorf("isOccurrencesSrc failed with error: %w", err)
		}

	}
	if len(pkgs) > 0 {
		_, err := model.IsOccurrencesPkg(ctx, client, pkgs, artifacts, occurrences)
		if err != nil {
			return fmt.Errorf("isOccurrencesPkg failed with error: %w", err)
		}
	}
	return nil
}
