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

	"github.com/Khan/genqlient/graphql"
	"golang.org/x/sync/errgroup"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/logging"
)

func GetParallelAssembler(ctx context.Context, gqlclient graphql.Client) func([]assembler.AssemblerInput) error {
	logger := logging.FromContext(ctx)
	// Assume docs are big and each call to the assembler is large, make each
	// assemble function call block, but the ingests within the call happen in
	// parallel.

	return func(preds []assembler.AssemblerInput) error {
		nouns, ctx := errgroup.WithContext(ctx)

		// Backend can only process one write at a time, but make
		// sure there are enough in flight so we don't wait for any round trips.
		nouns.SetLimit(20)

		for _, p := range preds {
			packages := p.GetPackages(ctx)
			logger.Infof("assembling Package: %v", len(packages))
			for _, v := range packages {
				if ctx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestPackage(ctx, gqlclient, v) })
			}

			sources := p.GetSources(ctx)
			logger.Infof("assembling Source: %v", len(sources))
			for _, v := range sources {
				if ctx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestSource(ctx, gqlclient, v) })
			}

			artifacts := p.GetArtifacts(ctx)
			logger.Infof("assembling Artifact: %v", len(artifacts))
			for _, v := range artifacts {
				if ctx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestArtifact(ctx, gqlclient, v) })
			}

			builders := p.GetBuilders(ctx)
			logger.Infof("assembling Builder: %v", len(builders))
			for _, v := range builders {
				if ctx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestBuilder(ctx, gqlclient, v) })
			}

			materials := p.GetMaterials(ctx)
			logger.Infof("assembling Materials: %v", len(materials))
			nouns.Go(func() error { return ingestMaterials(ctx, gqlclient, materials) })

			cves := p.GetCVEs(ctx)
			logger.Infof("assembling CVE: %v", len(cves))
			for _, v := range cves {
				if ctx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestCVE(ctx, gqlclient, v) })
			}

			osvs := p.GetOSVs(ctx)
			logger.Infof("assembling OSV: %v", len(osvs))
			for _, v := range osvs {
				if ctx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestOSV(ctx, gqlclient, v) })
			}

			ghsas := p.GetGHSAs(ctx)
			logger.Infof("assembling GHSA: %v", len(ghsas))
			for _, v := range ghsas {
				if ctx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestGHSA(ctx, gqlclient, v) })
			}
		}

		if err := nouns.Wait(); err != nil {
			return err
		}

		verbs, ctx := errgroup.WithContext(ctx)

		// Backend can only process one write at a time, but make
		// sure there are enough in flight so we don't wait for any round trips.
		verbs.SetLimit(20)

		for _, p := range preds {
			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			for _, v := range p.CertifyScorecard {
				if ctx.Err() != nil {
					break
				}
				v := v
				verbs.Go(func() error { return ingestCertifyScorecards(ctx, gqlclient, v) })
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			for _, v := range p.IsDependency {
				if ctx.Err() != nil {
					break
				}
				v := v
				verbs.Go(func() error { return ingestIsDependency(ctx, gqlclient, v) })
			}

			logger.Infof("assembling IsOccurence: %v", len(p.IsOccurrence))
			for _, v := range p.IsOccurrence {
				if ctx.Err() != nil {
					break
				}
				v := v
				verbs.Go(func() error { return ingestIsOccurrence(ctx, gqlclient, v) })
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			for _, v := range p.HasSlsa {
				if ctx.Err() != nil {
					break
				}
				v := v
				verbs.Go(func() error { return ingestHasSlsa(ctx, gqlclient, v) })
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			for _, cv := range p.CertifyVuln {
				if ctx.Err() != nil {
					break
				}
				cv := cv
				verbs.Go(func() error { return ingestCertifyVuln(ctx, gqlclient, cv) })
			}

			logger.Infof("assembling IsVuln: %v", len(p.IsVuln))
			for _, iv := range p.IsVuln {
				if ctx.Err() != nil {
					break
				}
				iv := iv
				verbs.Go(func() error { return ingestIsVuln(ctx, gqlclient, iv) })
			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			for _, hsa := range p.HasSourceAt {
				if ctx.Err() != nil {
					break
				}
				hsa := hsa
				verbs.Go(func() error { return hasSourceAt(ctx, gqlclient, hsa) })
			}

			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			for _, bad := range p.CertifyBad {
				if ctx.Err() != nil {
					break
				}
				bad := bad
				verbs.Go(func() error { return ingestCertifyBad(ctx, gqlclient, bad) })
			}

			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			for _, good := range p.CertifyGood {
				if ctx.Err() != nil {
					break
				}
				good := good
				verbs.Go(func() error { return ingestCertifyGood(ctx, gqlclient, good) })
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			for _, hb := range p.HasSBOM {
				if ctx.Err() != nil {
					break
				}
				hb := hb
				verbs.Go(func() error { return ingestHasSBOM(ctx, gqlclient, hb) })
			}
		}

		return verbs.Wait()
	}
}
