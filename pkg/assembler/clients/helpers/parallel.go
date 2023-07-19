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
		nouns, errGroupNounCtx := errgroup.WithContext(ctx)

		// Backend can only process one write at a time, but make
		// sure there are enough in flight so we don't wait for any round trips.
		nouns.SetLimit(20)

		for _, p := range preds {
			packages := p.GetPackages(errGroupNounCtx)
			logger.Infof("assembling Package: %v", len(packages))
			for _, v := range packages {
				if errGroupNounCtx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestPackage(errGroupNounCtx, gqlclient, v) })
			}

			sources := p.GetSources(errGroupNounCtx)
			logger.Infof("assembling Source: %v", len(sources))
			for _, v := range sources {
				if errGroupNounCtx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestSource(errGroupNounCtx, gqlclient, v) })
			}

			artifacts := p.GetArtifacts(errGroupNounCtx)
			logger.Infof("assembling Artifact: %v", len(artifacts))
			for _, v := range artifacts {
				if errGroupNounCtx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestArtifact(errGroupNounCtx, gqlclient, v) })
			}

			builders := p.GetBuilders(errGroupNounCtx)
			logger.Infof("assembling Builder: %v", len(builders))
			for _, v := range builders {
				if errGroupNounCtx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestBuilder(errGroupNounCtx, gqlclient, v) })
			}

			materials := p.GetMaterials(errGroupNounCtx)
			logger.Infof("assembling Materials: %v", len(materials))
			nouns.Go(func() error { return ingestMaterials(errGroupNounCtx, gqlclient, materials) })

			cves := p.GetCVEs(errGroupNounCtx)
			logger.Infof("assembling CVE: %v", len(cves))
			for _, v := range cves {
				if errGroupNounCtx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestCVE(errGroupNounCtx, gqlclient, v) })
			}

			osvs := p.GetOSVs(errGroupNounCtx)
			logger.Infof("assembling OSV: %v", len(osvs))
			for _, v := range osvs {
				if errGroupNounCtx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestOSV(errGroupNounCtx, gqlclient, v) })
			}

			ghsas := p.GetGHSAs(errGroupNounCtx)
			logger.Infof("assembling GHSA: %v", len(ghsas))
			for _, v := range ghsas {
				if errGroupNounCtx.Err() != nil {
					break
				}
				v := v
				nouns.Go(func() error { return ingestGHSA(errGroupNounCtx, gqlclient, v) })
			}
		}

		if err := nouns.Wait(); err != nil {
			return err
		}

		verbs, errGroupVerbCtx := errgroup.WithContext(ctx)

		// Backend can only process one write at a time, but make
		// sure there are enough in flight so we don't wait for any round trips.
		verbs.SetLimit(20)

		for _, p := range preds {
			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			for _, v := range p.CertifyScorecard {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				v := v
				verbs.Go(func() error { return ingestCertifyScorecard(errGroupVerbCtx, gqlclient, v) })
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			for _, v := range p.IsDependency {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				v := v
				verbs.Go(func() error { return ingestIsDependency(errGroupVerbCtx, gqlclient, v) })
			}

			logger.Infof("assembling IsOccurrence: %v", len(p.IsOccurrence))
			for _, v := range p.IsOccurrence {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				v := v
				verbs.Go(func() error { return ingestIsOccurrence(errGroupVerbCtx, gqlclient, v) })
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			for _, v := range p.HasSlsa {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				v := v
				verbs.Go(func() error { return ingestHasSlsa(errGroupVerbCtx, gqlclient, v) })
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			for _, cv := range p.CertifyVuln {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				cv := cv
				verbs.Go(func() error { return ingestCertifyVuln(errGroupVerbCtx, gqlclient, cv) })
			}

			logger.Infof("assembling IsVuln: %v", len(p.IsVuln))
			for _, iv := range p.IsVuln {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				iv := iv
				verbs.Go(func() error { return ingestIsVuln(errGroupVerbCtx, gqlclient, iv) })
			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			for _, hsa := range p.HasSourceAt {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				hsa := hsa
				verbs.Go(func() error { return hasSourceAt(errGroupVerbCtx, gqlclient, hsa) })
			}

			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			for _, bad := range p.CertifyBad {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				bad := bad
				verbs.Go(func() error { return ingestCertifyBad(errGroupVerbCtx, gqlclient, bad) })
			}

			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			for _, good := range p.CertifyGood {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				good := good
				verbs.Go(func() error { return ingestCertifyGood(errGroupVerbCtx, gqlclient, good) })
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			for _, hb := range p.HasSBOM {
				if errGroupVerbCtx.Err() != nil {
					break
				}
				hb := hb
				verbs.Go(func() error { return ingestHasSBOM(errGroupVerbCtx, gqlclient, hb) })
			}
		}

		return verbs.Wait()
	}
}
