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
		g, ctx := errgroup.WithContext(ctx)

		// Backend can only process one write at a time, but make
		// sure there are enough in flight so we don't wait for any round trips.
		g.SetLimit(20)

		for _, p := range preds {

			logger.Infof("assembling Package: %v", len(p.Package))
			for _, v := range p.Package {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestPackage(ctx, gqlclient, v) })
			}

			logger.Infof("assembling Source: %v", len(p.Source))
			for _, v := range p.Source {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestSource(ctx, gqlclient, v) })
			}

			logger.Infof("assembling Artifact: %v", len(p.Artifact))
			for _, v := range p.Artifact {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestArtifact(ctx, gqlclient, v) })
			}

			logger.Infof("assembling CVE: %v", len(p.CVE))
			for _, v := range p.CVE {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestCVE(ctx, gqlclient, v) })
			}

			logger.Infof("assembling OSV: %v", len(p.OSV))
			for _, v := range p.OSV {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestOSV(ctx, gqlclient, v) })
			}

			logger.Infof("assembling GHSA: %v", len(p.GHSA))
			for _, v := range p.GHSA {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestGHSA(ctx, gqlclient, v) })
			}

			logger.Infof("assembling CertifyScorecard: %v", len(p.CertifyScorecard))
			for _, v := range p.CertifyScorecard {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestCertifyScorecards(ctx, gqlclient, v) })
			}

			logger.Infof("assembling IsDependency: %v", len(p.IsDependency))
			for _, v := range p.IsDependency {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestIsDependency(ctx, gqlclient, v) })
			}

			logger.Infof("assembling IsOccurence: %v", len(p.IsOccurrence))
			for _, v := range p.IsOccurrence {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestIsOccurrence(ctx, gqlclient, v) })
			}

			logger.Infof("assembling HasSLSA: %v", len(p.HasSlsa))
			for _, v := range p.HasSlsa {
				if ctx.Err() != nil {
					break
				}
				v := v
				g.Go(func() error { return ingestHasSlsa(ctx, gqlclient, v) })
			}

			logger.Infof("assembling CertifyVuln: %v", len(p.CertifyVuln))
			for _, cv := range p.CertifyVuln {
				if ctx.Err() != nil {
					break
				}
				cv := cv
				g.Go(func() error { return ingestCertifyVuln(ctx, gqlclient, cv) })
			}

			logger.Infof("assembling IsVuln: %v", len(p.IsVuln))
			for _, iv := range p.IsVuln {
				if ctx.Err() != nil {
					break
				}
				iv := iv
				g.Go(func() error { return ingestIsVuln(ctx, gqlclient, iv) })
			}

			logger.Infof("assembling HasSourceAt: %v", len(p.HasSourceAt))
			for _, hsa := range p.HasSourceAt {
				if ctx.Err() != nil {
					break
				}
				hsa := hsa
				g.Go(func() error { return hasSourceAt(ctx, gqlclient, hsa) })
			}

			logger.Infof("assembling CertifyBad: %v", len(p.CertifyBad))
			for _, bad := range p.CertifyBad {
				if ctx.Err() != nil {
					break
				}
				bad := bad
				g.Go(func() error { return ingestCertifyBad(ctx, gqlclient, bad) })
			}

			logger.Infof("assembling CertifyGood: %v", len(p.CertifyGood))
			for _, good := range p.CertifyGood {
				if ctx.Err() != nil {
					break
				}
				good := good
				g.Go(func() error { return ingestCertifyGood(ctx, gqlclient, good) })
			}

			logger.Infof("assembling HasSBOM: %v", len(p.HasSBOM))
			for _, hb := range p.HasSBOM {
				if ctx.Err() != nil {
					break
				}
				hb := hb
				g.Go(func() error { return ingestHasSBOM(ctx, gqlclient, hb) })
			}

		}
		return g.Wait()
	}
}
