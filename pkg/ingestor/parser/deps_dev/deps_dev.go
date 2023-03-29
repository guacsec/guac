//
// Copyright 2022 The GUAC Authors.
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

package deps_dev

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/certifier/osv"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

type depsDevParser struct {
	doc           *processor.Document
	packComponent *deps_dev.PackageComponent
}

func NewDepsDevParser() common.DocumentParser {
	return &depsDevParser{}
}

func (d *depsDevParser) Parse(ctx context.Context, doc *processor.Document) error {
	d.doc = doc
	packComponent, err := parseDepsDevBlob(doc.Blob)
	if err != nil {
		return fmt.Errorf("failed to parse deps.dev document: %w", err)
	}
	d.packComponent = packComponent
	return nil
}

func parseDepsDevBlob(p []byte) (*deps_dev.PackageComponent, error) {
	packageComponent := deps_dev.PackageComponent{}
	if err := json.Unmarshal(p, &packageComponent); err != nil {
		return nil, err
	}
	return &packageComponent, nil
}

func (d *depsDevParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	preds := &assembler.IngestPredicates{}

	depPackages := []*model.PkgInputSpec{}
	for _, depComp := range d.packComponent.DepPackages {
		depPackages = append(depPackages, depComp.CurrentPackage)
		hasSourceAt := createHasSourceAtIngest(depComp.CurrentPackage, depComp.Source, depComp.UpdateTime.UTC())
		scorecard := createScorecardIngest(depComp.Source, depComp.Scorecard)
		isVulnList := createIsVulnerabilityIngest(depComp.Vulnerabilities)
		certifyVulnList := createCertifyVulnerabilityIngest(depComp.CurrentPackage, depComp.Vulnerabilities, depComp.UpdateTime.UTC())

		preds.HasSourceAt = append(preds.HasSourceAt, hasSourceAt)
		preds.CertifyScorecard = append(preds.CertifyScorecard, scorecard)
		preds.IsVuln = append(preds.IsVuln, isVulnList...)
		preds.CertifyVuln = append(preds.CertifyVuln, certifyVulnList...)
	}
	preds.IsDependency = append(preds.IsDependency, createTopLevelIsDeps(d.packComponent.CurrentPackage, depPackages)...)

	return preds
}

func createHasSourceAtIngest(pkg *model.PkgInputSpec, src *model.SourceInputSpec, knownSince time.Time) assembler.HasSourceAtIngest {
	return assembler.HasSourceAtIngest{
		Pkg: pkg,
		PkgMatchFlag: model.MatchFlags{
			Pkg: model.PkgMatchTypeAllVersions,
		},
		Src: src,
		HasSourceAt: &model.HasSourceAtInputSpec{
			KnownSince:    knownSince,
			Justification: "collected via deps.dev",
			Origin:        deps_dev.DepsCollector,
			Collector:     deps_dev.DepsCollector,
		},
	}
}

func createCertifyVulnerabilityIngest(pkg *model.PkgInputSpec, osvList []*model.OSVInputSpec, knownSince time.Time) []assembler.CertifyVulnIngest {
	var cvi []assembler.CertifyVulnIngest
	for _, o := range osvList {
		cv := assembler.CertifyVulnIngest{
			Pkg: pkg,
			OSV: o,
			VulnData: &model.VulnerabilityMetaDataInput{
				TimeScanned:    knownSince,
				DbUri:          "",
				DbVersion:      "",
				ScannerUri:     osv.URI,
				ScannerVersion: "",
				Origin:         deps_dev.DepsCollector,
				Collector:      deps_dev.DepsCollector,
			},
		}
		cvi = append(cvi, cv)
	}
	return cvi
}

func createIsVulnerabilityIngest(osvList []*model.OSVInputSpec) []assembler.IsVulnIngest {
	var ivs []assembler.IsVulnIngest
	for _, osv := range osvList {
		cve, ghsa, err := helpers.OSVToGHSACVE(osv.OsvId)
		if err != nil {
			continue
		}
		iv := assembler.IsVulnIngest{
			OSV:  osv,
			CVE:  cve,
			GHSA: ghsa,
			IsVuln: &model.IsVulnerabilityInputSpec{
				Justification: "decoded OSV data collected via deps.dev",
			},
		}
		ivs = append(ivs, iv)
	}
	return ivs
}

func createScorecardIngest(src *model.SourceInputSpec, scorecard *model.ScorecardInputSpec) assembler.CertifyScorecardIngest {
	return assembler.CertifyScorecardIngest{
		Source:    src,
		Scorecard: scorecard,
	}
}

func createTopLevelIsDeps(toplevel *model.PkgInputSpec, packages []*model.PkgInputSpec) []assembler.IsDependencyIngest {
	isDeps := []assembler.IsDependencyIngest{}
	for _, packNode := range packages {
		if !reflect.DeepEqual(*packNode, *toplevel) {
			p := assembler.IsDependencyIngest{
				Pkg:    toplevel,
				DepPkg: packNode,
				IsDependency: &model.IsDependencyInputSpec{
					Justification: "dependency data collected via deps.dev",
					VersionRange:  *packNode.Version,
					Origin:        deps_dev.DepsCollector,
					Collector:     deps_dev.DepsCollector,
				},
			}
			isDeps = append(isDeps, p)
		}
	}
	return isDeps
}

func (d *depsDevParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (d *depsDevParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	return nil, fmt.Errorf("not yet implemented")
}
