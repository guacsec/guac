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

	// create and append predicates for the top level package
	appendPredicates(d.packComponent, preds)

	depPackages := []*model.PkgInputSpec{}
	for _, depComp := range d.packComponent.DepPackages {
		depPackages = append(depPackages, depComp.CurrentPackage)

		// create and append predicates for dependent packages
		appendPredicates(depComp, preds)

	}
	preds.IsDependency = append(preds.IsDependency, createTopLevelIsDeps(d.packComponent.CurrentPackage, depPackages)...)

	return preds
}

func appendPredicates(packComponent *deps_dev.PackageComponent, preds *assembler.IngestPredicates) {
	hasSourceAt := createHasSourceAtIngest(packComponent.CurrentPackage, packComponent.Source, packComponent.UpdateTime.UTC())
	scorecard := createScorecardIngest(packComponent.Source, packComponent.Scorecard)
	isVulnList := createIsVulnerabilityIngest(packComponent.Vulnerabilities)
	certifyVulnList := createCertifyVulnerabilityIngest(packComponent.CurrentPackage, packComponent.Vulnerabilities, packComponent.UpdateTime.UTC())

	if hasSourceAt != nil {
		preds.HasSourceAt = append(preds.HasSourceAt, *hasSourceAt)
	}
	if scorecard != nil {
		preds.CertifyScorecard = append(preds.CertifyScorecard, *scorecard)
	}
	preds.IsVuln = append(preds.IsVuln, isVulnList...)
	preds.CertifyVuln = append(preds.CertifyVuln, certifyVulnList...)
}

func createHasSourceAtIngest(pkg *model.PkgInputSpec, src *model.SourceInputSpec, knownSince time.Time) *assembler.HasSourceAtIngest {
	if pkg != nil && src != nil {
		return &assembler.HasSourceAtIngest{
			Pkg: pkg,
			PkgMatchFlag: model.MatchFlags{
				Pkg: model.PkgMatchTypeAllVersions,
			},
			Src: src,
			HasSourceAt: &model.HasSourceAtInputSpec{
				KnownSince:    knownSince,
				Justification: "collected via deps.dev",
			},
		}
	}
	return nil
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

func createScorecardIngest(src *model.SourceInputSpec, scorecard *model.ScorecardInputSpec) *assembler.CertifyScorecardIngest {
	if src != nil && scorecard != nil {
		return &assembler.CertifyScorecardIngest{
			Source:    src,
			Scorecard: scorecard,
		}
	}
	return nil
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
