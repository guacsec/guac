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
	"fmt"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

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

	for _, depComp := range d.packComponent.DepPackages {
		appendPredicates(depComp, preds)
	}

	for _, isDepComp := range d.packComponent.IsDepPackages {
		preds.IsDependency = append(preds.IsDependency, assembler.IsDependencyIngest{
			Pkg:             isDepComp.CurrentPackageInput,
			DepPkg:          isDepComp.DepPackageInput,
			DepPkgMatchFlag: common.GetMatchFlagsFromPkgInput(isDepComp.DepPackageInput),
			IsDependency:    isDepComp.IsDependency,
		})
	}
	preds.HasSBOM = append(preds.HasSBOM, common.CreateTopLevelHasSBOM(d.packComponent.CurrentPackage, d.doc, helpers.PkgInputSpecToPurl(d.packComponent.CurrentPackage), d.packComponent.UpdateTime))

	return preds
}

func appendPredicates(packComponent *deps_dev.PackageComponent, preds *assembler.IngestPredicates) {
	hasSourceAt := createHasSourceAtIngest(packComponent.CurrentPackage, packComponent.Source, packComponent.UpdateTime.UTC())
	scorecard := createScorecardIngest(packComponent.Source, packComponent.Scorecard)
	if hasSourceAt != nil {
		preds.HasSourceAt = append(preds.HasSourceAt, *hasSourceAt)
	}
	if scorecard != nil {
		preds.CertifyScorecard = append(preds.CertifyScorecard, *scorecard)
	}
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

func createScorecardIngest(src *model.SourceInputSpec, scorecard *model.ScorecardInputSpec) *assembler.CertifyScorecardIngest {
	if src != nil && scorecard != nil {
		return &assembler.CertifyScorecardIngest{
			Source:    src,
			Scorecard: scorecard,
		}
	}
	return nil
}

func (d *depsDevParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	return nil
}

func (d *depsDevParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	idstrings := &common.IdentifierStrings{}
	for _, depComp := range d.packComponent.DepPackages {
		pkg := depComp.CurrentPackage
		idstrings.PurlStrings = append(idstrings.PurlStrings, helpers.PkgInputSpecToPurl(pkg))
	}
	return idstrings, nil
}
