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
	"sort"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
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
	visited := map[string]bool{}
	// create and append predicates for the top level package and all other packages below it (direct and indirect)
	appendPredicates(d.packComponent, preds, visited)
	return preds
}

func appendPredicates(packComponent *deps_dev.PackageComponent, preds *assembler.IngestPredicates, visited map[string]bool) {
	currentPkgPurl := pkgInputSpecToPurl(packComponent.CurrentPackage)
	if _, ok := visited[currentPkgPurl]; ok {
		return
	}
	hasSourceAt := createHasSourceAtIngest(packComponent.CurrentPackage, packComponent.Source, packComponent.UpdateTime.UTC())
	scorecard := createScorecardIngest(packComponent.Source, packComponent.Scorecard)
	if hasSourceAt != nil {
		preds.HasSourceAt = append(preds.HasSourceAt, *hasSourceAt)
	}
	if scorecard != nil {
		preds.CertifyScorecard = append(preds.CertifyScorecard, *scorecard)
	}

	for _, depComp := range packComponent.DepPackages {
		preds.IsDependency = append(preds.IsDependency, assembler.IsDependencyIngest{
			Pkg:          packComponent.CurrentPackage,
			DepPkg:       depComp.DepPackageComponent.CurrentPackage,
			IsDependency: depComp.IsDependency,
		})
		appendPredicates(depComp.DepPackageComponent, preds, visited)
	}
	visited[currentPkgPurl] = true
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
		pkg := depComp.DepPackageComponent.CurrentPackage
		idstrings.PurlStrings = append(idstrings.PurlStrings, pkgInputSpecToPurl(pkg))
	}
	return idstrings, nil
}

func pkgInputSpecToPurl(currentPkg *model.PkgInputSpec) string {
	qualifiersMap := map[string]string{}
	keys := []string{}
	for _, kv := range currentPkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	qualifiers := []string{}
	for _, k := range keys {
		qualifiers = append(qualifiers, k, qualifiersMap[k])
	}
	return helpers.PkgToPurl(currentPkg.Type, *currentPkg.Namespace, currentPkg.Name, *currentPkg.Version, *currentPkg.Subpath, qualifiers)
}
