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

package arangodb

import (
	"context"
	"fmt"
	"sort"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
)

func (c *arangoClient) PkgEqual(ctx context.Context, pkgEqualSpec *model.PkgEqualSpec) ([]*model.PkgEqual, error) {
	panic(fmt.Errorf("not implemented: PkgEqual - PkgEqual"))
}

func getPkgEqualQueryValues(currentPkg *model.PkgInputSpec, otherPkg *model.PkgInputSpec, pkgEqual *model.PkgEqualInputSpec) map[string]any {

	pkgPurl := helpers.PkgInputSpecToPurl(currentPkg)

	pkgsMap := make(map[string]*model.PkgInputSpec, 2)
	var purls []string
	purls = append(purls, pkgPurl)

	sort.Strings(purls)
	qualifiers := []string{}
	for _, k := range purls {
		qualifiers = append(qualifiers, k, pkgsMap[k])
	}

	values := map[string]any{}
	// add guac keys
	vuln := guacVulnId(pkgs[0])
	values["guacVulnKey"] = vuln.VulnerabilityID

	equalVuln := guacVulnId(pkgs[1])
	values["equalGuacVulnKey"] = equalVuln.VulnerabilityID

	values[justification] = vulnEqual.Justification
	values[origin] = vulnEqual.Origin
	values[collector] = vulnEqual.Collector

	return values
}

func (c *arangoClient) IngestPkgEquals(ctx context.Context, pkgs []*model.PkgInputSpec, otherPackages []*model.PkgInputSpec, pkgEquals []*model.PkgEqualInputSpec) ([]string, error) {
	return nil, fmt.Errorf("not implemented - IngestPkgEquals")
}

func (c *arangoClient) IngestPkgEqual(ctx context.Context, pkg model.PkgInputSpec, depPkg model.PkgInputSpec, pkgEqual model.PkgEqualInputSpec) (*model.PkgEqual, error) {
	panic(fmt.Errorf("not implemented: IngestPkgEqual - IngestPkgEqual"))
}
