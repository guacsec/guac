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

package testing

import (
	"context"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllCVE(client *demoClient) {
	client.registerCVE("2019", "CVE-2019-13110")
	client.registerCVE("2014", "CVE-2014-8139")
	client.registerCVE("2014", "CVE-2014-8140")
	client.registerCVE("2022", "CVE-2022-26499")
	client.registerCVE("2014", "CVE-2014-8140")
}

// Ingest CVE

func (c *demoClient) registerCVE(year, id string) {
	idLower := strings.ToLower(id)
	for i, s := range c.cve {
		if s.Year == year {
			c.cve[i] = registerCveID(s, idLower)
			return
		}
	}

	newCve := &model.Cve{Year: year}
	newCve = registerCveID(newCve, idLower)
	c.cve = append(c.cve, newCve)
}

func registerCveID(c *model.Cve, id string) *model.Cve {
	for _, cveID := range c.CveID {
		if cveID.ID == id {
			return c
		}
	}

	c.CveID = append(c.CveID, &model.CVEId{ID: id})
	return c
}

// Query CVE

func (c *demoClient) Cve(ctx context.Context, cveSpec *model.CVESpec) ([]*model.Cve, error) {
	var cve []*model.Cve
	for _, s := range c.cve {
		if cveSpec.Year == nil || s.Year == *cveSpec.Year {
			newCve, err := filterCVEID(s, cveSpec)
			if err != nil {
				return nil, err
			}
			if newCve != nil {
				cve = append(cve, newCve)
			}
		}
	}
	return cve, nil
}

func filterCVEID(cve *model.Cve, cveSpec *model.CVESpec) (*model.Cve, error) {
	var cveID []*model.CVEId
	for _, id := range cve.CveID {
		if cveSpec.CveID == nil || id.ID == strings.ToLower(*cveSpec.CveID) {
			cveID = append(cveID, id)
		}
	}
	if len(cveID) == 0 {
		return nil, nil
	}
	return &model.Cve{
		Year:  cve.Year,
		CveID: cveID,
	}, nil
}
