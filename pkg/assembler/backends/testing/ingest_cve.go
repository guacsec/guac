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

package backend

import (
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllCVE(client *demoClient) {
	client.registerCVE("1970", "CVE-2019-13110")
	client.registerCVE("2001", "CVE-2014-8139")
	client.registerCVE("1970", "CVE-2014-8140")
	client.registerCVE("2023", "CVE-2022-26499")
	client.registerCVE("1970", "CVE-2014-8140")
}

func (c *demoClient) registerCVE(year, id string) {
	for i, s := range c.cve {
		if s.Year == year {
			c.cve[i] = registerCveID(s, id)
			return
		}
	}

	newCve := &model.Cve{Year: year}
	newCve = registerCveID(newCve, id)
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
