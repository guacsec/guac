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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllOSV(client *demoClient) {
	client.registerOSV("CVE-2019-13110")
	client.registerOSV("CVE-2014-8139")
	client.registerOSV("CVE-2014-8140")
	client.registerOSV("CVE-2022-26499")
	client.registerOSV("CVE-2014-8140")
}

func (c *demoClient) registerOSV(id string) {
	for i, o := range c.osv {
		c.osv[i] = registerOsvID(o, id)
		return
	}

	newOsv := &model.Osv{}
	newOsv = registerOsvID(newOsv, id)
	c.osv = append(c.osv, newOsv)
}

func registerOsvID(o *model.Osv, id string) *model.Osv {
	for _, cveID := range o.OsvID {
		if cveID.ID == id {
			return o
		}
	}

	o.OsvID = append(o.OsvID, &model.OSVId{ID: id})
	return o
}
