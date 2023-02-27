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

func registerAllOSV(client *demoClient) {
	client.registerOSV("CVE-2019-13110")
	client.registerOSV("CVE-2014-8139")
	client.registerOSV("CVE-2014-8140")
	client.registerOSV("CVE-2022-26499")
	client.registerOSV("GHSA-h45f-rjvw-2rv2")
}

// Ingest OSV

func (c *demoClient) registerOSV(id string) *model.Osv {
	idLower := strings.ToLower(id)
	for i, o := range c.osv {
		c.osv[i] = registerOsvID(o, idLower)
		return c.osv[i]
	}

	newOsv := &model.Osv{}
	newOsv = registerOsvID(newOsv, idLower)
	c.osv = append(c.osv, newOsv)

	return newOsv
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

// Query OSV

func (c *demoClient) Osv(ctx context.Context, osvSpec *model.OSVSpec) ([]*model.Osv, error) {
	var osv []*model.Osv
	for _, o := range c.osv {
		newOSV, err := filterOSVID(o, osvSpec)
		if err != nil {
			return nil, err
		}
		if newOSV != nil {
			osv = append(osv, newOSV)
		}
	}
	return osv, nil
}

func filterOSVID(ghsa *model.Osv, osvSpec *model.OSVSpec) (*model.Osv, error) {
	var osvID []*model.OSVId
	for _, id := range ghsa.OsvID {
		if osvSpec.OsvID == nil || id.ID == strings.ToLower(*osvSpec.OsvID) {
			osvID = append(osvID, id)
		}
	}
	if len(osvID) == 0 {
		return nil, nil
	}
	return &model.Osv{
		OsvID: osvID,
	}, nil
}

func (c *demoClient) IngestOsv(ctx context.Context, osv *model.OSVInputSpec) (*model.Osv, error) {
	return c.registerOSV(osv.OsvID), nil
}
