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

package keyvalue

import (
	"context"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: Licenses
type licMap map[string]*licStruct
type licStruct struct {
	id            string
	name          string
	inline        string
	listVersion   string
	certifyLegals []string
}

func (n *licStruct) ID() string { return n.id }

func (n *licStruct) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeLicenseCertifyLegal] {
		return n.certifyLegals
	}
	return nil
}

func (n *licStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convLicense(n), nil
}

func (n *licStruct) setCertifyLegals(id string) { n.certifyLegals = append(n.certifyLegals, id) }

// Ingest Licenses

func (c *demoClient) IngestLicenses(ctx context.Context, licenses []*model.LicenseInputSpec) ([]*model.License, error) {
	var modelLicenses []*model.License
	for _, lic := range licenses {
		modelLic, err := c.IngestLicense(ctx, lic)
		if err != nil {
			return nil, gqlerror.Errorf("ingestLicense failed with err: %v", err)
		}
		modelLicenses = append(modelLicenses, modelLic)
	}
	return modelLicenses, nil
}

func (c *demoClient) IngestLicense(ctx context.Context, license *model.LicenseInputSpec) (*model.License, error) {
	return c.ingestLicense(ctx, license, true)
}

func (c *demoClient) ingestLicense(ctx context.Context, license *model.LicenseInputSpec, readOnly bool) (*model.License, error) {
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	a, ok := c.licenses[licenseKey(license.Name, license.ListVersion)]
	if !ok {
		if readOnly {
			c.m.RUnlock()
			a, err := c.ingestLicense(ctx, license, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return a, err
		}
		a = &licStruct{
			id:   c.getNextID(),
			name: license.Name,
		}
		if license.Inline != nil {
			a.inline = *license.Inline
		}
		if license.ListVersion != nil {
			a.listVersion = *license.ListVersion
		}
		c.index[a.id] = a
		c.licenses[licenseKey(license.Name, license.ListVersion)] = a
	}

	return c.convLicense(a), nil
}

func licenseKey(name string, listVersion *string) string {
	key := name
	if !strings.HasPrefix(name, "LicenseRef") {
		key = strings.Join([]string{name, *listVersion}, ":")
	}
	return key
}

func (c *demoClient) licenseExact(licenseSpec *model.LicenseSpec) (*licStruct, error) {

	// If ID is provided, try to look up
	if licenseSpec.ID != nil {
		a, err := byID[*licStruct](*licenseSpec.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		return a, nil
	}

	if licenseSpec.Name != nil && strings.HasPrefix(*licenseSpec.Name, "LicenseRef") {
		if l, ok := c.licenses[licenseKey(*licenseSpec.Name, nil)]; ok {
			if licenseSpec.Inline == nil ||
				(licenseSpec.Inline != nil && *licenseSpec.Inline == l.inline) {
				return l, nil
			}
		}
	}
	if licenseSpec.Name != nil &&
		!strings.HasPrefix(*licenseSpec.Name, "LicenseRef") &&
		licenseSpec.ListVersion != nil &&
		licenseSpec.Inline == nil {
		if l, ok := c.licenses[licenseKey(*licenseSpec.Name, licenseSpec.ListVersion)]; ok {
			return l, nil
		}
	}
	return nil, nil
}

// Query Licenses

func (c *demoClient) Licenses(ctx context.Context, licenseSpec *model.LicenseSpec) ([]*model.License, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	a, err := c.licenseExact(licenseSpec)
	if err != nil {
		return nil, gqlerror.Errorf("Licenses :: invalid spec %s", err)
	}
	if a != nil {
		return []*model.License{c.convLicense(a)}, nil
	}

	var rv []*model.License
	for _, l := range c.licenses {
		if noMatch(licenseSpec.Name, l.name) ||
			noMatch(licenseSpec.ListVersion, l.listVersion) ||
			noMatch(licenseSpec.Inline, l.inline) {
			continue
		}
		rv = append(rv, c.convLicense(l))
	}
	return rv, nil
}

func (c *demoClient) convLicense(a *licStruct) *model.License {
	rv := &model.License{
		ID:   a.id,
		Name: a.name,
	}
	if a.inline != "" {
		rv.Inline = &a.inline
	}
	if a.listVersion != "" {
		rv.ListVersion = &a.listVersion
	}
	return rv
}
