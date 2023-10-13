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
	"errors"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
)

// Internal data: Licenses
type licStruct struct {
	ThisID        string
	Name          string
	Inline        string
	ListVersion   string
	CertifyLegals []string
}

func (n *licStruct) ID() string { return n.ThisID }
func (n *licStruct) Key() string {
	return strings.Join([]string{
		n.Name,
		n.ListVersion,
	}, ":")
}

func (n *licStruct) Neighbors(allowedEdges edgeMap) []string {
	if allowedEdges[model.EdgeLicenseCertifyLegal] {
		return n.CertifyLegals
	}
	return nil
}

func (n *licStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convLicense(n), nil
}

func (n *licStruct) setCertifyLegals(ctx context.Context, id string, c *demoClient) error {
	n.CertifyLegals = append(n.CertifyLegals, id)
	return setkv(ctx, licenseCol, n, c)
}

func (c *demoClient) licenseByInput(ctx context.Context, b *model.LicenseInputSpec) (*licStruct, error) {
	in := &licStruct{
		Name:        b.Name,
		ListVersion: nilToEmpty(b.ListVersion),
	}
	return byKeykv[*licStruct](ctx, licenseCol, in.Key(), c)
}

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
	in := &licStruct{
		Name:        license.Name,
		Inline:      nilToEmpty(license.Inline),
		ListVersion: nilToEmpty(license.ListVersion),
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	out, err := byKeykv[*licStruct](ctx, licenseCol, in.Key(), c)
	if err == nil {
		return c.convLicense(out), nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return nil, err
	}
	if readOnly {
		c.m.RUnlock()
		a, err := c.ingestLicense(ctx, license, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return a, err
	}
	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, licenseCol, in); err != nil {
		return nil, err
	}
	if err := setkv(ctx, licenseCol, in, c); err != nil {
		return nil, err
	}

	return c.convLicense(in), nil
}

func (c *demoClient) licenseExact(ctx context.Context, licenseSpec *model.LicenseSpec) (*licStruct, error) {
	if licenseSpec == nil {
		return nil, nil
	}

	// If ID is provided, try to look up
	if licenseSpec.ID != nil {
		a, err := byIDkv[*licStruct](ctx, *licenseSpec.ID, c)
		if err == nil {
			// If found by id, ignore rest of fields in spec and return as a match
			return a, nil
		}
		if !errors.Is(err, kv.NotFoundError) && !errors.Is(err, errTypeNotMatch) {
			return nil, err
		}
		// Not found
		return nil, nil
	}

	if licenseSpec.Name != nil {
		in := &licStruct{
			Name:        *licenseSpec.Name,
			ListVersion: nilToEmpty(licenseSpec.ListVersion),
		}
		out, err := byKeykv[*licStruct](ctx, licenseCol, in.Key(), c)
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, kv.NotFoundError) {
			return nil, err
		}
	}
	return nil, nil
}

// Query Licenses

func (c *demoClient) Licenses(ctx context.Context, licenseSpec *model.LicenseSpec) ([]*model.License, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	a, err := c.licenseExact(ctx, licenseSpec)
	if err != nil {
		return nil, gqlerror.Errorf("Licenses :: invalid spec %s", err)
	}
	if a != nil {
		return []*model.License{c.convLicense(a)}, nil
	}

	var rv []*model.License
	lKeys, err := c.kv.Keys(ctx, licenseCol)
	if err != nil {
		return nil, err
	}
	for _, lk := range lKeys {
		l, err := byKeykv[*licStruct](ctx, licenseCol, lk, c)
		if err != nil {
			return nil, err
		}
		if noMatch(licenseSpec.Name, l.Name) ||
			noMatch(licenseSpec.ListVersion, l.ListVersion) ||
			noMatch(licenseSpec.Inline, l.Inline) {
			continue
		}
		rv = append(rv, c.convLicense(l))
	}
	return rv, nil
}

func (c *demoClient) convLicense(a *licStruct) *model.License {
	rv := &model.License{
		ID:   a.ThisID,
		Name: a.Name,
	}
	if a.Inline != "" {
		rv.Inline = &a.Inline
	}
	if a.ListVersion != "" {
		rv.ListVersion = &a.ListVersion
	}
	return rv
}
