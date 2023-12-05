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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/kv"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Internal certifyLegal

type certifyLegalStruct struct {
	ThisID             string
	Pkg                string
	Source             string
	DeclaredLicense    string
	DeclaredLicenses   []string
	DiscoveredLicense  string
	DiscoveredLicenses []string
	Attribution        string
	Justification      string
	TimeScanned        time.Time
	Origin             string
	Collector          string
}

func (n *certifyLegalStruct) ID() string { return n.ThisID }
func (n *certifyLegalStruct) Key() string {
	return strings.Join([]string{
		n.Pkg,
		n.Source,
		n.DeclaredLicense,
		fmt.Sprint(n.DeclaredLicenses),
		n.DiscoveredLicense,
		fmt.Sprint(n.DiscoveredLicenses),
		n.Attribution,
		n.Justification,
		timeKey(n.TimeScanned),
		n.Origin,
		n.Collector,
	}, ":")
}

func (n *certifyLegalStruct) Neighbors(allowedEdges edgeMap) []string {
	out := make([]string, 0, 2)
	if n.Pkg != "" && allowedEdges[model.EdgeCertifyLegalPackage] {
		out = append(out, n.Pkg)
	}
	if n.Source != "" && allowedEdges[model.EdgeCertifyLegalSource] {
		out = append(out, n.Source)
	}
	if allowedEdges[model.EdgeCertifyLegalLicense] {
		out = append(out, n.DeclaredLicenses...)
		out = append(out, n.DiscoveredLicenses...)
	}
	return out
}

func (n *certifyLegalStruct) BuildModelNode(ctx context.Context, c *demoClient) (model.Node, error) {
	return c.convLegal(ctx, n)
}

func (c *demoClient) IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.LicenseInputSpec, discoveredLicensesList [][]*model.LicenseInputSpec, certifyLegals []*model.CertifyLegalInputSpec) ([]string, error) {
	var rv []string

	for i, v := range certifyLegals {
		var l string
		var err error
		if len(subjects.Packages) > 0 {
			subject := model.PackageOrSourceInput{Package: subjects.Packages[i]}
			l, err = c.IngestCertifyLegal(ctx, subject, declaredLicensesList[i], discoveredLicensesList[i], v)
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyLegals failed with err: %v", err)
			}
		} else {
			subject := model.PackageOrSourceInput{Source: subjects.Sources[i]}
			l, err = c.IngestCertifyLegal(ctx, subject, declaredLicensesList[i], discoveredLicensesList[i], v)
			if err != nil {
				return nil, gqlerror.Errorf("IngestCertifyLegals failed with err: %v", err)
			}
		}
		rv = append(rv, l)
	}
	return rv, nil
}

func (c *demoClient) IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.LicenseInputSpec, discoveredLicenses []*model.LicenseInputSpec, certifyLegal *model.CertifyLegalInputSpec) (string, error) {
	return c.ingestCertifyLegal(ctx, subject, declaredLicenses, discoveredLicenses, certifyLegal, true)
}

func (c *demoClient) ingestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.LicenseInputSpec, discoveredLicenses []*model.LicenseInputSpec, certifyLegal *model.CertifyLegalInputSpec, readOnly bool) (string, error) {
	funcName := "IngestCertifyLegal"

	in := &certifyLegalStruct{
		DeclaredLicense:   certifyLegal.DeclaredLicense,
		DiscoveredLicense: certifyLegal.DiscoveredLicense,
		Attribution:       certifyLegal.Attribution,
		TimeScanned:       certifyLegal.TimeScanned.UTC(),
		Justification:     certifyLegal.Justification,
		Origin:            certifyLegal.Origin,
		Collector:         certifyLegal.Collector,
	}

	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var dec []string
	for _, lis := range declaredLicenses {
		l, err := c.licenseByInput(ctx, lis)
		if err != nil {
			return "", gqlerror.Errorf("%v :: License not found %q %v", funcName, lis.Name, err)
		}
		dec = append(dec, l.ThisID)
	}
	slices.Sort(dec)
	in.DeclaredLicenses = dec

	var dis []string
	for _, lis := range discoveredLicenses {
		l, err := c.licenseByInput(ctx, lis)
		if err != nil {
			return "", gqlerror.Errorf("%v :: License not found %q %v", funcName, lis.Name, err)
		}
		dis = append(dis, l.ThisID)
	}
	slices.Sort(dis)
	in.DiscoveredLicenses = dis

	var pkg *pkgVersion
	if subject.Package != nil {
		var err error
		pkg, err = c.getPackageVerFromInput(ctx, *subject.Package)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		in.Pkg = pkg.ThisID
	}

	var src *srcNameNode
	if subject.Source != nil {
		var err error
		src, err = c.getSourceNameFromInput(ctx, *subject.Source)
		if err != nil {
			return "", gqlerror.Errorf("%v :: %v", funcName, err)
		}
		in.Source = src.ThisID
	}

	out, err := byKeykv[*certifyLegalStruct](ctx, clCol, in.Key(), c)
	if err == nil {
		return out.ThisID, nil
	}
	if !errors.Is(err, kv.NotFoundError) {
		return "", err
	}

	if readOnly {
		c.m.RUnlock()
		o, err := c.ingestCertifyLegal(ctx, subject, declaredLicenses, discoveredLicenses, certifyLegal, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return o, err
	}
	in.ThisID = c.getNextID()

	if err := c.addToIndex(ctx, clCol, in); err != nil {
		return "", err
	}
	if pkg != nil {
		if err := pkg.setCertifyLegals(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	} else {
		if err := src.setCertifyLegals(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	for _, lid := range dec {
		l, err := byIDkv[*licStruct](ctx, lid, c)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		if err := l.setCertifyLegals(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	for _, lid := range dis {
		l, err := byIDkv[*licStruct](ctx, lid, c)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		if err := l.setCertifyLegals(ctx, in.ThisID, c); err != nil {
			return "", err
		}
	}
	if err := setkv(ctx, clCol, in, c); err != nil {
		return "", err
	}

	return in.ThisID, nil
}

func (c *demoClient) convLegal(ctx context.Context, in *certifyLegalStruct) (*model.CertifyLegal, error) {
	cl := &model.CertifyLegal{
		ID:                in.ThisID,
		DeclaredLicense:   in.DeclaredLicense,
		DiscoveredLicense: in.DiscoveredLicense,
		Attribution:       in.Attribution,
		Justification:     in.Justification,
		TimeScanned:       in.TimeScanned,
		Origin:            in.Origin,
		Collector:         in.Collector,
	}
	for _, lid := range in.DeclaredLicenses {
		l, err := byIDkv[*licStruct](ctx, lid, c)
		if err != nil {
			return nil, err
		}
		cl.DeclaredLicenses = append(cl.DeclaredLicenses, c.convLicense(l))
	}
	for _, lid := range in.DiscoveredLicenses {
		l, err := byIDkv[*licStruct](ctx, lid, c)
		if err != nil {
			return nil, err
		}
		cl.DiscoveredLicenses = append(cl.DiscoveredLicenses, c.convLicense(l))
	}
	if in.Pkg != "" {
		p, err := c.buildPackageResponse(ctx, in.Pkg, nil)
		if err != nil {
			return nil, err
		}
		cl.Subject = p
	} else {
		s, err := c.buildSourceResponse(ctx, in.Source, nil)
		if err != nil {
			return nil, err
		}
		cl.Subject = s
	}
	return cl, nil
}

func (c *demoClient) CertifyLegal(ctx context.Context, filter *model.CertifyLegalSpec) ([]*model.CertifyLegal, error) {
	funcName := "CertifyLegal"

	c.m.RLock()
	defer c.m.RUnlock()

	if filter != nil && filter.ID != nil {
		link, err := byIDkv[*certifyLegalStruct](ctx, *filter.ID, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		o, err := c.convLegal(ctx, link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyLegal{o}, nil
	}

	var search []string
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		pkgs, err := c.findPackageVersion(ctx, filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		foundOne = len(pkgs) > 0
		for _, pkg := range pkgs {
			search = append(search, pkg.CertifyLegals...)
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(ctx, filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.CertifyLegals...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil {
		for _, lSpec := range filter.DeclaredLicenses {
			exactLicense, err := c.licenseExact(ctx, lSpec)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactLicense != nil {
				search = append(search, exactLicense.CertifyLegals...)
				foundOne = true
				break
			}
		}
	}
	if !foundOne && filter != nil {
		for _, lSpec := range filter.DiscoveredLicenses {
			exactLicense, err := c.licenseExact(ctx, lSpec)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			if exactLicense != nil {
				search = append(search, exactLicense.CertifyLegals...)
				foundOne = true
				break
			}
		}
	}

	var out []*model.CertifyLegal
	if foundOne {
		for _, id := range search {
			link, err := byIDkv[*certifyLegalStruct](ctx, id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addLegalIfMatch(ctx, out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		var done bool
		scn := c.kv.Keys(clCol)
		for !done {
			var clKeys []string
			var err error
			clKeys, done, err = scn.Scan(ctx)
			if err != nil {
				return nil, err
			}
			for _, clk := range clKeys {
				link, err := byKeykv[*certifyLegalStruct](ctx, clCol, clk, c)
				if err != nil {
					return nil, err
				}
				out, err = c.addLegalIfMatch(ctx, out, filter, link)
				if err != nil {
					return nil, gqlerror.Errorf("%v :: %v", funcName, err)
				}
			}
		}
	}
	return out, nil
}

func (c *demoClient) addLegalIfMatch(ctx context.Context, out []*model.CertifyLegal,
	filter *model.CertifyLegalSpec, link *certifyLegalStruct) (
	[]*model.CertifyLegal, error,
) {
	if noMatch(filter.DeclaredLicense, link.DeclaredLicense) ||
		noMatch(filter.DiscoveredLicense, link.DiscoveredLicense) ||
		noMatch(filter.Attribution, link.Attribution) ||
		noMatch(filter.Justification, link.Justification) ||
		noMatch(filter.Origin, link.Origin) ||
		noMatch(filter.Collector, link.Collector) ||
		(filter.TimeScanned != nil && !link.TimeScanned.Equal(*filter.TimeScanned)) ||
		!c.matchLicenses(ctx, filter.DeclaredLicenses, link.DeclaredLicenses) ||
		!c.matchLicenses(ctx, filter.DiscoveredLicenses, link.DiscoveredLicenses) {
		return out, nil
	}
	if filter.Subject != nil {
		if filter.Subject.Package != nil {
			if link.Pkg == "" {
				return out, nil
			}
			p, err := c.buildPackageResponse(ctx, link.Pkg, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
			if p == nil {
				return out, nil
			}
		} else if filter.Subject.Source != nil {
			if link.Source == "" {
				return out, nil
			}
			s, err := c.buildSourceResponse(ctx, link.Source, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
			if s == nil {
				return out, nil
			}
		}
	}
	o, err := c.convLegal(ctx, link)
	if err != nil {
		return nil, err
	}
	return append(out, o), nil
}

func (c *demoClient) matchLicenses(ctx context.Context, filter []*model.LicenseSpec, value []string) bool {
	val := slices.Clone(value)
	var matchID []string
	var matchPartial []*model.LicenseSpec
	for _, aSpec := range filter {
		if aSpec == nil {
			continue
		}
		a, _ := c.licenseExact(ctx, aSpec)
		// drop error here if ID is bad
		if a != nil {
			matchID = append(matchID, a.ThisID)
		} else {
			matchPartial = append(matchPartial, aSpec)
		}
	}
	for _, m := range matchID {
		if !slices.Contains(val, m) {
			return false
		}
		val = slices.Delete(val, slices.Index(val, m), slices.Index(val, m)+1)
	}
	for _, m := range matchPartial {
		match := false
		remove := -1
		for i, v := range val {
			a, err := byIDkv[*licStruct](ctx, v, c)
			if err != nil {
				return false
			}
			if (m.Name == nil || *m.Name == a.Name) &&
				(m.ListVersion == nil || *m.ListVersion == a.ListVersion) &&
				(m.Inline == nil || *m.Inline == a.Inline) {
				match = true
				remove = i
				break
			}
		}
		if !match {
			return false
		}
		val = slices.Delete(val, remove, remove+1)
	}
	return true
}
