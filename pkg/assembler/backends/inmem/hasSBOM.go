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

package inmem

import (
	"context"
	"strconv"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type hasSBOMList []*hasSBOMStruct
type hasSBOMStruct struct {
	id        uint32
	pkg       uint32
	src       uint32
	uri       string
	origin    string
	collector string
}

func (n *hasSBOMStruct) ID() uint32 { return n.id }

func (n *hasSBOMStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	if n.pkg != 0 && allowedEdges[model.EdgeHasSbomPackage] {
		return []uint32{n.pkg}
	}
	if allowedEdges[model.EdgeHasSbomSource] {
		return []uint32{n.src}
	}
	return []uint32{}
}

func (n *hasSBOMStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convHasSBOM(n), nil
}

// TODO convert to unit tests
// func registerAllhasSBOM(client *demoClient) error {
// 	// pkg:conan/openssl.org/openssl@3.0.3?user=bincrafters&channel=stable
// 	// "conan", "openssl.org", "openssl", "3.0.3", "", "user=bincrafters", "channel=stable"
// 	selectedType := "conan"
// 	selectedNameSpace := "openssl.org"
// 	selectedName := "openssl"
// 	selectedVersion := "3.0.3"
// 	qualifierA := "bincrafters"
// 	qualifierB := "stable"
// 	selectedQualifiers := []*model.PackageQualifierSpec{{Key: "user", Value: &qualifierA}, {Key: "channel", Value: &qualifierB}}
// 	selectedPkgSpec := &model.PkgSpec{Type: &selectedType, Namespace: &selectedNameSpace, Name: &selectedName, Version: &selectedVersion, Qualifiers: selectedQualifiers}
// 	selectedPackage, err := client.Packages(context.TODO(), selectedPkgSpec)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = client.registerHasSBOM(selectedPackage[0], nil, "uri:location of SBOM", "inmem backend", "inmem backend")
// 	if err != nil {
// 		return err
// 	}
// 	// "git", "github", "github.com/guacsec/guac", "tag=v0.0.1"
// 	selectedSourceType := "git"
// 	selectedSourceNameSpace := "github"
// 	selectedSourceName := "github.com/guacsec/guac"
// 	selectedTag := "v0.0.1"
// 	selectedSourceSpec := &model.SourceSpec{Type: &selectedSourceType, Namespace: &selectedSourceNameSpace, Name: &selectedSourceName, Tag: &selectedTag}
// 	selectedSource, err := client.Sources(context.TODO(), selectedSourceSpec)
// 	if err != nil {
// 		return err
// 	}
// 	_, err = client.registerHasSBOM(nil, selectedSource[0], "uri:location of SBOM", "inmem backend", "inmem backend")
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// Ingest HasSBOM

func (c *demoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrSourceInput, input model.HasSBOMInputSpec) (*model.HasSbom, error) {
	return c.ingestHasSbom(ctx, subject, input, true)
}

func (c *demoClient) ingestHasSbom(ctx context.Context, subject model.PackageOrSourceInput, input model.HasSBOMInputSpec, readOnly bool) (*model.HasSbom, error) {
	err := helper.ValidatePackageOrSourceInput(&subject, "IngestHasSbom")
	if err != nil {
		return nil, err
	}
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var search []uint32
	var packageID uint32
	var pkg *pkgVersionNode
	if subject.Package != nil {
		var pmt model.MatchFlags
		pmt.Pkg = model.PkgMatchTypeSpecificVersion
		pid, err := getPackageIDFromInput(c, *subject.Package, pmt)
		if err != nil {
			return nil, gqlerror.Errorf("IngestHasSbom :: %v", err)
		}
		packageID = pid
		pkg, _ = byID[*pkgVersionNode](pid, c)
		search = pkg.getHasSBOM()
	}

	var sourceID uint32
	var src *srcNameNode
	if subject.Source != nil {
		sid, err := getSourceIDFromInput(c, *subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("IngestHasSbom :: %v", err)
		}
		sourceID = sid
		src, _ = byID[*srcNameNode](sid, c)
		search = src.hasSBOMs
	}

	for _, id := range search {
		h, _ := byID[*hasSBOMStruct](id, c)
		if h.pkg == packageID &&
			h.src == sourceID &&
			h.uri == input.URI &&
			h.origin == input.Origin &&
			h.collector == input.Collector {
			return c.convHasSBOM(h), nil
		}
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestHasSbom(ctx, subject, input, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}

	h := &hasSBOMStruct{
		id:        c.getNextID(),
		pkg:       packageID,
		src:       sourceID,
		uri:       input.URI,
		origin:    input.Origin,
		collector: input.Collector,
	}
	c.index[h.id] = h
	c.hasSBOMs = append(c.hasSBOMs, h)
	if packageID != 0 {
		pkg.setHasSBOM(h.id)
	} else {
		src.setHasSBOM(h.id)
	}
	return c.convHasSBOM(h), nil
}

func (c *demoClient) convHasSBOM(in *hasSBOMStruct) *model.HasSbom {
	out := &model.HasSbom{
		ID:        nodeID(in.id),
		URI:       in.uri,
		Origin:    in.origin,
		Collector: in.collector,
	}
	if in.pkg != 0 {
		p, _ := c.buildPackageResponse(in.pkg, nil)
		out.Subject = p
	} else {
		s, _ := c.buildSourceResponse(in.src, nil)
		out.Subject = s
	}
	return out
}

// Query HasSBOM

func (c *demoClient) HasSBOM(ctx context.Context, filter *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	funcName := "HasSBOM"
	if err := helper.ValidatePackageOrSourceQueryFilter(filter.Subject); err != nil {
		return nil, err
	}
	c.m.RLock()
	defer c.m.RUnlock()

	if filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %v", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*hasSBOMStruct](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		return []*model.HasSbom{c.convHasSBOM(link)}, nil
	}

	var search []uint32
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		exactPackage, err := c.exactPackageVersion(filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactPackage != nil {
			search = append(search, exactPackage.hasSBOMs...)
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Source != nil {
		exactSource, err := c.exactSource(filter.Subject.Source)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactSource != nil {
			search = append(search, exactSource.hasSBOMs...)
			foundOne = true
		}
	}

	var out []*model.HasSbom
	if foundOne {
		for _, id := range search {
			link, err := byID[*hasSBOMStruct](id, c)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
			out, err = c.addHasSBOMIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	} else {
		for _, link := range c.hasSBOMs {
			var err error
			out, err = c.addHasSBOMIfMatch(out, filter, link)
			if err != nil {
				return nil, gqlerror.Errorf("%v :: %v", funcName, err)
			}
		}
	}
	return out, nil
}

func (c *demoClient) addHasSBOMIfMatch(out []*model.HasSbom,
	filter *model.HasSBOMSpec, link *hasSBOMStruct) (
	[]*model.HasSbom, error) {
	if noMatch(filter.URI, link.uri) ||
		noMatch(filter.Origin, link.origin) ||
		noMatch(filter.Collector, link.collector) {
		return out, nil
	}
	if filter.Subject != nil {
		if filter.Subject.Package != nil {
			if link.pkg == 0 {
				return out, nil
			}
			p, err := c.buildPackageResponse(link.pkg, filter.Subject.Package)
			if err != nil {
				return nil, err
			}
			if p == nil {
				return out, nil
			}
		} else if filter.Subject.Source != nil {
			if link.src == 0 {
				return out, nil
			}
			s, err := c.buildSourceResponse(link.src, filter.Subject.Source)
			if err != nil {
				return nil, err
			}
			if s == nil {
				return out, nil
			}
		}
	}
	return append(out, c.convHasSBOM(link)), nil
}
