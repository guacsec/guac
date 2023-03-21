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
	"errors"
	"strconv"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
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

func (n *hasSBOMStruct) getID() uint32 { return n.id }

func (n *hasSBOMStruct) neighbors() []uint32 {
	if n.pkg != 0 {
		return []uint32{n.pkg}
	}
	return []uint32{n.src}
}

func (n *hasSBOMStruct) buildModelNode(c *demoClient) (model.Node, error) {
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
// 	_, err = client.registerHasSBOM(selectedPackage[0], nil, "uri:location of SBOM", "testing backend", "testing backend")
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
// 	_, err = client.registerHasSBOM(nil, selectedSource[0], "uri:location of SBOM", "testing backend", "testing backend")
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

// Ingest HasSBOM

func (c *demoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrSourceInput, input model.HasSBOMInputSpec) (*model.HasSbom, error) {
	err := helper.ValidatePackageOrSourceInput(&subject, "IngestHasSbom")
	if err != nil {
		return nil, err
	}

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
		pkg, _ = c.pkgVersionByID(pid)
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
		src, _ = c.sourceByID(sid)
		search = src.getHasSBOM()
	}

	for _, id := range search {
		h, _ := c.hasSBOMByID(id)
		if h.pkg == packageID &&
			h.src == sourceID &&
			h.uri == input.URI &&
			h.origin == input.Origin &&
			h.collector == input.Collector {
			return c.convHasSBOM(h), nil
		}
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

func (c *demoClient) hasSBOMByID(id uint32) (*hasSBOMStruct, error) {
	o, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find hasSBOM")
	}
	h, ok := o.(*hasSBOMStruct)
	if !ok {
		return nil, errors.New("not a hasSBOM")
	}
	return h, nil
}

// Query HasSBOM

func (c *demoClient) HasSBOM(ctx context.Context, hSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {

	err := helper.ValidatePackageOrSourceQueryFilter(hSpec.Subject)
	if err != nil {
		return nil, err
	}

	if hSpec.ID != nil {
		id64, err := strconv.ParseUint(*hSpec.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("HasSBOM :: invalid ID %s", err)
		}
		id := uint32(id64)
		h, err := c.hasSBOMByID(id)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		return []*model.HasSbom{c.convHasSBOM(h)}, nil
	}

	var rv []*model.HasSbom
	// TODO if an exact pkg/src is specified in the subject, only search those backedges
	for _, h := range c.hasSBOMs {
		if noMatch(hSpec.URI, h.uri) ||
			noMatch(hSpec.Origin, h.origin) ||
			noMatch(hSpec.Collector, h.collector) {
			continue
		}
		if hSpec.Subject != nil {
			if hSpec.Subject.Package != nil {
				if h.pkg == 0 {
					continue
				}
				p, err := c.buildPackageResponse(h.pkg, hSpec.Subject.Package)
				if err != nil {
					return nil, err
				}
				if p == nil {
					continue
				}
			} else if hSpec.Subject.Source != nil {
				if h.src == 0 {
					continue
				}
				s, err := c.buildSourceResponse(h.src, hSpec.Subject.Source)
				if err != nil {
					return nil, err
				}
				if s == nil {
					continue
				}
			}
		}
		rv = append(rv, c.convHasSBOM(h))
	}
	return rv, nil
}
