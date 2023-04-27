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
	"reflect"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type hasSBOMList []*hasSBOMStruct
type hasSBOMStruct struct {
	id               uint32
	pkg              uint32
	artifact         uint32
	uri              string
	algorithm        string
	digest           string
	downloadLocation string
	annotations      map[string]string
	origin           string
	collector        string
}

func (n *hasSBOMStruct) ID() uint32 { return n.id }

func (n *hasSBOMStruct) Neighbors(allowedEdges edgeMap) []uint32 {
	if n.pkg != 0 && allowedEdges[model.EdgeHasSbomPackage] {
		return []uint32{n.pkg}
	}
	if allowedEdges[model.EdgeHasSbomArtifact] {
		return []uint32{n.artifact}
	}
	return []uint32{}
}

func (n *hasSBOMStruct) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.convHasSBOM(n)
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

func (c *demoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, input model.HasSBOMInputSpec) (*model.HasSbom, error) {
	return c.ingestHasSbom(ctx, subject, input, true)
}

func (c *demoClient) ingestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, input model.HasSBOMInputSpec, readOnly bool) (*model.HasSbom, error) {
	funcName := "IngestHasSbom"
	if err := helper.ValidatePackageOrArtifactInput(&subject, "IngestHasSbom"); err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	var search []uint32
	var packageID uint32
	var pkg *pkgVersionNode
	var artID uint32
	var art *artStruct
	if subject.Package != nil {
		pmt := model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion}
		var err error
		packageID, err = getPackageIDFromInput(c, *subject.Package, pmt)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		pkg, err = byID[*pkgVersionNode](packageID, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		search = pkg.hasSBOMs
	} else {
		var err error
		art, err = c.artifactByKey(subject.Artifact.Algorithm, subject.Artifact.Digest)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		artID = art.id
		search = art.hasSBOMs
	}

	algorithm := strings.ToLower(input.Algorithm)
	digest := strings.ToLower(input.Digest)

	for _, id := range search {
		h, err := byID[*hasSBOMStruct](id, c)
		if err != nil {
			return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		if h.pkg == packageID &&
			h.artifact == artID &&
			h.uri == input.URI &&
			h.algorithm == algorithm &&
			h.digest == digest &&
			h.downloadLocation == input.DownloadLocation &&
			reflect.DeepEqual(h.annotations, getAnnotationsFromInput(input.Annotations)) &&
			h.origin == input.Origin &&
			h.collector == input.Collector {
			return c.convHasSBOM(h)
		}
	}

	if readOnly {
		c.m.RUnlock()
		b, err := c.ingestHasSbom(ctx, subject, input, false)
		c.m.RLock() // relock so that defer unlock does not panic
		return b, err
	}

	h := &hasSBOMStruct{
		id:               c.getNextID(),
		pkg:              packageID,
		artifact:         artID,
		uri:              input.URI,
		algorithm:        algorithm,
		digest:           digest,
		downloadLocation: input.DownloadLocation,
		annotations:      getAnnotationsFromInput(input.Annotations),
		origin:           input.Origin,
		collector:        input.Collector,
	}
	c.index[h.id] = h
	c.hasSBOMs = append(c.hasSBOMs, h)
	if packageID != 0 {
		pkg.setHasSBOM(h.id)
	} else {
		art.setHasSBOMs(h.id)
	}
	return c.convHasSBOM(h)
}

func (c *demoClient) convHasSBOM(in *hasSBOMStruct) (*model.HasSbom, error) {
	out := &model.HasSbom{
		ID:               nodeID(in.id),
		URI:              in.uri,
		Algorithm:        in.algorithm,
		Digest:           in.digest,
		DownloadLocation: in.downloadLocation,
		Annotations:      getCollectedHasSBOMAnnotations(in.annotations),
		Origin:           in.origin,
		Collector:        in.collector,
	}
	if in.pkg != 0 {
		p, err := c.buildPackageResponse(in.pkg, nil)
		if err != nil {
			return nil, err
		}
		out.Subject = p
	} else {
		art, err := byID[*artStruct](in.artifact, c)
		if err != nil {
			return nil, err
		}
		out.Subject = c.convArtifact(art)
	}
	return out, nil
}

// Query HasSBOM

func (c *demoClient) HasSBOM(ctx context.Context, filter *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	funcName := "HasSBOM"
	if err := helper.ValidatePackageOrArtifactQueryFilter(filter.Subject); err != nil {
		return nil, gqlerror.Errorf("%v :: %v", funcName, err)
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
		sb, err := c.convHasSBOM(link)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.HasSbom{sb}, nil
	}

	var search []uint32
	foundOne := false
	if filter != nil && filter.Subject != nil && filter.Subject.Package != nil {
		exactPackage, err := c.exactPackageVersion(filter.Subject.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactPackage != nil {
			search = exactPackage.hasSBOMs
			foundOne = true
		}
	}
	if !foundOne && filter != nil && filter.Subject != nil && filter.Subject.Artifact != nil {
		exactArt, err := c.artifactExact(filter.Subject.Artifact)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactArt != nil {
			search = exactArt.hasSBOMs
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

	algorithm := strings.ToLower(nilToEmpty(filter.Algorithm))
	digest := strings.ToLower(nilToEmpty(filter.Digest))

	if noMatch(filter.URI, link.uri) ||
		noMatch(ptrfrom.String(algorithm), link.algorithm) ||
		noMatch(ptrfrom.String(digest), link.digest) ||
		noMatch(filter.DownloadLocation, link.downloadLocation) ||
		noMatchAnnotations(filter.Annotations, link.annotations) ||
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
		} else if filter.Subject.Artifact != nil {
			if link.artifact == 0 {
				return out, nil
			}
			if !c.artifactMatch(link.artifact, filter.Subject.Artifact) {
				return out, nil
			}
		}
	}
	sb, err := c.convHasSBOM(link)
	if err != nil {
		return nil, err
	}
	return append(out, sb), nil
}

func getCollectedHasSBOMAnnotations(annotationMap map[string]string) []*model.Annotation {
	annotations := []*model.Annotation{}
	for key, val := range annotationMap {
		annotation := &model.Annotation{
			Key:   key,
			Value: val,
		}
		annotations = append(annotations, annotation)

	}
	return annotations
}

func getAnnotationsFromInput(annotationInput []*model.AnnotationInputSpec) map[string]string {
	annotationMap := map[string]string{}
	if annotationInput == nil {
		return annotationMap
	}
	for _, kv := range annotationInput {
		annotationMap[kv.Key] = kv.Value
	}
	return annotationMap
}

func getAnnotationsFromFilter(annotationFilter []*model.AnnotationSpec) map[string]string {
	annotationMap := map[string]string{}
	if annotationFilter == nil {
		return annotationMap
	}
	for _, kv := range annotationFilter {
		annotationMap[kv.Key] = kv.Value
	}
	return annotationMap
}

func noMatchAnnotations(annotationFilter []*model.AnnotationSpec, v map[string]string) bool {
	if annotationFilter == nil && len(annotationFilter) > 0 {
		return !reflect.DeepEqual(v, getAnnotationsFromFilter(annotationFilter))
	}
	return false
}
