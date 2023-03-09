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
	"reflect"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

func registerAllHashEqual(client *demoClient) {

	// strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
	client.registerHashEqual([]*model.Artifact{client.artifacts[0], client.artifacts[1], client.artifacts[2]}, "different algorithm for the same artifact", "testing backend", "testing backend")
	client.registerHashEqual([]*model.Artifact{{Digest: "5a787865sd676dacb0142afa0b83029cd7befd9", Algorithm: "sha1"},
		{Digest: "89bb0da1891646e58eb3e6ed24f3a6fc3c8eb5a0d44824cba581dfa34a0450cf", Algorithm: "sha256"}}, "these two are the same", "testing backend", "testing backend")
}

// Ingest HashEqual

func (c *demoClient) registerHashEqual(artifacts []*model.Artifact, justification, origin, collector string) *model.HashEqual {

	for _, a := range c.hashEquals {
		if reflect.DeepEqual(a.Artifacts, artifacts) && a.Justification == justification {
			return a
		}
	}

	newHashEqual := &model.HashEqual{
		Justification: justification,
		Artifacts:     artifacts,
		Origin:        origin,
		Collector:     collector,
	}
	c.hashEquals = append(c.hashEquals, newHashEqual)
	return newHashEqual
}

func (c *demoClient) IngestHashEqual(ctx context.Context, artifact model.ArtifactInputSpec, equalArtifact model.ArtifactInputSpec, hashEqual model.HashEqualInputSpec) (*model.HashEqual, error) {

	collectedArt, err := c.Artifacts(ctx, &model.ArtifactSpec{Algorithm: &artifact.Algorithm, Digest: &artifact.Digest})
	if err != nil {
		return nil, err
	}
	if len(collectedArt) != 1 {
		return nil, gqlerror.Errorf(
			"IngestHashEqual :: multiple artifacts found")
	}

	collectedEqualArt, err := c.Artifacts(ctx, &model.ArtifactSpec{Algorithm: &equalArtifact.Algorithm, Digest: &equalArtifact.Digest})
	if err != nil {
		return nil, err
	}
	if len(collectedEqualArt) != 1 {
		return nil, gqlerror.Errorf(
			"IngestHashEqual :: multiple artifacts found")
	}

	return c.registerHashEqual(
		[]*model.Artifact{collectedArt[0], collectedEqualArt[0]},
		hashEqual.Justification,
		hashEqual.Origin,
		hashEqual.Collector), nil
}

// Query HashEqual

func (c *demoClient) HashEqual(ctx context.Context, hashEqualSpec *model.HashEqualSpec) ([]*model.HashEqual, error) {
	var hashEquals []*model.HashEqual

	for _, h := range c.hashEquals {
		matchOrSkip := true

		if hashEqualSpec.Justification != nil && h.Justification != *hashEqualSpec.Justification {
			matchOrSkip = false
		}
		if hashEqualSpec.Collector != nil && h.Collector != *hashEqualSpec.Collector {
			matchOrSkip = false
		}
		if hashEqualSpec.Origin != nil && h.Origin != *hashEqualSpec.Origin {
			matchOrSkip = false
		}

		if len(hashEqualSpec.Artifacts) > 0 && !filterEqualArtifact(h.Artifacts, hashEqualSpec.Artifacts) {
			matchOrSkip = false
		}

		if matchOrSkip {
			hashEquals = append(hashEquals, h)
		}
	}

	return hashEquals, nil
}

func filterEqualArtifact(storedArtifacts []*model.Artifact, queryArtifacts []*model.ArtifactSpec) bool {
	exists := make(map[model.Artifact]bool)
	for _, value := range storedArtifacts {
		exists[*value] = true
	}

	// enforce lowercase for both the algorithm and digest when querying
	for _, value := range queryArtifacts {
		queryArt := model.Artifact{
			Algorithm: strings.ToLower(*value.Algorithm),
			Digest:    strings.ToLower(*value.Digest),
		}
		if _, ok := exists[queryArt]; ok {
			return true
		}
	}
	return false
}
