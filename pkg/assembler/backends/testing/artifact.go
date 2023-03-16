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
	"fmt"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: Artifacts
type artMap map[string]*artStruct
type artStruct struct {
	id          uint32
	algorithm   string
	digest      string
	hashEquals  []uint32
	occurrences []uint32
}

func (n *artStruct) getID() uint32 { return n.id }

func registerAllArtifacts(c *demoClient) {
	c.IngestArtifact(context.Background(), &model.ArtifactInputSpec{
		Algorithm: "sha256",
		Digest:    "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf",
	})
	c.IngestArtifact(context.Background(), &model.ArtifactInputSpec{
		Algorithm: "sha1",
		Digest:    "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9",
	})
	c.IngestArtifact(context.Background(), &model.ArtifactInputSpec{
		Algorithm: "sha512",
		Digest:    "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7",
	})
}

// Ingest Artifacts

func (c *demoClient) IngestArtifact(ctx context.Context, artifact *model.ArtifactInputSpec) (*model.Artifact, error) {
	algorithm := strings.ToLower(artifact.Algorithm)
	digest := strings.ToLower(artifact.Digest)
	a, err := c.artifactByKey(algorithm, digest)

	if err != nil {
		a = &artStruct{
			id:        c.getNextID(),
			algorithm: algorithm,
			digest:    digest,
		}
		c.index[a.id] = a
		c.artifacts[strings.Join([]string{algorithm, digest}, ":")] = a
	}

	return convArtifact(a), nil
}

func (c *demoClient) artifactByID(id uint32) (*artStruct, error) {
	o, ok := c.index[id]
	if !ok {
		return nil, errors.New("could not find artifact")
	}
	a, ok := o.(*artStruct)
	if !ok {
		return nil, errors.New("not an artifact")
	}
	return a, nil
}

func (c *demoClient) artifactByKey(alg, dig string) (*artStruct, error) {
	algorithm := strings.ToLower(alg)
	digest := strings.ToLower(dig)
	if a, ok := c.artifacts[strings.Join([]string{algorithm, digest}, ":")]; ok {
		return a, nil
	}
	return nil, errors.New("artifact not found")
}

func (c *demoClient) artifactExact(artifactSpec *model.ArtifactSpec) (*artStruct, error) {
	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))

	// If ID is provided, try to look up, then check if algo and digest match.
	if artifactSpec.ID != nil {
		id64, err := strconv.ParseUint(*artifactSpec.ID, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse id %w", err)
		}
		id := uint32(id64)
		a, err := c.artifactByID(id)
		if err != nil {
			// Not found
			return nil, nil
		}
		if algorithm != "" && algorithm != a.algorithm {
			return nil, nil
		}
		if digest != "" && digest != a.digest {
			return nil, nil
		}
		return a, nil
	}

	// If algo and digest are provided, try to lookup
	if algorithm != "" && digest != "" {
		if a, err := c.artifactByKey(algorithm, digest); err != nil {
			return a, nil
		}
	}
	return nil, nil
}

// Query Artifacts

func (c *demoClient) Artifacts(ctx context.Context, artifactSpec *model.ArtifactSpec) ([]*model.Artifact, error) {
	a, err := c.artifactExact(artifactSpec)
	if err != nil {
		return nil, gqlerror.Errorf("Artifacts :: invalid spec %s", err)
	}
	if a != nil {
		return []*model.Artifact{convArtifact(a)}, nil
	}

	algorithm := strings.ToLower(nilToEmpty(artifactSpec.Algorithm))
	digest := strings.ToLower(nilToEmpty(artifactSpec.Digest))
	var rv []*model.Artifact
	for _, a := range c.artifacts {
		matchAlgorithm := false
		if algorithm == "" || algorithm == a.algorithm {
			matchAlgorithm = true
		}

		matchDigest := false
		if digest == "" || digest == a.digest {
			matchDigest = true
		}

		if matchDigest && matchAlgorithm {
			rv = append(rv, convArtifact(a))
		}
	}
	return rv, nil
}

func convArtifact(a *artStruct) *model.Artifact {
	return &model.Artifact{
		ID:        fmt.Sprint(a.id),
		Digest:    a.digest,
		Algorithm: a.algorithm,
	}
}
