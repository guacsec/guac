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

package backend

import (
	"strings"

	"github.com/guacsec/guac/pkg/assembler"
)

func registerAllArtifacts(client *neo4jClient) {
	// strings.ToLower(string(checksum.Algorithm)) + ":" + checksum.Value
	client.registerArtifact("sha256", "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf")
	client.registerArtifact("sha1", "7A8F47318E4676DACB0142AFA0B83029CD7BEFD9")
	client.registerArtifact("sha512", "374AB8F711235830769AA5F0B31CE9B72C5670074B34CB302CDAFE3B606233EE92EE01E298E5701F15CC7087714CD9ABD7DDB838A6E1206B3642DE16D9FC9DD7")
}

func (c *neo4jClient) registerArtifact(algorithm, digest string) {

	collectedArtifact := ArtifactNode{
		Algorithm: algorithm,
		Digest:    digest,
	}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedArtifact},
	}
	assembler.StoreGraph(assemblerinput, c.driver)
}

// ArtifactNode is a node that represents an artifact
type ArtifactNode struct {
	Algorithm string
	Digest    string
}

func (an ArtifactNode) Type() string {
	return "Artifact"
}

func (an ArtifactNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["algorithm"] = an.Algorithm
	properties["digest"] = strings.ToLower(an.Digest)
	return properties
}

func (an ArtifactNode) PropertyNames() []string {
	fields := []string{"algorithm", "digest"}
	return fields
}

func (an ArtifactNode) IdentifiablePropertyNames() []string {
	// An artifact can be uniquely identified by digest
	return []string{"algorithm", "digest"}
}
