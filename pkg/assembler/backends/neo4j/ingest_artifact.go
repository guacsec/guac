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

package neo4jBackend

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
	// enforce lowercase for both the algorithm and digest when ingesting
	collectedArtifact := artifactNode{
		algorithm: strings.ToLower(algorithm),
		digest:    strings.ToLower(digest),
	}
	assemblerinput := assembler.AssemblerInput{
		Nodes: []assembler.GuacNode{collectedArtifact},
	}
	assembler.StoreGraph(assemblerinput, c.driver)
}

// ArtifactNode is a node that represents an artifact
type artifactNode struct {
	algorithm string
	digest    string
}

func (an artifactNode) Type() string {
	return "Artifact"
}

func (an artifactNode) Properties() map[string]interface{} {
	properties := make(map[string]interface{})
	properties["algorithm"] = an.algorithm
	properties["digest"] = strings.ToLower(an.digest)
	return properties
}

func (an artifactNode) PropertyNames() []string {
	fields := []string{"algorithm", "digest"}
	return fields
}

func (an artifactNode) IdentifiablePropertyNames() []string {
	// An artifact can be uniquely identified by algorithm and digest
	return []string{"algorithm", "digest"}
}
