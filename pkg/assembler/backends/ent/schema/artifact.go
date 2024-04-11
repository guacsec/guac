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

package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

func getUUIDv7() uuid.UUID {
	uuid, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return uuid
}

// Artifact holds the schema definition for the Artifact entity.
type Artifact struct {
	ent.Schema
}

// Fields of the Artifact.
func (Artifact) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.String("algorithm"),
		field.String("digest"),
	}
}

// Edges of the Artifact.
func (Artifact) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("occurrences", Occurrence.Type).Ref("artifact"),
		edge.From("sbom", BillOfMaterials.Type).Ref("artifact"),
		edge.From("attestations", SLSAAttestation.Type).Ref("built_from"),
		edge.From("attestations_subject", SLSAAttestation.Type).Ref("subject"),
		edge.From("hash_equal_art_a", HashEqual.Type).Ref("artifact_a"),
		edge.From("hash_equal_art_b", HashEqual.Type).Ref("artifact_b"),
		edge.From("vex", CertifyVex.Type).Ref("artifact"),
		edge.From("certification", Certification.Type).Ref("artifact"),
		edge.From("metadata", HasMetadata.Type).Ref("artifact"),
		edge.From("poc", PointOfContact.Type).Ref("artifact"),
		edge.From("included_in_sboms", BillOfMaterials.Type).Ref("included_software_artifacts"),
	}
}

// Indexes of the Artifact.
//
// NOTE: Given the nature of digests, we could treat them as unique identifiers
// with a single index, but currently we index both alg and digest so that it is possible
// to query all artifacts using a specific algorithm.
func (Artifact) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("algorithm", "digest").Unique(),
	}
}
