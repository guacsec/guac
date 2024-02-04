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
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// Artifact holds the schema definition for the Artifact entity.
type Artifact struct {
	ent.Schema
}

// Fields of the Artifact.
func (Artifact) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Unique().
			Immutable(),
		field.String("algorithm"),
		field.String("digest"),
	}
}

// Edges of the Artifact.
func (Artifact) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("occurrences", Occurrence.Type).Ref("artifact").Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.From("sbom", BillOfMaterials.Type).Ref("artifact"),
		edge.From("attestations", SLSAAttestation.Type).Ref("built_from"),
		edge.From("same", HashEqual.Type).Ref("artifacts"),
		// edge.To("dependency", Artifact.Type).Annotations(entsql.OnDelete(entsql.Cascade)).From("dependents"),
		// edge.From("source_occurrences", SourceOccurrence.Type).Ref("artifact"),
		// edge.To("sources", Source.Type).Through("source_occurrences", SourceOccurrence.Type),
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
		index.Fields("algorithm"),
		index.Fields("digest").Unique(),
	}
}
