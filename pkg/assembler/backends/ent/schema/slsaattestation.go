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
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// SLSAAttestation holds the schema definition for the SLSAAttestation entity.
type SLSAAttestation struct {
	ent.Schema
}

// Annotations of the User.
func (SLSAAttestation) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "slsa_attestations"},
	}
}

// Fields of the SLSA.
func (SLSAAttestation) Fields() []ent.Field {
	return []ent.Field{
		field.String("build_type").Comment("Type of the builder"),
		field.Int("built_by_id").Comment("ID of the builder"),
		field.Int("subject_id").Comment("ID of the subject artifact"),
		field.JSON("slsa_predicate", []*model.SLSAPredicate{}).Optional().Comment("Individual predicates found in the attestation"),
		field.String("slsa_version").Comment("Version of the SLSA predicate"),
		field.Time("started_on").Optional().Nillable().Comment("Timestamp of build start time"),
		field.Time("finished_on").Optional().Nillable().Comment("Timestamp of build end time"),
		field.String("origin").Comment("Document from which this attestation is generated from"),
		field.String("collector").Comment("GUAC collector for the document"),
		field.String("built_from_hash").Comment("Hash of the artifacts that was built"),
	}
}

// Edges of the SLSA.
func (SLSAAttestation) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("built_from", Artifact.Type),
		edge.To("built_by", Builder.Type).Unique().Field("built_by_id").Required(),
		edge.To("subject", Artifact.Type).Unique().Field("subject_id").Required(),
	}
}

// TODO: (ivanvanderbyl) Add indexes for the SLSAAttestation entity.

func (SLSAAttestation) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("subject_id", "origin", "collector", "build_type", "slsa_version", "built_by_id", "built_from_hash").Unique(),
		index.Fields("started_on"),
		index.Fields("finished_on"),
	}
}
