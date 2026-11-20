//
// Copyright 2026 The GUAC Authors.
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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// SafetyAssertion stores a decision, its declared target, and an optional
// one-to-one binding to existing package versions, resolved by the certifier.
type SafetyAssertion struct{ ent.Schema }

func (SafetyAssertion) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(getUUIDv7).Unique().Immutable(),
		field.UUID("document_id", uuid.UUID{}),
		field.String("assertion_id"),
		field.String("content_hash"),
		field.Enum("safety_relevance").Values("SAFETY_RELATED", "NOT_SAFETY_RELATED", "UNDETERMINED"),
		field.String("classification_scheme").Optional().Nillable(),
		field.String("classification_value").Optional().Nillable(),
		field.Text("rationale"),
		field.Enum("decision_status").Values("DRAFT", "REVIEWED", "APPROVED", "REJECTED"),
		field.String("reviewer").Optional().Nillable(),
		field.Time("asserted_at"),
		field.Time("valid_until").Optional().Nillable(),
		field.Text("product_purl"),
		field.Text("component_purl"),
		field.String("component_bom_ref").Optional().Nillable(),
		field.String("component_digest_algorithm").Optional().Nillable(),
		field.String("component_digest").Optional().Nillable(),
		// Evidence is owned by the assertion, rather than a reusable graph node.
		field.JSON("evidence", []*model.SafetyEvidenceReferenceInput{}),
		field.Enum("correlation_status").Values("PENDING", "MATCHED", "AMBIGUOUS", "INVALID", "STALE").Default("PENDING"),
		field.String("correlation_reason").Optional().Nillable(),
		field.Time("last_evaluated_at").Optional().Nillable(),
		field.Int("correlation_revision").Default(0),
		field.UUID("resolved_product_id", uuid.UUID{}).Optional().Nillable(),
		field.UUID("resolved_component_id", uuid.UUID{}).Optional().Nillable(),
		field.String("matched_by").Optional().Nillable(),
		field.Time("resolved_at").Optional().Nillable(),
	}
}

func (SafetyAssertion) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("document", SafetyAssertionDocument.Type).Ref("assertions").Unique().Required().Field("document_id"),
		edge.To("resolved_product", PackageVersion.Type).Unique().Field("resolved_product_id"),
		edge.To("resolved_component", PackageVersion.Type).Unique().Field("resolved_component_id"),
	}
}

func (SafetyAssertion) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("document_id", "assertion_id").Unique(),
		index.Fields("product_purl"),
		index.Fields("component_purl"),
		index.Fields("safety_relevance", "decision_status"),
		index.Fields("correlation_status"),
	}
}
