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
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// SafetyAssertionDocument retains the provenance of the exact received bytes.
type SafetyAssertionDocument struct{ ent.Schema }

func (SafetyAssertionDocument) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).Default(getUUIDv7).Unique().Immutable(),
		field.String("digest_algorithm"),
		field.String("digest"),
		field.String("document_ref"),
		field.String("origin"),
		field.String("collector"),
		field.String("source_authority").Optional().Nillable(),
		field.Time("received_at").Default(time.Now).Immutable(),
	}
}

func (SafetyAssertionDocument) Edges() []ent.Edge {
	return []ent.Edge{edge.To("assertions", SafetyAssertion.Type)}
}

func (SafetyAssertionDocument) Indexes() []ent.Index {
	return []ent.Index{index.Fields("digest_algorithm", "digest").Unique()}
}
