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

// VulnEqual holds the schema definition for the VulnEqual entity.
type VulnEqual struct {
	ent.Schema
}

// Fields of the VulnEqual.
func (VulnEqual) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(getUUIDv7).
			Unique().
			Immutable(),
		field.UUID("vuln_id", getUUIDv7()),
		field.UUID("equal_vuln_id", getUUIDv7()),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
		field.String("vulnerabilities_hash").Comment("An opaque hash of the vulnerability IDs that are equal"),
	}
}

// Edges of the VulnEqual.
func (VulnEqual) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("vulnerability_a", VulnerabilityID.Type).Required().Field("vuln_id").Unique(),
		edge.To("vulnerability_b", VulnerabilityID.Type).Required().Field("equal_vuln_id").Unique(),
	}
}

// Indexes of the VulnEqual.
func (VulnEqual) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("vuln_id", "equal_vuln_id", "vulnerabilities_hash", "justification", "origin", "collector").Unique(),
	}
}
