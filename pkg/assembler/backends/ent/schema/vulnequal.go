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
)

// VulnEqual holds the schema definition for the VulnEqual entity.
type VulnEqual struct {
	ent.Schema
}

// Fields of the VulnEqual.
func (VulnEqual) Fields() []ent.Field {
	return []ent.Field{
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the VulnEqual.
func (VulnEqual) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("vulnerability_ids", VulnerabilityID.Type).Required(),
	}
}

// Indexes of the VulnEqual.
//func (VulnEqual) Indexes() []ent.Index {
//	return []ent.Index{
//		index.Fields("justification", "origin", "collector")/*.Edges("vulnerability_ids")*/,
//	}
//}
