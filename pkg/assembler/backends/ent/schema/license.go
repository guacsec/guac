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
)

// License holds the schema definition for the License entity.
type License struct {
	ent.Schema
}

// Fields of the License.
func (License) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").NotEmpty(),
		field.String("inline").Optional().Nillable(),
		field.String("list_version").Optional().Nillable(),
	}
}

// Edges of the License.
func (License) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("declared_in_certify_legals", CertifyLegal.Type).Ref("declared_licenses"),
		edge.From("discovered_in_certify_legals", CertifyLegal.Type).Ref("discovered_licenses"),
	}
}

// Indexes of the License.
func (License) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("name", "inline", "list_version").Unique().Annotations(entsql.IndexWhere("inline IS NOT NULL AND list_version IS NOT NULL")),
		index.Fields("name", "list_version").Unique().Annotations(entsql.IndexWhere("inline IS NULL AND list_version IS NOT NULL")),
		index.Fields("name", "inline").Unique().Annotations(entsql.IndexWhere("inline IS NOT NULL AND list_version IS NULL")),
	}
}
