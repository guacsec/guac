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
)

// PackageType holds the schema definition for the PackageType entity.
// This node maps to models.Package in the GraphQL schema. It is named PackageType
// because Package is a reserved keyword in Ent.
type PackageType struct {
	ent.Schema
}

// Fields of the PackageType.
func (PackageType) Fields() []ent.Field {
	return []ent.Field{
		field.String("type").NotEmpty().Unique().Comment("This node matches a pkg:<type> partial pURL"),
	}
}

// Edges of the PackageType.
func (PackageType) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("namespaces", PackageNamespace.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}
