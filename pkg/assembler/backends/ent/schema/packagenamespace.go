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

// PackageNamespace holds the schema definition for the PackageNamespace entity.
type PackageNamespace struct {
	ent.Schema
}

// Fields of the PackageNamespace.
func (PackageNamespace) Fields() []ent.Field {
	return []ent.Field{
		field.Int("package_id"),
		field.String("namespace").Comment("In the pURL representation, each PackageNamespace matches the pkg:<type>/<namespace>/ partial pURL"),
	}
}

// Edges of the PackageNamespace.
func (PackageNamespace) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("package", PackageType.Type).Required().Field("package_id").Ref("namespaces").Unique(),
		edge.To("names", PackageName.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Indexes of the PackageNamespace.
func (PackageNamespace) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("namespace").Edges("package").Unique(),
	}
}
