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

// PackageName holds the schema definition for the PackageName entity.
type PackageName struct {
	ent.Schema
}

// Fields of the PackageName.
func (PackageName) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Unique().
			Immutable(),
		field.String("type").NotEmpty().Unique().Comment("This node matches a pkg:<type> partial pURL"),
		field.String("namespace").Comment("In the pURL representation, each PackageNamespace matches the pkg:<type>/<namespace>/ partial pURL"),
		field.String("name").NotEmpty(),
	}
}

// Edges of the PackageName.
func (PackageName) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("versions", PackageVersion.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		// edge.From("occurrences", PackageName.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		// edge.To("depends_on", PackageName.Type).Through("dependencies", IsOccurrence),
	}
}

// Indexes of the PackageName.
func (PackageName) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("name", "namespace", "type").Unique(),
	}
}
