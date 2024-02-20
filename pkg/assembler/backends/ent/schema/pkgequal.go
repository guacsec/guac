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

// PkgEqual holds the schema definition for the PkgEqual entity.
type PkgEqual struct {
	ent.Schema
}

// func (PkgEqual) Annotations() []schema.Annotation {
// 	return []schema.Annotation{
// 		field.ID("package_version_id", "equal_package_id"),
// 	}
// }

// Fields of the PkgEqual.
func (PkgEqual) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Unique().
			Immutable(),
		field.String("origin"),
		field.String("collector"),
		field.String("justification"),
		field.String("packages_hash").Comment("An opaque hash of the packages that are equal"),
	}
}

// Edges of the PkgEqual.
func (PkgEqual) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("packages", PackageVersion.Type).Required(),
		// edge.To("package", PackageVersion.Type).Required().Field("equal_package_id").Unique(),
		// edge.To("dependant_package", PackageVersion.Type).Required().Field("package_version_id").Unique(),
	}
}

// Indexes of the PkgEqual.
func (PkgEqual) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("packages_hash", "origin", "justification", "collector").Unique(),
	}
}
