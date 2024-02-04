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
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Dependency holds the schema definition for the Dependency entity.
type Dependency struct {
	ent.Schema
}

// Annotations of the Dependency.
func (Dependency) Annotations() []schema.Annotation {
	return []schema.Annotation{
		// field.ID("dependent_package_id", "package_id"),
	}
}

// Fields of the Dependency.
func (Dependency) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Unique().
			Immutable(),
		field.UUID("package_id", uuid.New()),
		field.UUID("dependent_package_name_id", uuid.New()).Optional(),
		field.UUID("dependent_package_version_id", uuid.New()).Optional(),
		field.String("version_range"),
		field.Enum("dependency_type").Values(model.DependencyTypeDirect.String(), model.DependencyTypeIndirect.String(), model.DependencyTypeUnknown.String()),
		field.String("justification"),
		field.String("origin"),
		field.String("collector"),
	}
}

// Edges of the Dependency.
func (Dependency) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("package", PackageVersion.Type).
			Required().
			Field("package_id").
			Unique(),
		edge.To("dependent_package_name", PackageName.Type).
			Field("dependent_package_name_id").
			Unique(),
		edge.To("dependent_package_version", PackageVersion.Type).
			Field("dependent_package_version_id").
			Unique(),
		edge.From("included_in_sboms", BillOfMaterials.Type).Ref("included_dependencies"),
	}
}

// Indexes of the Dependency.
func (Dependency) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("version_range", "dependency_type", "justification", "origin", "collector").
			Edges("package", "dependent_package_name").
			Unique().
			Annotations(entsql.IndexWhere("dependent_package_name_id IS NOT NULL AND dependent_package_version_id IS NULL")).StorageKey("dep_package_name"),
		index.Fields("version_range", "dependency_type", "justification", "origin", "collector").
			Edges("package", "dependent_package_version").
			Unique().
			Annotations(entsql.IndexWhere("dependent_package_name_id IS NULL AND dependent_package_version_id IS NOT NULL")).StorageKey("dep_package_version"),
	}
}
