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
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// PackageVersion holds the schema definition for the PackageVersion entity.
type PackageVersion struct {
	ent.Schema
}

// Fields of the PackageVersion.
func (PackageVersion) Fields() []ent.Field {
	return []ent.Field{
		field.Int("name_id"),
		field.String("version").Default(""),
		field.String("subpath").Default(""),
		field.JSON("qualifiers", []model.PackageQualifier{}).Optional(),
		field.String("hash").Comment("A SHA1 of the qualifiers, subpath, version fields after sorting keys, used to ensure uniqueness of version records."),
	}
}

// Edges of the PackageVersion.
func (PackageVersion) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("name", PackageName.Type).Required().Field("name_id").Ref("versions").Unique(),
		edge.From("occurrences", Occurrence.Type).Ref("package"),
		edge.From("sbom", BillOfMaterials.Type).Ref("package"),

		// edge.To("equal_packages", PackageVersion.Type).Through("equals", PkgEqual.Type),
		edge.From("equal_packages", PkgEqual.Type).Ref("packages"),
		// edge.From("pkg_equal_dependant", PkgEqual.Type).Ref("dependant_package"),
	}
}

// Indexes of the PackageVersion.
func (PackageVersion) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("hash").Edges("name").Unique(),
		index.Fields("qualifiers").Annotations(
			entsql.IndexTypes(map[string]string{dialect.Postgres: "GIN"}),
		),
		index.Fields("version", "subpath", "qualifiers").Edges("name").Unique(),
	}
}
