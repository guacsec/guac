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

package neo4jBackend

import (
	"context"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	knownSince string = "knownSince"
)

func (c *neo4jClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true

	returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
		"version.qualifier_list, hasSourceAt, objSrcType.type, objSrcNamespace.namespace, objSrcName.name, objSrcName.tag, objSrcName.commit"

	queryValues := map[string]any{}
	// query with pkgVersion
	query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
		"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
		"-[hasSourceAt:HasSourceAt]-(objSrcName:SrcName)<-[:SrcHasName]-(objSrcNamespace:SrcNamespace)<-[:SrcHasNamespace]" +
		"-(objSrcType:SrcType)<-[:SrcHasType]-(objSrcRoot:Src)"
	sb.WriteString(query)

	setPkgMatchValues(&sb, hasSourceAtSpec.Package, false, &firstMatch, queryValues)
	setSrcMatchValues(&sb, hasSourceAtSpec.Source, true, &firstMatch, queryValues)
	setHasSourceAtValues(&sb, hasSourceAtSpec, &firstMatch, queryValues)
	sb.WriteString(returnValue)

	if hasSourceAtSpec.Package == nil || hasSourceAtSpec.Package != nil && hasSourceAtSpec.Package.Version == nil && hasSourceAtSpec.Package.Subpath == nil &&
		len(hasSourceAtSpec.Package.Qualifiers) == 0 && !*hasSourceAtSpec.Package.MatchOnlyEmptyQualifiers {

		sb.WriteString("\nUNION")
		// query without pkgVersion
		query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)" +
			"-[hasSourceAt:HasSourceAt]-(objSrcName:SrcName)<-[:SrcHasName]-(objSrcNamespace:SrcNamespace)<-[:SrcHasNamespace]" +
			"-(objSrcType:SrcType)<-[:SrcHasType]-(objSrcRoot:Src)" +
			"\nWITH *, null AS version"
		sb.WriteString(query)

		firstMatch = true
		setPkgMatchValues(&sb, hasSourceAtSpec.Package, false, &firstMatch, queryValues)
		setSrcMatchValues(&sb, hasSourceAtSpec.Source, true, &firstMatch, queryValues)
		setHasSourceAtValues(&sb, hasSourceAtSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)
	}

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedHasSourceAt := []*model.HasSourceAt{}

			for result.Next() {

				pkgQualifiers := getCollectedPackageQualifiers(result.Record().Values[5].([]interface{}))
				subPathString := result.Record().Values[4].(string)
				versionString := result.Record().Values[3].(string)
				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				version := &model.PackageVersion{
					Version:    versionString,
					Subpath:    subPathString,
					Qualifiers: pkgQualifiers,
				}

				name := &model.PackageName{
					Name:     nameString,
					Versions: []*model.PackageVersion{version},
				}

				namespace := &model.PackageNamespace{
					Namespace: namespaceString,
					Names:     []*model.PackageName{name},
				}
				pkg := model.Package{
					Type:       typeString,
					Namespaces: []*model.PackageNamespace{namespace},
				}

				commitString := ""
				if result.Record().Values[11] != nil {
					commitString = result.Record().Values[11].(string)
				}
				tagString := ""
				if result.Record().Values[10] != nil {
					tagString = result.Record().Values[10].(string)
				}
				nameString = result.Record().Values[9].(string)
				namespaceString = result.Record().Values[8].(string)
				typeString = result.Record().Values[7].(string)

				srcName := &model.SourceName{
					Name:   nameString,
					Tag:    &tagString,
					Commit: &commitString,
				}

				srcNamespace := &model.SourceNamespace{
					Namespace: namespaceString,
					Names:     []*model.SourceName{srcName},
				}
				src := model.Source{
					Type:       typeString,
					Namespaces: []*model.SourceNamespace{srcNamespace},
				}

				hasSourceAtEdge := dbtype.Relationship{}
				if result.Record().Values[6] != nil {
					hasSourceAtEdge = result.Record().Values[6].(dbtype.Relationship)
				} else {
					return nil, gqlerror.Errorf("hasSourceAtEdge not found in neo4j")
				}

				hasSourceAt := &model.HasSourceAt{
					Package:       &pkg,
					Source:        &src,
					KnownSince:    hasSourceAtEdge.Props[knownSince].(string),
					Justification: hasSourceAtEdge.Props[justification].(string),
					Origin:        hasSourceAtEdge.Props[origin].(string),
					Collector:     hasSourceAtEdge.Props[collector].(string),
				}
				collectedHasSourceAt = append(collectedHasSourceAt, hasSourceAt)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return collectedHasSourceAt, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.HasSourceAt), nil
}

func setHasSourceAtValues(sb *strings.Builder, hasSourceAtSpec *model.HasSourceAtSpec, firstMatch *bool, queryValues map[string]any) {
	if hasSourceAtSpec.KnownSince != nil {

		matchProperties(sb, *firstMatch, "hasSourceAt", "knownSince", "$knownSince")
		*firstMatch = false
		queryValues["knownSince"] = hasSourceAtSpec.KnownSince
	}
	if hasSourceAtSpec.Justification != nil {

		matchProperties(sb, *firstMatch, "hasSourceAt", "justification", "$justification")
		*firstMatch = false
		queryValues["justification"] = hasSourceAtSpec.Justification
	}
	if hasSourceAtSpec.Origin != nil {

		matchProperties(sb, *firstMatch, "hasSourceAt", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = hasSourceAtSpec.Origin
	}
	if hasSourceAtSpec.Collector != nil {

		matchProperties(sb, *firstMatch, "hasSourceAt", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = hasSourceAtSpec.Collector
	}
}
