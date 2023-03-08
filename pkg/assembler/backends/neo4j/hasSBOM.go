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
	uri string = "uri"
)

func (c *neo4jClient) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {

	queryAll := false
	if hasSBOMSpec.Package != nil && hasSBOMSpec.Source != nil {
		return nil, gqlerror.Errorf("cannot specify both package and source for HasSBOM")
	} else if hasSBOMSpec.Package == nil && hasSBOMSpec.Source == nil {
		queryAll = true
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	aggregateHasSBOM := []*model.HasSbom{}

	if hasSBOMSpec.Package != nil || queryAll {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, hasSBOM"
		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(hasSBOM:HasSBOM)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, hasSBOMSpec.Package, false, &firstMatch, queryValues)
		setHasSBOMValues(&sb, hasSBOMSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if hasSBOMSpec.Package == nil || hasSBOMSpec.Package != nil && hasSBOMSpec.Package.Version == nil && hasSBOMSpec.Package.Subpath == nil &&
			len(hasSBOMSpec.Package.Qualifiers) == 0 && !*hasSBOMSpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)-[:subject]-(hasSBOM:HasSBOM)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true
			setPkgMatchValues(&sb, hasSBOMSpec.Package, false, &firstMatch, queryValues)
			setHasSBOMValues(&sb, hasSBOMSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedHasSBOM := []*model.HasSbom{}

				for result.Next() {
					pkgQualifiers := result.Record().Values[5]
					subPath := result.Record().Values[4]
					version := result.Record().Values[3]
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

					hasSBOMNode := dbtype.Node{}
					if result.Record().Values[6] != nil {
						hasSBOMNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("hasSBOM Node not found in neo4j")
					}

					hasSBOM := generateModelHasSBOM(pkg, hasSBOMNode.Props[uri].(string), hasSBOMNode.Props[origin].(string), hasSBOMNode.Props[collector].(string))

					collectedHasSBOM = append(collectedHasSBOM, hasSBOM)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedHasSBOM, nil
			})
		if err != nil {
			return nil, err
		}

		aggregateHasSBOM = append(aggregateHasSBOM, result.([]*model.HasSbom)...)
	}

	if hasSBOMSpec.Source != nil || queryAll {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName)-[:subject]-(hasSBOM:HasSBOM)"
		sb.WriteString(query)

		setSrcMatchValues(&sb, hasSBOMSpec.Source, false, &firstMatch, queryValues)
		setHasSBOMValues(&sb, hasSBOMSpec, &firstMatch, queryValues)
		sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, hasSBOM")

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedHasSBOM := []*model.HasSbom{}

				for result.Next() {
					tag := result.Record().Values[3]
					commit := result.Record().Values[4]
					nameStr := result.Record().Values[2].(string)
					namespaceStr := result.Record().Values[1].(string)
					srcType := result.Record().Values[0].(string)

					src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

					hasSBOMNode := dbtype.Node{}
					if result.Record().Values[5] != nil {
						hasSBOMNode = result.Record().Values[5].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("hasSBOM Node not found in neo4j")
					}

					hasSBOM := generateModelHasSBOM(src, hasSBOMNode.Props[uri].(string), hasSBOMNode.Props[origin].(string), hasSBOMNode.Props[collector].(string))

					collectedHasSBOM = append(collectedHasSBOM, hasSBOM)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedHasSBOM, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateHasSBOM = append(aggregateHasSBOM, result.([]*model.HasSbom)...)
	}

	return aggregateHasSBOM, nil
}

func setHasSBOMValues(sb *strings.Builder, hasSBOMSpec *model.HasSBOMSpec, firstMatch *bool, queryValues map[string]any) {
	if hasSBOMSpec.URI != nil {
		matchProperties(sb, *firstMatch, "hasSBOM", "uri", "$uri")
		*firstMatch = false
		queryValues["uri"] = hasSBOMSpec.URI
	}
	if hasSBOMSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "hasSBOM", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = hasSBOMSpec.Origin
	}
	if hasSBOMSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "hasSBOM", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = hasSBOMSpec.Collector
	}
}

func generateModelHasSBOM(subject model.PackageOrSource, uri, origin, collector string) *model.HasSbom {
	hasSBOM := model.HasSbom{
		Subject:   subject,
		URI:       uri,
		Origin:    origin,
		Collector: collector,
	}
	return &hasSBOM
}
