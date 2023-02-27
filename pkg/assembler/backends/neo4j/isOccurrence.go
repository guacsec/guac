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

func (c *neo4jClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {
	matchPkgSrc := false
	if isOccurrenceSpec.Package != nil && isOccurrenceSpec.Source != nil {
		return nil, gqlerror.Errorf("cannot specify both package and source for IsOccurrence")
	}

	if isOccurrenceSpec.Package == nil && isOccurrenceSpec.Source == nil {
		matchPkgSrc = true
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	aggregateIsOccurrence := []*model.IsOccurrence{}
	var result interface{}

	if matchPkgSrc || isOccurrenceSpec.Package != nil {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, isOccurrence, objArt.algorithm, objArt.digest"

		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(isOccurrence:IsOccurrence)-[:has_occurrence]-(objArt:Artifact)"
		sb.WriteString(query)

		setPkgMatchValues(&sb, isOccurrenceSpec.Package, false, &firstMatch, queryValues)
		setArtifactMatchValues(&sb, isOccurrenceSpec.Artifact, true, &firstMatch, queryValues)
		setIsOccurrenceValues(&sb, isOccurrenceSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if isOccurrenceSpec.Package != nil && isOccurrenceSpec.Package.Version == nil && isOccurrenceSpec.Package.Subpath == nil &&
			len(isOccurrenceSpec.Package.Qualifiers) == 0 && !*isOccurrenceSpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)" +
				"-[:subject]-(isOccurrence:IsOccurrence)-[:has_occurrence]-(objArt:Artifact)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true
			setPkgMatchValues(&sb, isOccurrenceSpec.Package, false, &firstMatch, queryValues)
			setArtifactMatchValues(&sb, isOccurrenceSpec.Artifact, true, &firstMatch, queryValues)
			setIsOccurrenceValues(&sb, isOccurrenceSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}

		var err error
		result, err = session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedIsOccurrence := []*model.IsOccurrence{}

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

					artifact := model.Artifact{
						Algorithm: result.Record().Values[7].(string),
						Digest:    result.Record().Values[8].(string),
					}

					isOccurrenceNode := dbtype.Node{}
					if result.Record().Values[6] != nil {
						isOccurrenceNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("isOccurrence Node not found in neo4j")
					}

					isOccurrence := &model.IsOccurrence{
						Subject:            &pkg,
						OccurrenceArtifact: &artifact,
						Justification:      isOccurrenceNode.Props[justification].(string),
						Origin:             isOccurrenceNode.Props[origin].(string),
						Collector:          isOccurrenceNode.Props[collector].(string),
					}
					collectedIsOccurrence = append(collectedIsOccurrence, isOccurrence)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedIsOccurrence, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateIsOccurrence = append(aggregateIsOccurrence, result.([]*model.IsOccurrence)...)
	}

	if matchPkgSrc || isOccurrenceSpec.Source != nil {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName)-[:subject]-(isOccurrence:IsOccurrence)-[:has_occurrence]-(objArt:Artifact)"
		sb.WriteString(query)

		setSrcMatchValues(&sb, isOccurrenceSpec.Source, false, &firstMatch, queryValues)
		setArtifactMatchValues(&sb, isOccurrenceSpec.Artifact, true, &firstMatch, queryValues)
		setIsOccurrenceValues(&sb, isOccurrenceSpec, &firstMatch, queryValues)
		sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, isOccurrence, objArt.algorithm, objArt.digest")

		var err error
		result, err = session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedIsOccurrence := []*model.IsOccurrence{}

				for result.Next() {
					commitString := ""
					if result.Record().Values[4] != nil {
						commitString = result.Record().Values[4].(string)
					}
					tagString := ""
					if result.Record().Values[3] != nil {
						tagString = result.Record().Values[3].(string)
					}
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

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

					artifact := model.Artifact{
						Algorithm: result.Record().Values[6].(string),
						Digest:    result.Record().Values[7].(string),
					}

					isOccurrenceNode := dbtype.Node{}
					if result.Record().Values[5] != nil {
						isOccurrenceNode = result.Record().Values[5].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("isOccurrence Node not found in neo4j")
					}

					isOccurrence := &model.IsOccurrence{
						Subject:            &src,
						OccurrenceArtifact: &artifact,
						Justification:      isOccurrenceNode.Props[justification].(string),
						Origin:             isOccurrenceNode.Props[origin].(string),
						Collector:          isOccurrenceNode.Props[collector].(string),
					}
					collectedIsOccurrence = append(collectedIsOccurrence, isOccurrence)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedIsOccurrence, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateIsOccurrence = append(aggregateIsOccurrence, result.([]*model.IsOccurrence)...)
	}
	return aggregateIsOccurrence, nil
}

func setIsOccurrenceValues(sb *strings.Builder, isOccurrenceSpec *model.IsOccurrenceSpec, firstMatch *bool, queryValues map[string]any) {
	if isOccurrenceSpec.Justification != nil {
		matchProperties(sb, *firstMatch, "isOccurrence", "justification", "$justification")
		*firstMatch = false
		queryValues["justification"] = isOccurrenceSpec.Justification
	}
	if isOccurrenceSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "isOccurrence", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = isOccurrenceSpec.Origin
	}
	if isOccurrenceSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "isOccurrence", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = isOccurrenceSpec.Collector
	}
}
