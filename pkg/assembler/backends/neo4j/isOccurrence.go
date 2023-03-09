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

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Query IsOccurrence

func (c *neo4jClient) IsOccurrence(ctx context.Context, isOccurrenceSpec *model.IsOccurrenceSpec) ([]*model.IsOccurrence, error) {

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	queryAll := false
	if isOccurrenceSpec.Subject == nil {
		queryAll = true
	} else {
		if isOccurrenceSpec.Subject.Package != nil && isOccurrenceSpec.Subject.Source != nil {
			return nil, gqlerror.Errorf("cannot specify both package and source for IsOccurrence")
		}
	}

	aggregateIsOccurrence := []*model.IsOccurrence{}

	if queryAll || isOccurrenceSpec.Subject != nil && isOccurrenceSpec.Subject.Package != nil {
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

		if isOccurrenceSpec.Subject != nil && isOccurrenceSpec.Subject.Package != nil {
			setPkgMatchValues(&sb, isOccurrenceSpec.Subject.Package, false, &firstMatch, queryValues)
		}
		setArtifactMatchValues(&sb, isOccurrenceSpec.Artifact, true, &firstMatch, queryValues)
		setIsOccurrenceValues(&sb, isOccurrenceSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedIsOccurrence := []*model.IsOccurrence{}

				for result.Next() {
					pkgQualifiers := result.Record().Values[5]
					subPath := result.Record().Values[4]
					version := result.Record().Values[3]
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

					algorithm := result.Record().Values[7].(string)
					digest := result.Record().Values[8].(string)
					artifact := generateModelArtifact(algorithm, digest)

					isOccurrenceNode := dbtype.Node{}
					if result.Record().Values[6] != nil {
						isOccurrenceNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("isOccurrence Node not found in neo4j")
					}

					isOccurrence := generateModelIsOccurrence(pkg, artifact, isOccurrenceNode.Props[justification].(string),
						isOccurrenceNode.Props[origin].(string), isOccurrenceNode.Props[collector].(string))

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

	if queryAll || isOccurrenceSpec.Subject != nil && isOccurrenceSpec.Subject.Source != nil {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName)-[:subject]-(isOccurrence:IsOccurrence)-[:has_occurrence]-(objArt:Artifact)"
		sb.WriteString(query)

		if isOccurrenceSpec.Subject != nil && isOccurrenceSpec.Subject.Source != nil {
			setSrcMatchValues(&sb, isOccurrenceSpec.Subject.Source, false, &firstMatch, queryValues)
		}
		setArtifactMatchValues(&sb, isOccurrenceSpec.Artifact, true, &firstMatch, queryValues)
		setIsOccurrenceValues(&sb, isOccurrenceSpec, &firstMatch, queryValues)
		sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, isOccurrence, objArt.algorithm, objArt.digest")

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedIsOccurrence := []*model.IsOccurrence{}

				for result.Next() {
					tag := result.Record().Values[3]
					commit := result.Record().Values[4]
					nameStr := result.Record().Values[2].(string)
					namespaceStr := result.Record().Values[1].(string)
					srcType := result.Record().Values[0].(string)
					src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

					algorithm := result.Record().Values[6].(string)
					digest := result.Record().Values[7].(string)
					artifact := generateModelArtifact(algorithm, digest)

					isOccurrenceNode := dbtype.Node{}
					if result.Record().Values[5] != nil {
						isOccurrenceNode = result.Record().Values[5].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("isOccurrence Node not found in neo4j")
					}

					isOccurrence := generateModelIsOccurrence(src, artifact, isOccurrenceNode.Props[justification].(string),
						isOccurrenceNode.Props[origin].(string), isOccurrenceNode.Props[collector].(string))

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
		matchProperties(sb, *firstMatch, "isOccurrence", justification, "$"+justification)
		*firstMatch = false
		queryValues[justification] = isOccurrenceSpec.Justification
	}
	if isOccurrenceSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "isOccurrence", origin, "$"+origin)
		*firstMatch = false
		queryValues[origin] = isOccurrenceSpec.Origin
	}
	if isOccurrenceSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "isOccurrence", collector, "$"+collector)
		*firstMatch = false
		queryValues[collector] = isOccurrenceSpec.Collector
	}
}

func generateModelIsOccurrence(subject model.PackageOrSource, artifact *model.Artifact, justification, origin, collector string) *model.IsOccurrence {
	isOccurrence := model.IsOccurrence{
		Subject:       subject,
		Artifact:      artifact,
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	return &isOccurrence
}

// Ingest IngestOccurrence

func (c *neo4jClient) IngestOccurrence(ctx context.Context, subject model.PackageOrSourceInput, artifact model.ArtifactInputSpec, occurrence model.IsOccurrenceInputSpec) (*model.IsOccurrence, error) {

	if subject.Package != nil && subject.Source != nil {
		return nil, gqlerror.Errorf("cannot specify both package and source for IngestOccurrence")
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	occurrenceArt := helper.ConvertArtInputSpecToArtSpec(&artifact)

	queryValues[justification] = occurrence.Justification
	queryValues[origin] = occurrence.Origin
	queryValues[collector] = occurrence.Collector

	if subject.Package != nil {
		// TODO: use generics here between PkgInputSpec and PkgSpecs?
		selectedPkgSpec := helper.ConvertPkgInputSpecToPkgSpec(subject.Package)

		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion), (objArt:Artifact)"

		sb.WriteString(query)
		setPkgMatchValues(&sb, selectedPkgSpec, false, &firstMatch, queryValues)
		setArtifactMatchValues(&sb, occurrenceArt, true, &firstMatch, queryValues)

		merge := "\nMERGE (version)<-[:subject]-(isOccurrence:IsOccurrence{justification:$justification,origin:$origin,collector:$collector})" +
			"-[:has_occurrence]->(objArt)"
		sb.WriteString(merge)
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, isOccurrence, objArt.algorithm, objArt.digest"
		sb.WriteString(returnValue)

		result, err := session.WriteTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {
				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				// query returns a single record
				record, err := result.Single()
				if err != nil {
					return nil, err
				}

				pkgQualifiers := record.Values[5]
				subPath := record.Values[4]
				version := record.Values[3]
				nameString := record.Values[2].(string)
				namespaceString := record.Values[1].(string)
				typeString := record.Values[0].(string)

				pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

				algorithm := record.Values[7].(string)
				digest := record.Values[8].(string)
				artifact := generateModelArtifact(algorithm, digest)

				isOccurrenceNode := dbtype.Node{}
				if record.Values[6] != nil {
					isOccurrenceNode = record.Values[6].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("isOccurrence Node not found in neo4j")
				}

				isOccurrence := generateModelIsOccurrence(pkg, artifact, isOccurrenceNode.Props[justification].(string),
					isOccurrenceNode.Props[origin].(string), isOccurrenceNode.Props[collector].(string))

				return isOccurrence, nil
			})
		if err != nil {
			return nil, err
		}

		return result.(*model.IsOccurrence), nil
	} else if subject.Source != nil {
		// TODO: use generics here between SourceInputSpec and SourceSpec?
		selectedSrcSpec := helper.ConvertSrcInputSpecToSrcSpec(subject.Source)

		returnValue := " RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, isOccurrence, objArt.algorithm, objArt.digest"

		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName), (objArt:Artifact)"

		sb.WriteString(query)
		setSrcMatchValues(&sb, selectedSrcSpec, false, &firstMatch, queryValues)
		setArtifactMatchValues(&sb, occurrenceArt, true, &firstMatch, queryValues)

		merge := "\nMERGE (name)<-[:subject]-(isOccurrence:IsOccurrence{justification:$justification,origin:$origin,collector:$collector})" +
			"-[:has_occurrence]->(objArt)"
		sb.WriteString(merge)
		sb.WriteString(returnValue)

		result, err := session.WriteTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {
				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				// query returns a single record
				record, err := result.Single()
				if err != nil {
					return nil, err
				}

				tag := record.Values[3]
				commit := record.Values[4]
				nameStr := record.Values[2].(string)
				namespaceStr := record.Values[1].(string)
				srcType := record.Values[0].(string)
				src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

				algorithm := record.Values[6].(string)
				digest := record.Values[7].(string)
				artifact := generateModelArtifact(algorithm, digest)

				isOccurrenceNode := dbtype.Node{}
				if record.Values[5] != nil {
					isOccurrenceNode = record.Values[5].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("isOccurrence Node not found in neo4j")
				}

				isOccurrence := generateModelIsOccurrence(src, artifact, isOccurrenceNode.Props[justification].(string),
					isOccurrenceNode.Props[origin].(string), isOccurrenceNode.Props[collector].(string))

				return isOccurrence, nil
			})
		if err != nil {
			return nil, err
		}

		return result.(*model.IsOccurrence), nil

	} else {
		return nil, gqlerror.Errorf("package or source not specified for IngestOccurrence")
	}
}
