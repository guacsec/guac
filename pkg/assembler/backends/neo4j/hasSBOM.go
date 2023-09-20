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

package neo4j

import (
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	uri string = "uri"
)

// TODO: noe4j backend does not match the schema. This needs updating before use!
func (c *neo4jClient) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {

	queryAll := true
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	aggregateHasSBOM := []*model.HasSbom{}

	if queryAll || (hasSBOMSpec.Subject != nil && hasSBOMSpec.Subject.Package != nil) {
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

		if hasSBOMSpec.Subject != nil && hasSBOMSpec.Subject.Package != nil {
			setPkgMatchValues(&sb, hasSBOMSpec.Subject.Package, false, &firstMatch, queryValues)
		}
		setHasSBOMValues(&sb, hasSBOMSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

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

	if queryAll || (hasSBOMSpec.Subject != nil && hasSBOMSpec.Subject.Artifact != nil) {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName)-[:subject]-(hasSBOM:HasSBOM)"
		sb.WriteString(query)

		if hasSBOMSpec.Subject != nil && hasSBOMSpec.Subject.Artifact != nil {
			setArtifactMatchValues(&sb, hasSBOMSpec.Subject.Artifact, false, &firstMatch, queryValues)
		}
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
					algorithm := result.Record().Values[0].(string)
					digest := result.Record().Values[1].(string)

					src := generateModelArtifact(algorithm, digest)

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
		matchProperties(sb, *firstMatch, "hasSBOM", uri, "$"+uri)
		*firstMatch = false
		queryValues[uri] = hasSBOMSpec.URI
	}
	if hasSBOMSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "hasSBOM", origin, "$"+origin)
		*firstMatch = false
		queryValues[origin] = hasSBOMSpec.Origin
	}
	if hasSBOMSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "hasSBOM", collector, "$"+collector)
		*firstMatch = false
		queryValues[collector] = hasSBOMSpec.Collector
	}
}

func generateModelHasSBOM(subject model.PackageOrArtifact, uri, origin, collector string) *model.HasSbom {
	hasSBOM := model.HasSbom{
		Subject:   subject,
		URI:       uri,
		Origin:    origin,
		Collector: collector,
	}
	return &hasSBOM
}

func (c *neo4jClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (*model.HasSbom, error) {
	panic(fmt.Errorf("not implemented: IngestHasSbom - IngestHasSbom"))
}

func (c *neo4jClient) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]*model.HasSbom, error) {
	return []*model.HasSbom{}, fmt.Errorf("not implemented: IngestHasSBOMs")
}
