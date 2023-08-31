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

// query certifyGood

func (c *neo4jClient) CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	queryAll := true
	aggregateCertifyGood := []*model.CertifyGood{}

	if queryAll || (certifyGoodSpec.Subject != nil && certifyGoodSpec.Subject.Package != nil) {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyGood"
		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyGood:CertifyGood)"
		sb.WriteString(query)

		if certifyGoodSpec.Subject != nil && certifyGoodSpec.Subject.Package != nil {
			setPkgMatchValues(&sb, certifyGoodSpec.Subject.Package, false, &firstMatch, queryValues)
		}
		setCertifyGoodValues(&sb, certifyGoodSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if certifyGoodSpec.Subject.Package == nil || certifyGoodSpec.Subject.Package != nil && certifyGoodSpec.Subject.Package.Version == nil &&
			certifyGoodSpec.Subject.Package.Subpath == nil && len(certifyGoodSpec.Subject.Package.Qualifiers) == 0 &&
			!*certifyGoodSpec.Subject.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)-[:subject]-(certifyGood:CertifyGood)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true

			if certifyGoodSpec.Subject != nil && certifyGoodSpec.Subject.Package != nil {
				setPkgMatchValues(&sb, certifyGoodSpec.Subject.Package, false, &firstMatch, queryValues)
			}
			setCertifyGoodValues(&sb, certifyGoodSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}
		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyGood := []*model.CertifyGood{}

				for result.Next() {
					pkgQualifiers := result.Record().Values[5]
					subPath := result.Record().Values[4]
					version := result.Record().Values[3]
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

					certifyGoodNode := dbtype.Node{}
					if result.Record().Values[6] != nil {
						certifyGoodNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyGood Node not found in neo4j")
					}

					certifyGood := generateModelCertifyGood(pkg, certifyGoodNode.Props[justification].(string), certifyGoodNode.Props[origin].(string), certifyGoodNode.Props[collector].(string))

					collectedCertifyGood = append(collectedCertifyGood, certifyGood)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyGood, nil
			})
		if err != nil {
			return nil, err
		}

		aggregateCertifyGood = append(aggregateCertifyGood, result.([]*model.CertifyGood)...)
	}

	if queryAll || (certifyGoodSpec.Subject != nil && certifyGoodSpec.Subject.Source != nil) {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName)-[:subject]-(certifyGood:CertifyGood)"
		sb.WriteString(query)

		if certifyGoodSpec.Subject != nil && certifyGoodSpec.Subject.Source != nil {
			setSrcMatchValues(&sb, certifyGoodSpec.Subject.Source, false, &firstMatch, queryValues)
		}
		setCertifyGoodValues(&sb, certifyGoodSpec, &firstMatch, queryValues)
		sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, certifyGood")
		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyGood := []*model.CertifyGood{}

				for result.Next() {
					tag := result.Record().Values[3]
					commit := result.Record().Values[4]
					nameStr := result.Record().Values[2].(string)
					namespaceStr := result.Record().Values[1].(string)
					srcType := result.Record().Values[0].(string)

					src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

					certifyGoodNode := dbtype.Node{}
					if result.Record().Values[5] != nil {
						certifyGoodNode = result.Record().Values[5].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyGood Node not found in neo4j")
					}

					certifyGood := generateModelCertifyGood(src, certifyGoodNode.Props[justification].(string), certifyGoodNode.Props[origin].(string), certifyGoodNode.Props[collector].(string))

					collectedCertifyGood = append(collectedCertifyGood, certifyGood)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyGood, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyGood = append(aggregateCertifyGood, result.([]*model.CertifyGood)...)
	}

	if queryAll || (certifyGoodSpec.Subject != nil && certifyGoodSpec.Subject.Artifact != nil) {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		query := "MATCH (a:Artifact)-[:subject]-(certifyGood:CertifyGood)"
		sb.WriteString(query)

		if certifyGoodSpec.Subject != nil && certifyGoodSpec.Subject.Artifact != nil {
			setArtifactMatchValues(&sb, certifyGoodSpec.Subject.Artifact, false, &firstMatch, queryValues)
		}
		setCertifyGoodValues(&sb, certifyGoodSpec, &firstMatch, queryValues)
		sb.WriteString(" RETURN a.algorithm, a.digest, certifyGood")
		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyGood := []*model.CertifyGood{}

				for result.Next() {
					algorithm := result.Record().Values[0].(string)
					digest := result.Record().Values[1].(string)
					artifact := generateModelArtifact(algorithm, digest)

					certifyGoodNode := dbtype.Node{}
					if result.Record().Values[2] != nil {
						certifyGoodNode = result.Record().Values[2].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyGood Node not found in neo4j")
					}

					certifyGood := generateModelCertifyGood(artifact, certifyGoodNode.Props[justification].(string), certifyGoodNode.Props[origin].(string), certifyGoodNode.Props[collector].(string))
					collectedCertifyGood = append(collectedCertifyGood, certifyGood)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyGood, nil
			})
		if err != nil {
			return nil, err
		}

		aggregateCertifyGood = append(aggregateCertifyGood, result.([]*model.CertifyGood)...)
	}
	return aggregateCertifyGood, nil

}

func setCertifyGoodValues(sb *strings.Builder, certifyGoodSpec *model.CertifyGoodSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyGoodSpec.Justification != nil {
		matchProperties(sb, *firstMatch, "certifyGood", "justification", "$justification")
		*firstMatch = false
		queryValues["justification"] = certifyGoodSpec.Justification
	}
	if certifyGoodSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "certifyGood", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = certifyGoodSpec.Origin
	}
	if certifyGoodSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "certifyGood", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = certifyGoodSpec.Collector
	}
}

func generateModelCertifyGood(subject model.PackageSourceOrArtifact, justification, origin, collector string) *model.CertifyGood {
	certifyGood := model.CertifyGood{
		Subject:       subject,
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	return &certifyGood
}

// ingest certifyGood

func (c *neo4jClient) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error) {
	panic(fmt.Errorf("not implemented: IngestCertifyGood - IngestCertifyGood"))
}

func (c *neo4jClient) IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]*model.CertifyGood, error) {
	return []*model.CertifyGood{}, fmt.Errorf("not implemented: IngestCertifyGoods")
}
