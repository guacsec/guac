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
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// query certifyBad

func (c *neo4jClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	queryAll, err := helper.CheckCertifyBadQueryInput(certifyBadSpec.Subject)
	if err != nil {
		return nil, err
	}

	aggregateCertifyBad := []*model.CertifyBad{}

	if queryAll || (certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Package != nil) {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyBad"
		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(certifyBad:CertifyBad)"
		sb.WriteString(query)

		if certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Package != nil {
			setPkgMatchValues(&sb, certifyBadSpec.Subject.Package, false, &firstMatch, queryValues)
		}
		setCertifyBadValues(&sb, certifyBadSpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if certifyBadSpec.Subject.Package == nil || certifyBadSpec.Subject.Package != nil && certifyBadSpec.Subject.Package.Version == nil &&
			certifyBadSpec.Subject.Package.Subpath == nil && len(certifyBadSpec.Subject.Package.Qualifiers) == 0 &&
			!*certifyBadSpec.Subject.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)-[:subject]-(certifyBad:CertifyBad)" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true

			if certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Package != nil {
				setPkgMatchValues(&sb, certifyBadSpec.Subject.Package, false, &firstMatch, queryValues)
			}
			setCertifyBadValues(&sb, certifyBadSpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}
		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyBad := []*model.CertifyBad{}

				for result.Next() {
					pkgQualifiers := result.Record().Values[5]
					subPath := result.Record().Values[4]
					version := result.Record().Values[3]
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

					certifyBadNode := dbtype.Node{}
					if result.Record().Values[6] != nil {
						certifyBadNode = result.Record().Values[6].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyBad Node not found in neo4j")
					}

					certifyBad := generateModelCertifyBad(pkg, certifyBadNode.Props[justification].(string), certifyBadNode.Props[origin].(string), certifyBadNode.Props[collector].(string))

					collectedCertifyBad = append(collectedCertifyBad, certifyBad)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyBad, nil
			})
		if err != nil {
			return nil, err
		}

		aggregateCertifyBad = append(aggregateCertifyBad, result.([]*model.CertifyBad)...)
	}

	if queryAll || (certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Source != nil) {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName)-[:subject]-(certifyBad:CertifyBad)"
		sb.WriteString(query)

		if certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Source != nil {
			setSrcMatchValues(&sb, certifyBadSpec.Subject.Source, false, &firstMatch, queryValues)
		}
		setCertifyBadValues(&sb, certifyBadSpec, &firstMatch, queryValues)
		sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, certifyBad")
		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyBad := []*model.CertifyBad{}

				for result.Next() {
					tag := result.Record().Values[3]
					commit := result.Record().Values[4]
					nameStr := result.Record().Values[2].(string)
					namespaceStr := result.Record().Values[1].(string)
					srcType := result.Record().Values[0].(string)

					src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

					certifyBadNode := dbtype.Node{}
					if result.Record().Values[5] != nil {
						certifyBadNode = result.Record().Values[5].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyBad Node not found in neo4j")
					}

					certifyBad := generateModelCertifyBad(src, certifyBadNode.Props[justification].(string), certifyBadNode.Props[origin].(string), certifyBadNode.Props[collector].(string))

					collectedCertifyBad = append(collectedCertifyBad, certifyBad)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyBad, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateCertifyBad = append(aggregateCertifyBad, result.([]*model.CertifyBad)...)
	}

	if queryAll || (certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Artifact != nil) {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		query := "MATCH (a:Artifact)-[:subject]-(certifyBad:CertifyBad)"
		sb.WriteString(query)

		if certifyBadSpec.Subject != nil && certifyBadSpec.Subject.Artifact != nil {
			setArtifactMatchValues(&sb, certifyBadSpec.Subject.Artifact, false, &firstMatch, queryValues)
		}
		setCertifyBadValues(&sb, certifyBadSpec, &firstMatch, queryValues)
		sb.WriteString(" RETURN a.algorithm, a.digest, certifyBad")
		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				collectedCertifyBad := []*model.CertifyBad{}

				for result.Next() {
					algorithm := result.Record().Values[0].(string)
					digest := result.Record().Values[1].(string)
					artifact := generateModelArtifact(algorithm, digest)

					certifyBadNode := dbtype.Node{}
					if result.Record().Values[2] != nil {
						certifyBadNode = result.Record().Values[2].(dbtype.Node)
					} else {
						return nil, gqlerror.Errorf("certifyBad Node not found in neo4j")
					}

					certifyBad := generateModelCertifyBad(artifact, certifyBadNode.Props[justification].(string), certifyBadNode.Props[origin].(string), certifyBadNode.Props[collector].(string))
					collectedCertifyBad = append(collectedCertifyBad, certifyBad)
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				return collectedCertifyBad, nil
			})
		if err != nil {
			return nil, err
		}

		aggregateCertifyBad = append(aggregateCertifyBad, result.([]*model.CertifyBad)...)
	}
	return aggregateCertifyBad, nil

}

func setCertifyBadValues(sb *strings.Builder, certifyBadSpec *model.CertifyBadSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyBadSpec.Justification != nil {
		matchProperties(sb, *firstMatch, "certifyBad", "justification", "$justification")
		*firstMatch = false
		queryValues["justification"] = certifyBadSpec.Justification
	}
	if certifyBadSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "certifyBad", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = certifyBadSpec.Origin
	}
	if certifyBadSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "certifyBad", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = certifyBadSpec.Collector
	}
}

func generateModelCertifyBad(subject model.PackageSourceOrArtifact, justification, origin, collector string) *model.CertifyBad {
	certifyBad := model.CertifyBad{
		Subject:       subject,
		Justification: justification,
		Origin:        origin,
		Collector:     collector,
	}
	return &certifyBad
}

// ingest certifyBad

func (c *neo4jClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {

	err := helper.CheckCertifyBadIngestionInput(subject)
	if err != nil {
		return nil, err
	}
	panic(fmt.Errorf("not implemented: IngestCertifyBad - IngestCertifyBad"))
}
