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

func (c *neo4jClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {
	certifyPkg := false
	certifySrc := false
	certifyArt := false
	if certifyBadSpec.Package != nil {
		certifyPkg = true
	}
	if certifyBadSpec.Source != nil {
		certifySrc = true
	}
	if certifyBadSpec.Artifact != nil {
		certifyArt = true
	}

	if certifyPkg && certifySrc && certifyArt {
		return nil, gqlerror.Errorf("cannot specify package, source and artifact together for CertifyBad")
	}
	if certifyPkg && certifySrc {
		return nil, gqlerror.Errorf("cannot specify package and source together for CertifyBad")
	}
	if certifyPkg && certifyArt {
		return nil, gqlerror.Errorf("cannot specify package and artifact together for CertifyBad")
	}
	if certifySrc && certifyArt {
		return nil, gqlerror.Errorf("cannot specify source and artifact together for CertifyBad")
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true

	queryValues := map[string]any{}

	if certifyPkg {
		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, certifyBad"
		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[certifyBad:CertifyBad]"
		sb.WriteString(query)

		setPkgMatchValues(&sb, certifyBadSpec.Package, false, firstMatch, queryValues)
		setCertifyBadValues(&sb, certifyBadSpec, firstMatch, queryValues)
		sb.WriteString(returnValue)

		if certifyBadSpec.Package.Version == nil && certifyBadSpec.Package.Subpath == nil &&
			len(certifyBadSpec.Package.Qualifiers) == 0 && !*certifyBadSpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query = "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)" +
				"-[certifyBad:CertifyBad]" +
				"\nWITH *, null AS version"
			sb.WriteString(query)

			firstMatch = true
			setPkgMatchValues(&sb, certifyBadSpec.Package, false, firstMatch, queryValues)
			setCertifyBadValues(&sb, certifyBadSpec, firstMatch, queryValues)
			sb.WriteString(returnValue)
		}
	}
	if certifySrc {
		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName)-[certifyBad:CertifyBad]"
		sb.WriteString(query)

		setSrcMatchValues(&sb, certifyBadSpec.Source, false, firstMatch, queryValues)
		setCertifyBadValues(&sb, certifyBadSpec, firstMatch, queryValues)
		sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, certifyBad")
	}

	if certifyArt {
		query := "MATCH (a:Artifact)-[certifyBad:CertifyBad]"
		sb.WriteString(query)

		setSrcMatchValues(&sb, certifyBadSpec.Source, false, firstMatch, queryValues)
		setCertifyBadValues(&sb, certifyBadSpec, firstMatch, queryValues)
		sb.WriteString(" RETURN a.algorithm, a.digest, certifyBad")
	}

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedCertifyBad := []*model.CertifyBad{}

			for result.Next() {
				if certifyPkg {
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
					certifyBadEdge := dbtype.Relationship{}
					if result.Record().Values[6] != nil {
						certifyBadEdge = result.Record().Values[6].(dbtype.Relationship)
					} else {
						return nil, gqlerror.Errorf("certifyBadEdge not found in neo4j")
					}

					certifyBad := &model.CertifyBad{
						Subject:       &pkg,
						Justification: certifyBadEdge.Props[justification].(string),
						Origin:        certifyBadEdge.Props[origin].(string),
						Collector:     certifyBadEdge.Props[collector].(string),
					}
					collectedCertifyBad = append(collectedCertifyBad, certifyBad)
				}
				if certifySrc {
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
					certifyBadEdge := dbtype.Relationship{}
					if result.Record().Values[5] != nil {
						certifyBadEdge = result.Record().Values[5].(dbtype.Relationship)
					} else {
						return nil, gqlerror.Errorf("certifyBadEdge not found in neo4j")
					}

					certifyBad := &model.CertifyBad{
						Subject:       &src,
						Justification: certifyBadEdge.Props[justification].(string),
						Origin:        certifyBadEdge.Props[origin].(string),
						Collector:     certifyBadEdge.Props[collector].(string),
					}
					collectedCertifyBad = append(collectedCertifyBad, certifyBad)
				}
				if certifyArt {
					artifact := model.Artifact{
						Algorithm: result.Record().Values[0].(string),
						Digest:    result.Record().Values[1].(string),
					}
					certifyBadEdge := dbtype.Relationship{}
					if result.Record().Values[2] != nil {
						certifyBadEdge = result.Record().Values[2].(dbtype.Relationship)
					} else {
						return nil, gqlerror.Errorf("certifyBadEdge not found in neo4j")
					}

					certifyBad := &model.CertifyBad{
						Subject:       &artifact,
						Justification: certifyBadEdge.Props[justification].(string),
						Origin:        certifyBadEdge.Props[origin].(string),
						Collector:     certifyBadEdge.Props[collector].(string),
					}
					collectedCertifyBad = append(collectedCertifyBad, certifyBad)
				}
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return collectedCertifyBad, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.CertifyBad), nil
}

func setCertifyBadValues(sb *strings.Builder, certifyBadSpec *model.CertifyBadSpec, firstMatch bool, queryValues map[string]any) {
	if certifyBadSpec.Justification != nil {

		matchProperties(sb, firstMatch, "certifyBad", "justification", "$justification")
		firstMatch = false
		queryValues["justification"] = certifyBadSpec.Justification
	}
	if certifyBadSpec.Origin != nil {

		matchProperties(sb, firstMatch, "certifyBad", "origin", "$origin")
		firstMatch = false
		queryValues["origin"] = certifyBadSpec.Origin
	}
	if certifyBadSpec.Collector != nil {

		matchProperties(sb, firstMatch, "certifyBad", "collector", "$collector")
		firstMatch = false
		queryValues["collector"] = certifyBadSpec.Collector
	}
}
