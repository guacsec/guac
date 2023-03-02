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
	"sort"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	buildType   string = "buildType"
	predicate   string = "predicate"
	slsaVersion string = "slsaVersion"
	startedOn   string = "startedOn"
	finishedOn  string = "finishedOn"
)

func (c *neo4jClient) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	err := checkHasSLSAInputs(hasSLSASpec)
	if err != nil {
		return nil, err
	}

	queryAll := false
	if hasSLSASpec.Package == nil && hasSLSASpec.Source == nil && hasSLSASpec.Artifact == nil {
		queryAll = true
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	aggregateHasSLSA := []*model.HasSlsa{}

	if hasSLSASpec.Package != nil || queryAll {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		returnValue := " RETURN type.type, namespace.namespace, name.name, version.version, version.subpath, " +
			"version.qualifier_list, hasSLSA, b.uri, objArt.algorithm, objArt.digest, " +
			"objSrcType.type, objSrcNamespace.namespace, objSrcName.name, objSrcName.tag, objSrcName.commit, " +
			"objPkgType.type, objPkgNamespace.namespace, objPkgName.name, " +
			"objPkgVersion.version, objPkgVersion.subpath, objPkgVersion.qualifier_list"
		// query with pkgVersion
		query := "MATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
			"-[:PkgHasName]->(name:PkgName)-[:PkgHasVersion]->(version:PkgVersion)" +
			"-[:subject]-(hasSLSA:HasSLSA)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:built_by]->(b:Builder)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objArt:Artifact)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objSrcName:SrcName)<-[:SrcHasName]-(objSrcNamespace:SrcNamespace)<-[:SrcHasNamespace]" +
			"-(objSrcType:SrcType)<-[:SrcHasType]-(objSrcRoot:Src)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objPkgVersion:PkgVersion)<-[:PkgHasVersion]-(objPkgName:PkgName)<-[:PkgHasName]" +
			"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objPkgName:PkgName)<-[:PkgHasName]" +
			"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, hasSLSA, null AS objPkgVersion"

		sb.WriteString(query)
		setPkgMatchValues(&sb, hasSLSASpec.Package, false, &firstMatch, queryValues)
		setHasSLSAValues(&sb, hasSLSASpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		if hasSLSASpec.Package == nil || hasSLSASpec.Package != nil && hasSLSASpec.Package.Version == nil && hasSLSASpec.Package.Subpath == nil &&
			len(hasSLSASpec.Package.Qualifiers) == 0 && !*hasSLSASpec.Package.MatchOnlyEmptyQualifiers {

			sb.WriteString("\nUNION")
			// query without pkgVersion
			query := "\nMATCH (root:Pkg)-[:PkgHasType]->(type:PkgType)-[:PkgHasNamespace]->(namespace:PkgNamespace)" +
				"-[:PkgHasName]->(name:PkgName)" +
				"-[:subject]-(hasSLSA:HasSLSA)" +
				"\nWITH *, hasSLSA" +
				"\nMATCH (hasSLSA)-[:built_by]->(b:Builder)" +
				"\nWITH *, hasSLSA" +
				"\nMATCH (hasSLSA)-[:BuildFrom]->(objArt:Artifact)" +
				"\nWITH *, hasSLSA" +
				"\nMATCH (hasSLSA)-[:BuildFrom]->(objSrcName:SrcName)<-[:SrcHasName]-(objSrcNamespace:SrcNamespace)<-[:SrcHasNamespace]" +
				"-(objSrcType:SrcType)<-[:SrcHasType]-(objSrcRoot:Src)" +
				"\nWITH *, hasSLSA" +
				"\nMATCH (hasSLSA)-[:BuildFrom]->(objPkgVersion:PkgVersion)<-[:PkgHasVersion]-(objPkgName:PkgName)<-[:PkgHasName]" +
				"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
				"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
				"\nWITH *, hasSLSA" +
				"\nMATCH (hasSLSA)-[:BuildFrom]->(objPkgName:PkgName)<-[:PkgHasName]" +
				"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
				"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
				"\nWITH *, hasSLSA, null AS version, null AS objPkgVersion"

			sb.WriteString(query)
			firstMatch = true
			setPkgMatchValues(&sb, hasSLSASpec.Package, false, &firstMatch, queryValues)
			setHasSLSAValues(&sb, hasSLSASpec, &firstMatch, queryValues)
			sb.WriteString(returnValue)
		}

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				resultBuiltFromMap := map[model.PkgSrcArtObject][]model.PkgSrcArtObject{}
				resultHasSlsaMap := map[model.PkgSrcArtObject]*model.HasSlsa{}
				for result.Next() {
					pkgQualifiers := result.Record().Values[5]
					subPath := result.Record().Values[4]
					version := result.Record().Values[3]
					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					pkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

					if _, ok := resultHasSlsaMap[pkg]; !ok {
						uri := result.Record().Values[7].(string)
						builder := generateModelBuilder(uri)
						hasSLSANode := dbtype.Node{}
						if result.Record().Values[6] != nil {
							hasSLSANode = result.Record().Values[6].(dbtype.Node)
						} else {
							return nil, gqlerror.Errorf("HasSLSA Node not found in neo4j")
						}
						hasSLSA := generateModelHasSLSA(pkg, &builder, hasSLSANode.Props[predicate].([]interface{}), hasSLSANode.Props[buildType].(string),
							hasSLSANode.Props[slsaVersion].(string), hasSLSANode.Props[startedOn].(string), hasSLSANode.Props[finishedOn].(string),
							hasSLSANode.Props[origin].(string), hasSLSANode.Props[collector].(string))

						resultHasSlsaMap[pkg] = &hasSLSA
					}

					if _, ok := resultBuiltFromMap[pkg]; !ok {
						resultBuiltFromMap[pkg] = []model.PkgSrcArtObject{}
					}

					if result.Record().Values[8] != nil && result.Record().Values[9] != nil {

						algorithm := result.Record().Values[7].(string)
						digest := result.Record().Values[8].(string)
						objArt := generateModelArtifact(algorithm, digest)

						if _, ok := resultBuiltFromMap[pkg]; ok {
							resultBuiltFromMap[pkg] = append(resultBuiltFromMap[pkg], objArt)
						}
					}

					if result.Record().Values[10] != nil && result.Record().Values[11] != nil && result.Record().Values[12] != nil {
						tag := result.Record().Values[13]
						commit := result.Record().Values[14]
						nameStr := result.Record().Values[12].(string)
						namespaceStr := result.Record().Values[11].(string)
						srcType := result.Record().Values[10].(string)

						objSrc := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

						if _, ok := resultBuiltFromMap[pkg]; ok {
							resultBuiltFromMap[pkg] = append(resultBuiltFromMap[pkg], objSrc)
						}
					}

					if result.Record().Values[15] != nil && result.Record().Values[16] != nil && result.Record().Values[17] != nil {

						pkgQualifiers := result.Record().Values[20]
						subPath := result.Record().Values[19]
						version := result.Record().Values[18]
						nameString := result.Record().Values[17].(string)
						namespaceString := result.Record().Values[16].(string)
						typeString := result.Record().Values[15].(string)

						artPkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

						if _, ok := resultBuiltFromMap[pkg]; ok {
							resultBuiltFromMap[pkg] = append(resultBuiltFromMap[pkg], artPkg)
						}
					}
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				collectedHasSLSA := []*model.HasSlsa{}
				for subject, hasSLSA := range resultHasSlsaMap {
					if builtFrom, ok := resultBuiltFromMap[subject]; ok {
						hasSLSA.BuiltFrom = builtFrom
					}
					collectedHasSLSA = append(collectedHasSLSA, hasSLSA)
				}
				return collectedHasSLSA, nil
			})
		if err != nil {
			return nil, err
		}

		aggregateHasSLSA = append(aggregateHasSLSA, result.([]*model.HasSlsa)...)
	}

	if hasSLSASpec.Source != nil || queryAll {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		returnValue := " RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, " +
			"hasSLSA, b.uri, objArt.algorithm, objArt.digest, " +
			"objSrcType.type, objSrcNamespace.namespace, objSrcName.name, objSrcName.tag, objSrcName.commit, " +
			"objPkgType.type, objPkgNamespace.namespace, objPkgName.name, " +
			"objPkgVersion.version, objPkgVersion.subpath, objPkgVersion.qualifier_list"
		// query with pkgVersion
		query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
			"-[:SrcHasName]->(name:SrcName)" +
			"-[:subject]-(hasSLSA:HasSLSA)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:built_by]->(b:Builder)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objArt:Artifact)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objSrcName:SrcName)<-[:SrcHasName]-(objSrcNamespace:SrcNamespace)<-[:SrcHasNamespace]" +
			"-(objSrcType:SrcType)<-[:SrcHasType]-(objSrcRoot:Src)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objPkgVersion:PkgVersion)<-[:PkgHasVersion]-(objPkgName:PkgName)<-[:PkgHasName]" +
			"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objPkgName:PkgName)<-[:PkgHasName]" +
			"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, hasSLSA, null AS objPkgVersion"

		sb.WriteString(query)
		setSrcMatchValues(&sb, hasSLSASpec.Source, false, &firstMatch, queryValues)
		setHasSLSAValues(&sb, hasSLSASpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				resultBuiltFromMap := map[model.PkgSrcArtObject][]model.PkgSrcArtObject{}
				resultHasSlsaMap := map[model.PkgSrcArtObject]*model.HasSlsa{}

				for result.Next() {
					tag := result.Record().Values[3]
					commit := result.Record().Values[4]
					nameStr := result.Record().Values[2].(string)
					namespaceStr := result.Record().Values[1].(string)
					srcType := result.Record().Values[0].(string)

					src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

					if _, ok := resultHasSlsaMap[src]; !ok {
						uri := result.Record().Values[6].(string)
						builder := generateModelBuilder(uri)

						hasSLSANode := dbtype.Node{}
						if result.Record().Values[5] != nil {
							hasSLSANode = result.Record().Values[5].(dbtype.Node)
						} else {
							return nil, gqlerror.Errorf("HasSLSA Node not found in neo4j")
						}
						hasSLSA := generateModelHasSLSA(src, &builder, hasSLSANode.Props[predicate].([]interface{}), hasSLSANode.Props[buildType].(string),
							hasSLSANode.Props[slsaVersion].(string), hasSLSANode.Props[startedOn].(string), hasSLSANode.Props[finishedOn].(string),
							hasSLSANode.Props[origin].(string), hasSLSANode.Props[collector].(string))

						resultHasSlsaMap[src] = &hasSLSA
					}

					if _, ok := resultBuiltFromMap[src]; !ok {
						resultBuiltFromMap[src] = []model.PkgSrcArtObject{}
					}

					if result.Record().Values[7] != nil && result.Record().Values[8] != nil {
						algorithm := result.Record().Values[7].(string)
						digest := result.Record().Values[8].(string)
						objArt := generateModelArtifact(algorithm, digest)
						if _, ok := resultBuiltFromMap[src]; ok {
							resultBuiltFromMap[src] = append(resultBuiltFromMap[src], objArt)
						}
					}

					if result.Record().Values[9] != nil && result.Record().Values[10] != nil && result.Record().Values[11] != nil {
						tag := result.Record().Values[12]
						commit := result.Record().Values[13]
						nameStr := result.Record().Values[11].(string)
						namespaceStr := result.Record().Values[10].(string)
						srcType := result.Record().Values[9].(string)

						objSrc := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

						if _, ok := resultBuiltFromMap[src]; ok {
							resultBuiltFromMap[src] = append(resultBuiltFromMap[src], objSrc)
						}
					}

					if result.Record().Values[14] != nil && result.Record().Values[15] != nil && result.Record().Values[16] != nil {
						pkgQualifiers := result.Record().Values[19]
						subPath := result.Record().Values[18]
						version := result.Record().Values[17]
						nameString := result.Record().Values[16].(string)
						namespaceString := result.Record().Values[15].(string)
						typeString := result.Record().Values[14].(string)

						artPkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)
						if _, ok := resultBuiltFromMap[src]; ok {
							resultBuiltFromMap[src] = append(resultBuiltFromMap[src], artPkg)
						}
					}
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				collectedHasSLSA := []*model.HasSlsa{}
				for subject, hasSLSA := range resultHasSlsaMap {
					if builtFrom, ok := resultBuiltFromMap[subject]; ok {
						hasSLSA.BuiltFrom = builtFrom
					}
					collectedHasSLSA = append(collectedHasSLSA, hasSLSA)
				}

				return collectedHasSLSA, nil
			})
		if err != nil {
			return nil, err
		}
		aggregateHasSLSA = append(aggregateHasSLSA, result.([]*model.HasSlsa)...)
	}

	if hasSLSASpec.Artifact != nil || queryAll {
		var sb strings.Builder
		var firstMatch bool = true
		queryValues := map[string]any{}

		returnValue := " RETURN a.algorithm, a.digest, " +
			"hasSLSA, b.uri, objArt.algorithm, objArt.digest, " +
			"objSrcType.type, objSrcNamespace.namespace, objSrcName.name, objSrcName.tag, objSrcName.commit, " +
			"objPkgType.type, objPkgNamespace.namespace, objPkgName.name, " +
			"objPkgVersion.version, objPkgVersion.subpath, objPkgVersion.qualifier_list"
		// query with pkgVersion
		query := "MATCH (a:Artifact)-[:subject]-(hasSLSA:HasSLSA)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:built_by]->(b:Builder)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objArt:Artifact)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objSrcName:SrcName)<-[:SrcHasName]-(objSrcNamespace:SrcNamespace)<-[:SrcHasNamespace]" +
			"-(objSrcType:SrcType)<-[:SrcHasType]-(objSrcRoot:Src)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objPkgVersion:PkgVersion)<-[:PkgHasVersion]-(objPkgName:PkgName)<-[:PkgHasName]" +
			"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, hasSLSA" +
			"\nMATCH (hasSLSA)-[:BuildFrom]->(objPkgName:PkgName)<-[:PkgHasName]" +
			"-(objPkgNamespace:PkgNamespace)<-[:PkgHasNamespace]" +
			"-(objPkgType:PkgType)<-[:PkgHasType]-(objPkgRoot:Pkg)" +
			"\nWITH *, hasSLSA, null AS objPkgVersion"

		sb.WriteString(query)
		setArtifactMatchValues(&sb, hasSLSASpec.Artifact, false, &firstMatch, queryValues)
		setHasSLSAValues(&sb, hasSLSASpec, &firstMatch, queryValues)
		sb.WriteString(returnValue)

		result, err := session.ReadTransaction(
			func(tx neo4j.Transaction) (interface{}, error) {

				result, err := tx.Run(sb.String(), queryValues)
				if err != nil {
					return nil, err
				}

				resultBuiltFromMap := map[model.PkgSrcArtObject][]model.PkgSrcArtObject{}
				resultHasSlsaMap := map[model.PkgSrcArtObject]*model.HasSlsa{}

				for result.Next() {
					algorithm := result.Record().Values[0].(string)
					digest := result.Record().Values[1].(string)
					artifact := generateModelArtifact(algorithm, digest)

					if _, ok := resultHasSlsaMap[artifact]; !ok {
						uri := result.Record().Values[3].(string)
						builder := generateModelBuilder(uri)

						hasSLSANode := dbtype.Node{}
						if result.Record().Values[2] != nil {
							hasSLSANode = result.Record().Values[2].(dbtype.Node)
						} else {
							return nil, gqlerror.Errorf("HasSLSA Node not found in neo4j")
						}
						hasSLSA := generateModelHasSLSA(artifact, &builder, hasSLSANode.Props[predicate].([]interface{}), hasSLSANode.Props[buildType].(string),
							hasSLSANode.Props[slsaVersion].(string), hasSLSANode.Props[startedOn].(string), hasSLSANode.Props[finishedOn].(string),
							hasSLSANode.Props[origin].(string), hasSLSANode.Props[collector].(string))

						resultHasSlsaMap[artifact] = &hasSLSA
					}

					if _, ok := resultBuiltFromMap[artifact]; !ok {
						resultBuiltFromMap[artifact] = []model.PkgSrcArtObject{}
					}

					if result.Record().Values[4] != nil && result.Record().Values[5] != nil {
						algorithm := result.Record().Values[4].(string)
						digest := result.Record().Values[5].(string)
						objArt := generateModelArtifact(algorithm, digest)
						if _, ok := resultBuiltFromMap[artifact]; ok {
							resultBuiltFromMap[artifact] = append(resultBuiltFromMap[artifact], objArt)
						}
					}

					if result.Record().Values[6] != nil && result.Record().Values[7] != nil && result.Record().Values[8] != nil {
						tag := result.Record().Values[9]
						commit := result.Record().Values[10]
						nameStr := result.Record().Values[8].(string)
						namespaceStr := result.Record().Values[7].(string)
						srcType := result.Record().Values[6].(string)

						objSrc := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

						if _, ok := resultBuiltFromMap[artifact]; ok {
							resultBuiltFromMap[artifact] = append(resultBuiltFromMap[artifact], objSrc)
						}
					}

					if result.Record().Values[13] != nil && result.Record().Values[12] != nil && result.Record().Values[11] != nil {

						pkgQualifiers := result.Record().Values[16]
						subPath := result.Record().Values[15]
						version := result.Record().Values[14]
						nameString := result.Record().Values[13].(string)
						namespaceString := result.Record().Values[12].(string)
						typeString := result.Record().Values[11].(string)

						artPkg := generateModelPackage(typeString, namespaceString, nameString, version, subPath, pkgQualifiers)

						if _, ok := resultBuiltFromMap[artifact]; ok {
							resultBuiltFromMap[artifact] = append(resultBuiltFromMap[artifact], artPkg)
						}
					}
				}
				if err = result.Err(); err != nil {
					return nil, err
				}

				collectedHasSLSA := []*model.HasSlsa{}
				for subject, hasSLSA := range resultHasSlsaMap {
					if builtFrom, ok := resultBuiltFromMap[subject]; ok {
						hasSLSA.BuiltFrom = builtFrom
					}
					collectedHasSLSA = append(collectedHasSLSA, hasSLSA)
				}

				return collectedHasSLSA, nil
			})
		if err != nil {
			return nil, err
		}

		aggregateHasSLSA = append(aggregateHasSLSA, result.([]*model.HasSlsa)...)
	}
	return aggregateHasSLSA, nil

}

// TODO (pxp928): combine with testing backend in shared utility
func checkHasSLSAInputs(hasSLSASpec *model.HasSLSASpec) error {
	invalidSubject := false
	if hasSLSASpec.Package != nil && hasSLSASpec.Source != nil && hasSLSASpec.Artifact != nil {
		invalidSubject = true
	}
	if hasSLSASpec.Package != nil && hasSLSASpec.Source != nil {
		invalidSubject = true
	}
	if hasSLSASpec.Package != nil && hasSLSASpec.Artifact != nil {
		invalidSubject = true
	}
	if hasSLSASpec.Source != nil && hasSLSASpec.Artifact != nil {
		invalidSubject = true
	}
	if invalidSubject {
		return gqlerror.Errorf("cannot specify more than one subject for CertifyBad query")
	}
	return nil
}

func getCollectedPredicate(predicateList []interface{}) []*model.SLSAPredicate {
	predicate := []*model.SLSAPredicate{}
	for i := range predicateList {
		if i%2 == 0 {
			value := &model.SLSAPredicate{
				Key:   predicateList[i].(string),
				Value: predicateList[i+1].(string),
			}
			predicate = append(predicate, value)
		}
	}
	return predicate
}

func getPredicateValuesFromSpec(slsaPredicate []*model.SLSAPredicateSpec) []string {
	predicateMap := map[string]string{}
	keys := []string{}
	for _, kv := range slsaPredicate {
		key := removeInvalidCharFromProperty(kv.Key)
		predicateMap[key] = kv.Value
		keys = append(keys, key)
	}
	sort.Strings(keys)
	predicateValues := []string{}
	for _, k := range keys {
		predicateValues = append(predicateValues, k, predicateMap[k])
	}
	return predicateValues
}

func setHasSLSAValues(sb *strings.Builder, hasSLSASpec *model.HasSLSASpec, firstMatch *bool, queryValues map[string]any) {
	if hasSLSASpec.BuildType != nil {
		matchProperties(sb, *firstMatch, "hasSLSA", buildType, "$"+buildType)
		*firstMatch = false
		queryValues[buildType] = hasSLSASpec.BuildType
	}
	if len(hasSLSASpec.Predicate) > 0 {
		predicateValues := getPredicateValuesFromSpec(hasSLSASpec.Predicate)
		matchProperties(sb, *firstMatch, "hasSLSA", predicate, "$"+predicate)
		*firstMatch = false
		queryValues[predicate] = predicateValues
	}
	if hasSLSASpec.SlsaVersion != nil {
		matchProperties(sb, *firstMatch, "hasSLSA", slsaVersion, "$"+slsaVersion)
		*firstMatch = false
		queryValues[slsaVersion] = hasSLSASpec.SlsaVersion
	}
	if hasSLSASpec.StartedOn != nil {
		matchProperties(sb, *firstMatch, "hasSLSA", startedOn, "$"+startedOn)
		*firstMatch = false
		queryValues[startedOn] = hasSLSASpec.StartedOn
	}
	if hasSLSASpec.FinishedOn != nil {
		matchProperties(sb, *firstMatch, "hasSLSA", finishedOn, "$"+finishedOn)
		*firstMatch = false
		queryValues[finishedOn] = hasSLSASpec.FinishedOn
	}
	if hasSLSASpec.Origin != nil {
		matchProperties(sb, *firstMatch, "hasSLSA", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = hasSLSASpec.Origin
	}
	if hasSLSASpec.Collector != nil {
		matchProperties(sb, *firstMatch, "hasSLSA", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = hasSLSASpec.Collector
	}
}

func generateModelHasSLSA(subject model.PkgSrcArtObject, builder *model.Builder, slsaPredicate []interface{}, buildType,
	slsaVersion, startedOn, finishedOn, origin, collector string) model.HasSlsa {
	hasSLSA := model.HasSlsa{
		Subject:       subject,
		BuiltBy:       builder,
		BuildType:     buildType,
		SlsaPredicate: getCollectedPredicate(slsaPredicate),
		SlsaVersion:   slsaVersion,
		StartedOn:     startedOn,
		FinishedOn:    finishedOn,
		Origin:        origin,
		Collector:     collector,
	}
	return hasSLSA
}
