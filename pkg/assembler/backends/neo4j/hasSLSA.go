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
					var version *model.PackageVersion = nil
					if result.Record().Values[5] != nil && result.Record().Values[4] != nil && result.Record().Values[3] != nil {
						pkgQualifiers := getCollectedPackageQualifiers(result.Record().Values[5].([]interface{}))
						subPathString := result.Record().Values[4].(string)
						versionString := result.Record().Values[3].(string)
						version = &model.PackageVersion{
							Version:    versionString,
							Subpath:    subPathString,
							Qualifiers: pkgQualifiers,
						}
					}

					nameString := result.Record().Values[2].(string)
					namespaceString := result.Record().Values[1].(string)
					typeString := result.Record().Values[0].(string)

					versions := []*model.PackageVersion{}
					if version != nil {
						versions = append(versions, version)
					}
					name := &model.PackageName{
						Name:     nameString,
						Versions: versions,
					}

					namespace := &model.PackageNamespace{
						Namespace: namespaceString,
						Names:     []*model.PackageName{name},
					}
					pkg := model.Package{
						Type:       typeString,
						Namespaces: []*model.PackageNamespace{namespace},
					}

					if _, ok := resultHasSlsaMap[pkg]; !ok {
						builder := &model.Builder{
							URI: result.Record().Values[7].(string),
						}
						hasSLSANode := dbtype.Node{}
						if result.Record().Values[6] != nil {
							hasSLSANode = result.Record().Values[6].(dbtype.Node)
						} else {
							return nil, gqlerror.Errorf("HasSLSA Node not found in neo4j")
						}
						hasSLSA := &model.HasSlsa{
							Subject:       &pkg,
							BuiltBy:       builder,
							BuildType:     hasSLSANode.Props[buildType].(string),
							SlsaPredicate: getCollectedPredicate(hasSLSANode.Props[predicate].([]interface{})),
							SlsaVersion:   hasSLSANode.Props[slsaVersion].(string),
							StartedOn:     hasSLSANode.Props[startedOn].(string),
							FinishedOn:    hasSLSANode.Props[finishedOn].(string),
							Origin:        hasSLSANode.Props[origin].(string),
							Collector:     hasSLSANode.Props[collector].(string),
						}
						resultHasSlsaMap[pkg] = hasSLSA
					}

					if _, ok := resultBuiltFromMap[pkg]; !ok {
						resultBuiltFromMap[pkg] = []model.PkgSrcArtObject{}
					}

					if result.Record().Values[8] != nil && result.Record().Values[9] != nil {
						objArt := model.Artifact{
							Algorithm: result.Record().Values[7].(string),
							Digest:    result.Record().Values[8].(string),
						}
						if _, ok := resultBuiltFromMap[pkg]; ok {
							resultBuiltFromMap[pkg] = append(resultBuiltFromMap[pkg], objArt)
						}
					}

					if result.Record().Values[10] != nil && result.Record().Values[11] != nil && result.Record().Values[12] != nil {
						commitString := ""
						if result.Record().Values[14] != nil {
							commitString = result.Record().Values[14].(string)
						}
						tagString := ""
						if result.Record().Values[13] != nil {
							tagString = result.Record().Values[13].(string)
						}
						nameString := result.Record().Values[12].(string)
						namespaceString := result.Record().Values[11].(string)
						typeString := result.Record().Values[10].(string)

						srcName := &model.SourceName{
							Name:   nameString,
							Tag:    &tagString,
							Commit: &commitString,
						}

						srcNamespace := &model.SourceNamespace{
							Namespace: namespaceString,
							Names:     []*model.SourceName{srcName},
						}
						objSrc := model.Source{
							Type:       typeString,
							Namespaces: []*model.SourceNamespace{srcNamespace},
						}
						if _, ok := resultBuiltFromMap[pkg]; ok {
							resultBuiltFromMap[pkg] = append(resultBuiltFromMap[pkg], objSrc)
						}
					}

					if result.Record().Values[15] != nil && result.Record().Values[16] != nil && result.Record().Values[17] != nil {
						var version *model.PackageVersion = nil
						if result.Record().Values[20] != nil && result.Record().Values[19] != nil && result.Record().Values[18] != nil {
							pkgQualifiers := getCollectedPackageQualifiers(result.Record().Values[20].([]interface{}))
							subPathString := result.Record().Values[19].(string)
							versionString := result.Record().Values[18].(string)
							version = &model.PackageVersion{
								Version:    versionString,
								Subpath:    subPathString,
								Qualifiers: pkgQualifiers,
							}
						}

						nameString := result.Record().Values[17].(string)
						namespaceString := result.Record().Values[16].(string)
						typeString := result.Record().Values[15].(string)

						versions := []*model.PackageVersion{}
						if version != nil {
							versions = append(versions, version)
						}
						name := &model.PackageName{
							Name:     nameString,
							Versions: versions,
						}

						namespace := &model.PackageNamespace{
							Namespace: namespaceString,
							Names:     []*model.PackageName{name},
						}
						artPkg := model.Package{
							Type:       typeString,
							Namespaces: []*model.PackageNamespace{namespace},
						}
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

					if _, ok := resultHasSlsaMap[src]; !ok {
						builder := &model.Builder{
							URI: result.Record().Values[6].(string),
						}

						hasSLSANode := dbtype.Node{}
						if result.Record().Values[5] != nil {
							hasSLSANode = result.Record().Values[5].(dbtype.Node)
						} else {
							return nil, gqlerror.Errorf("HasSLSA Node not found in neo4j")
						}
						hasSLSA := &model.HasSlsa{
							Subject:       &src,
							BuiltBy:       builder,
							BuildType:     hasSLSANode.Props[buildType].(string),
							SlsaPredicate: getCollectedPredicate(hasSLSANode.Props[predicate].([]interface{})),
							SlsaVersion:   hasSLSANode.Props[slsaVersion].(string),
							StartedOn:     hasSLSANode.Props[startedOn].(string),
							FinishedOn:    hasSLSANode.Props[finishedOn].(string),
							Origin:        hasSLSANode.Props[origin].(string),
							Collector:     hasSLSANode.Props[collector].(string),
						}
						resultHasSlsaMap[src] = hasSLSA
					}

					if _, ok := resultBuiltFromMap[src]; !ok {
						resultBuiltFromMap[src] = []model.PkgSrcArtObject{}
					}

					if result.Record().Values[7] != nil && result.Record().Values[8] != nil {
						objArt := model.Artifact{
							Algorithm: result.Record().Values[7].(string),
							Digest:    result.Record().Values[8].(string),
						}
						if _, ok := resultBuiltFromMap[src]; ok {
							resultBuiltFromMap[src] = append(resultBuiltFromMap[src], objArt)
						}
					}

					if result.Record().Values[9] != nil && result.Record().Values[10] != nil && result.Record().Values[11] != nil {
						commitString := ""
						if result.Record().Values[13] != nil {
							commitString = result.Record().Values[14].(string)
						}
						tagString := ""
						if result.Record().Values[12] != nil {
							tagString = result.Record().Values[12].(string)
						}
						nameString := result.Record().Values[11].(string)
						namespaceString := result.Record().Values[10].(string)
						typeString := result.Record().Values[9].(string)

						srcName := &model.SourceName{
							Name:   nameString,
							Tag:    &tagString,
							Commit: &commitString,
						}

						srcNamespace := &model.SourceNamespace{
							Namespace: namespaceString,
							Names:     []*model.SourceName{srcName},
						}
						objSrc := &model.Source{
							Type:       typeString,
							Namespaces: []*model.SourceNamespace{srcNamespace},
						}
						if _, ok := resultBuiltFromMap[src]; ok {
							resultBuiltFromMap[src] = append(resultBuiltFromMap[src], objSrc)
						}
					}

					if result.Record().Values[14] != nil && result.Record().Values[15] != nil && result.Record().Values[16] != nil {
						var version *model.PackageVersion = nil
						if result.Record().Values[19] != nil && result.Record().Values[18] != nil && result.Record().Values[17] != nil {
							pkgQualifiers := getCollectedPackageQualifiers(result.Record().Values[19].([]interface{}))
							subPathString := result.Record().Values[18].(string)
							versionString := result.Record().Values[17].(string)
							version = &model.PackageVersion{
								Version:    versionString,
								Subpath:    subPathString,
								Qualifiers: pkgQualifiers,
							}
						}

						nameString := result.Record().Values[16].(string)
						namespaceString := result.Record().Values[15].(string)
						typeString := result.Record().Values[14].(string)

						versions := []*model.PackageVersion{}
						if version != nil {
							versions = append(versions, version)
						}
						name := &model.PackageName{
							Name:     nameString,
							Versions: versions,
						}

						namespace := &model.PackageNamespace{
							Namespace: namespaceString,
							Names:     []*model.PackageName{name},
						}
						artPkg := &model.Package{
							Type:       typeString,
							Namespaces: []*model.PackageNamespace{namespace},
						}
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
					artifact := model.Artifact{
						Algorithm: result.Record().Values[0].(string),
						Digest:    result.Record().Values[1].(string),
					}
					if _, ok := resultHasSlsaMap[artifact]; !ok {
						builder := &model.Builder{
							URI: result.Record().Values[3].(string),
						}

						hasSLSANode := dbtype.Node{}
						if result.Record().Values[2] != nil {
							hasSLSANode = result.Record().Values[2].(dbtype.Node)
						} else {
							return nil, gqlerror.Errorf("HasSLSA Node not found in neo4j")
						}
						hasSLSA := &model.HasSlsa{
							Subject:       &artifact,
							BuiltBy:       builder,
							BuildType:     hasSLSANode.Props[buildType].(string),
							SlsaPredicate: getCollectedPredicate(hasSLSANode.Props[predicate].([]interface{})),
							SlsaVersion:   hasSLSANode.Props[slsaVersion].(string),
							StartedOn:     hasSLSANode.Props[startedOn].(string),
							FinishedOn:    hasSLSANode.Props[finishedOn].(string),
							Origin:        hasSLSANode.Props[origin].(string),
							Collector:     hasSLSANode.Props[collector].(string),
						}
						resultHasSlsaMap[artifact] = hasSLSA
					}

					if _, ok := resultBuiltFromMap[artifact]; !ok {
						resultBuiltFromMap[artifact] = []model.PkgSrcArtObject{}
					}

					if result.Record().Values[4] != nil && result.Record().Values[5] != nil {
						objArt := model.Artifact{
							Algorithm: result.Record().Values[4].(string),
							Digest:    result.Record().Values[5].(string),
						}
						if _, ok := resultBuiltFromMap[artifact]; ok {
							resultBuiltFromMap[artifact] = append(resultBuiltFromMap[artifact], objArt)
						}
					}

					if result.Record().Values[6] != nil && result.Record().Values[7] != nil && result.Record().Values[8] != nil {
						commitString := ""
						if result.Record().Values[10] != nil {
							commitString = result.Record().Values[10].(string)
						}
						tagString := ""
						if result.Record().Values[9] != nil {
							tagString = result.Record().Values[9].(string)
						}
						nameString := result.Record().Values[8].(string)
						namespaceString := result.Record().Values[7].(string)
						typeString := result.Record().Values[6].(string)

						srcName := &model.SourceName{
							Name:   nameString,
							Tag:    &tagString,
							Commit: &commitString,
						}

						srcNamespace := &model.SourceNamespace{
							Namespace: namespaceString,
							Names:     []*model.SourceName{srcName},
						}
						objSrc := &model.Source{
							Type:       typeString,
							Namespaces: []*model.SourceNamespace{srcNamespace},
						}
						if _, ok := resultBuiltFromMap[artifact]; ok {
							resultBuiltFromMap[artifact] = append(resultBuiltFromMap[artifact], objSrc)
						}
					}

					if result.Record().Values[13] != nil && result.Record().Values[12] != nil && result.Record().Values[11] != nil {
						var version *model.PackageVersion = nil
						if result.Record().Values[16] != nil && result.Record().Values[15] != nil && result.Record().Values[14] != nil {
							pkgQualifiers := getCollectedPackageQualifiers(result.Record().Values[16].([]interface{}))
							subPathString := result.Record().Values[15].(string)
							versionString := result.Record().Values[14].(string)
							version = &model.PackageVersion{
								Version:    versionString,
								Subpath:    subPathString,
								Qualifiers: pkgQualifiers,
							}
						}

						nameString := result.Record().Values[13].(string)
						namespaceString := result.Record().Values[12].(string)
						typeString := result.Record().Values[11].(string)

						versions := []*model.PackageVersion{}
						if version != nil {
							versions = append(versions, version)
						}
						name := &model.PackageName{
							Name:     nameString,
							Versions: versions,
						}

						namespace := &model.PackageNamespace{
							Namespace: namespaceString,
							Names:     []*model.PackageName{name},
						}
						artPkg := &model.Package{
							Type:       typeString,
							Namespaces: []*model.PackageNamespace{namespace},
						}
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
