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

package arangodb

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

type SrcIds struct {
	TypeId      string
	NamespaceId string
	NameId      string
}

func guacSrcId(src model.SourceInputSpec) SrcIds {
	ids := SrcIds{}

	ids.TypeId = src.Type

	var ns string
	if src.Namespace != "" {
		ns = src.Namespace
	} else {
		ns = guacEmpty
	}
	ids.NamespaceId = fmt.Sprintf("%s::%s", ids.TypeId, ns)

	var tag string
	if src.Tag != nil {
		if *src.Tag != "" {
			tag = *src.Tag
		} else {
			tag = guacEmpty
		}
	}

	var commit string
	if src.Commit != nil {
		if *src.Commit != "" {
			commit = *src.Commit
		} else {
			commit = guacEmpty
		}
	}

	ids.NameId = fmt.Sprintf("%s::%s::%s::%s?", ids.NamespaceId, src.Name, tag, commit)
	return ids
}

func (c *arangoClient) IngestSources(ctx context.Context, sources []*model.SourceInputSpec) ([]*model.Source, error) {
	listOfValues := []map[string]any{}

	for i := range sources {
		values := map[string]any{}

		// add guac keys
		values["typeID"] = c.pkgTypeMap[pkgs[i].Type].Id
		values["typeKey"] = c.pkgTypeMap[pkgs[i].Type].Key
		values["typeValue"] = c.pkgTypeMap[pkgs[i].Type].PkgType

		guacIds := guacPkgId(*pkgs[i])
		values["guacNsKey"] = guacIds.NamespaceId
		values["guacNameKey"] = guacIds.NameId
		values["guacVersionKey"] = guacIds.VersionId

		values["name"] = pkgs[i].Name
		if pkgs[i].Namespace != nil {
			values["namespace"] = *pkgs[i].Namespace
		} else {
			values["namespace"] = ""
		}
		if pkgs[i].Version != nil {
			values["version"] = *pkgs[i].Version
		} else {
			values["version"] = ""
		}
		if pkgs[i].Subpath != nil {
			values["subpath"] = *pkgs[i].Subpath
		} else {
			values["subpath"] = ""
		}

		// To ensure consistency, always sort the qualifiers by key
		qualifiersMap := map[string]string{}
		keys := []string{}
		for _, kv := range pkgs[i].Qualifiers {
			qualifiersMap[kv.Key] = kv.Value
			keys = append(keys, kv.Key)
		}
		sort.Strings(keys)
		qualifiers := []string{}
		for _, k := range keys {
			qualifiers = append(qualifiers, k, qualifiersMap[k])
		}
		values["qualifier"] = qualifiers

		listOfValues = append(listOfValues, values)
	}

	var documents []string
	for _, val := range listOfValues {
		bs, _ := json.Marshal(val)
		documents = append(documents, string(bs))
	}

	queryValues := map[string]any{}
	queryValues["documents"] = fmt.Sprint(strings.Join(documents, ","))

	var sb strings.Builder

	sb.WriteString("for doc in [")
	for i, val := range listOfValues {
		bs, _ := json.Marshal(val)
		if i == len(listOfValues)-1 {
			sb.WriteString(string(bs))
		} else {
			sb.WriteString(string(bs) + ",")
		}
	}
	sb.WriteString("]")

	query := `	  
	LET ns = FIRST(
	  UPSERT { namespace: doc.namespace, _parent: doc.typeID , guacKey: doc.guacNsKey}
	  INSERT { namespace: doc.namespace, _parent: doc.typeID , guacKey: doc.guacNsKey}
	  UPDATE {}
	  IN PkgNamespace OPTIONS { indexHint: "byNamespaceParent" }
	  RETURN NEW
	)
	
	LET name = FIRST(
	  UPSERT { name: doc.name, _parent: ns._id, guacKey: doc.guacNameKey}
	  INSERT { name: doc.name, _parent: ns._id, guacKey: doc.guacNameKey}
	  UPDATE {}
	  IN PkgName OPTIONS { indexHint: "byNameParent" }
	  RETURN NEW
	)
	
	LET pkgVersionObj = FIRST(
	  UPSERT { version: doc.version, subpath: doc.subpath, qualifier_list: doc.qualifier, _parent: name._id, guacKey: doc.guacVersionKey}
	  INSERT { version: doc.version, subpath: doc.subpath, qualifier_list: doc.qualifier, _parent: name._id, guacKey: doc.guacVersionKey}
	  UPDATE {}
	  IN PkgVersion OPTIONS { indexHint: "byAllVersionParent" }
	  RETURN NEW
	)
  
	LET pkgHasNamespaceCollection = (
	  INSERT { _key: CONCAT("pkgHasNamespace", doc.typeKey, ns._key), _from: doc.typeID, _to: ns._id, label : "PkgHasNamespace"} INTO PkgHasNamespace OPTIONS { overwriteMode: "ignore" }
	)
	
	LET pkgHasNameCollection = (
	  INSERT { _key: CONCAT("pkgHasName", ns._key, name._key), _from: ns._id, _to: name._id, label : "PkgHasName"} INTO PkgHasName OPTIONS { overwriteMode: "ignore" }
	)
	
	LET pkgHasVersionCollection = (
	  INSERT { _key: CONCAT("pkgHasVersion", name._key, pkgVersionObj._key), _from: name._id, _to: pkgVersionObj._id, label : "PkgHasVersion"} INTO PkgHasVersion OPTIONS { overwriteMode: "ignore" }
	)
	  
  RETURN {
  "type": doc.typeValue,
  "namespace": ns.namespace,
  "name": name.name,
  "version": pkgVersionObj.version,
  "subpath": pkgVersionObj.subpath,
  "qualifier_list": pkgVersionObj.qualifier_list
}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestPackages")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}

	type collectedData struct {
		PkgType       string      `json:"type"`
		Namespace     string      `json:"namespace"`
		Name          string      `json:"name"`
		Version       string      `json:"version"`
		Subpath       string      `json:"subpath"`
		QualifierList interface{} `json:"qualifier_list"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				cursor.Close()
				break
			} else {
				return nil, fmt.Errorf("failed to ingest package: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var packageList []*model.Package
	for _, createdValue := range createdValues {
		pkg, err := generateModelPackage(createdValue.PkgType, createdValue.Namespace,
			createdValue.Name, createdValue.Version, createdValue.Subpath, createdValue.QualifierList)
		if err != nil {
			return nil, fmt.Errorf("failed to get model.package with err: %w", err)
		}
		packageList = append(packageList, pkg)
	}

	return packageList, nil
}

func (c *arangoClient) IngestSource(ctx context.Context, source model.SourceInputSpec) (*model.Source, error) {

	values := map[string]any{}
	values["name"] = pkg.Name
	if pkg.Namespace != nil {
		values["namespace"] = *pkg.Namespace
	} else {
		values["namespace"] = ""
	}
	if pkg.Version != nil {
		values["version"] = *pkg.Version
	} else {
		values["version"] = ""
	}
	if pkg.Subpath != nil {
		values["subpath"] = *pkg.Subpath
	} else {
		values["subpath"] = ""
	}

	// To ensure consistency, always sort the qualifiers by key
	qualifiersMap := map[string]string{}
	keys := []string{}
	for _, kv := range pkg.Qualifiers {
		qualifiersMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	qualifiers := []string{}
	for _, k := range keys {
		qualifiers = append(qualifiers, k, qualifiersMap[k])
	}
	values["qualifier"] = qualifiers
	values["typeID"] = c.pkgTypeMap[pkg.Type].Id
	values["typeKey"] = c.pkgTypeMap[pkg.Type].Key
	values["typeValue"] = c.pkgTypeMap[pkg.Type].PkgType

	guacIds := guacPkgId(pkg)
	values["guacNsKey"] = guacIds.NamespaceId
	values["guacNameKey"] = guacIds.NameId
	values["guacVersionKey"] = guacIds.VersionId

	query := `	  
	  LET ns = FIRST(
		UPSERT { namespace: @namespace, _parent: @typeID , guacKey: @guacNsKey}
		INSERT { namespace: @namespace, _parent: @typeID , guacKey: @guacNsKey}
		UPDATE {}
		IN PkgNamespace OPTIONS { indexHint: "byNamespaceParent" }
		RETURN NEW
	  )
	  
	  LET name = FIRST(
		UPSERT { name: @name, _parent: ns._id, guacKey: @guacNameKey}
		INSERT { name: @name, _parent: ns._id, guacKey: @guacNameKey}
		UPDATE {}
		IN PkgName OPTIONS { indexHint: "byNameParent" }
		RETURN NEW
	  )
	  
	  LET pkgVersionObj = FIRST(
		UPSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier, _parent: name._id, guacKey: @guacVersionKey}
		INSERT { version: @version, subpath: @subpath, qualifier_list: @qualifier, _parent: name._id, guacKey: @guacVersionKey}
		UPDATE {}
		IN PkgVersion OPTIONS { indexHint: "byAllVersionParent" }
		RETURN NEW
	  )
	
	  LET pkgHasNamespaceCollection = (
		INSERT { _key: CONCAT("pkgHasNamespace", @typeKey, ns._key), _from: @typeID, _to: ns._id, label : "PkgHasNamespace"} INTO PkgHasNamespace OPTIONS { overwriteMode: "ignore" }
	  )
	  
	  LET pkgHasNameCollection = (
		INSERT { _key: CONCAT("pkgHasName", ns._key, name._key), _from: ns._id, _to: name._id, label : "PkgHasName"} INTO PkgHasName OPTIONS { overwriteMode: "ignore" }
	  )
	  
	  LET pkgHasVersionCollection = (
		INSERT { _key: CONCAT("pkgHasVersion", name._key, pkgVersionObj._key), _from: name._id, _to: pkgVersionObj._id, label : "PkgHasVersion"} INTO PkgHasVersion OPTIONS { overwriteMode: "ignore" }
	  )
		
	RETURN {
    "type": @typeValue,
    "namespace": ns.namespace,
    "name": name.name,
    "version": pkgVersionObj.version,
    "subpath": pkgVersionObj.subpath,
    "qualifier_list": pkgVersionObj.qualifier_list
  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestPackage")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}

	type collectedData struct {
		PkgType       string      `json:"type"`
		Namespace     string      `json:"namespace"`
		Name          string      `json:"name"`
		Version       string      `json:"version"`
		Subpath       string      `json:"subpath"`
		QualifierList interface{} `json:"qualifier_list"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				cursor.Close()
				break
			} else {
				return nil, fmt.Errorf("failed to ingest package: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}
	if len(createdValues) == 1 {
		return generateModelPackage(createdValues[0].PkgType, createdValues[0].Namespace,
			createdValues[0].Name, createdValues[0].Version, createdValues[0].Subpath, createdValues[0].QualifierList)
	} else {
		return nil, fmt.Errorf("number of hashEqual ingested is greater than one")
	}
}

func (c *arangoClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {

	// fields: [type namespaces namespaces.namespace namespaces.names namespaces.names.name namespaces.names.tag namespaces.names.commit]
	fields := getPreloads(ctx)

	nameRequired := false
	namespaceRequired := false
	for _, f := range fields {
		if f == namespaces {
			namespaceRequired = true
		}
		if f == names {
			nameRequired = true
		}
	}

	if !namespaceRequired && !nameRequired {
		return c.sourcesType(ctx, sourceSpec)
	} else if namespaceRequired && !nameRequired {
		return c.sourcesNamespace(ctx, sourceSpec)
	}

	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	if sourceSpec.Commit != nil && sourceSpec.Tag != nil {
		if *sourceSpec.Commit != "" && *sourceSpec.Tag != "" {
			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
		}
	}

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	sb.WriteString("MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)-[:SrcHasName]->(name:SrcName)")

	setSrcMatchValues(&sb, sourceSpec, false, &firstMatch, queryValues)

	sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			srcTypes := map[string]map[string][]*model.SourceName{}
			for result.Next() {

				commitString := result.Record().Values[4].(string)
				tagString := result.Record().Values[3].(string)
				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				srcName := &model.SourceName{
					Name:   nameString,
					Tag:    &tagString,
					Commit: &commitString,
				}
				if srcNamespaces, ok := srcTypes[typeString]; ok {
					srcNamespaces[namespaceString] = append(srcNamespaces[namespaceString], srcName)
				} else {
					srcNamespaces := map[string][]*model.SourceName{}
					srcNamespaces[namespaceString] = append(srcNamespaces[namespaceString], srcName)
					srcTypes[typeString] = srcNamespaces
				}
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			sources := []*model.Source{}
			for srcType, namespaces := range srcTypes {
				sourceNamespaces := []*model.SourceNamespace{}
				for namespace, sourceNames := range namespaces {
					srcNamespace := &model.SourceNamespace{
						Namespace: namespace,
						Names:     sourceNames,
					}
					sourceNamespaces = append(sourceNamespaces, srcNamespace)
				}

				source := &model.Source{
					Type:       srcType,
					Namespaces: sourceNamespaces,
				}
				sources = append(sources, source)
			}

			return sources, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Source), nil
}

func (c *arangoClient) sourcesType(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}
	sb.WriteString("MATCH (root:Src)-[:SrcHasType]->(type:SrcType)")

	if sourceSpec.Type != nil {

		matchProperties(&sb, firstMatch, "type", "type", "$srcType")
		queryValues["srcType"] = sourceSpec.Type
	}

	sb.WriteString(" RETURN type.type")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			sources := []*model.Source{}
			for result.Next() {

				source := &model.Source{
					Type:       result.Record().Values[0].(string),
					Namespaces: []*model.SourceNamespace{},
				}

				sources = append(sources, source)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return sources, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Source), nil
}

func (c *arangoClient) sourcesNamespace(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}
	sb.WriteString("MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)")

	if sourceSpec.Type != nil {

		matchProperties(&sb, firstMatch, "type", "type", "$srcType")
		firstMatch = false
		queryValues["srcType"] = sourceSpec.Type
	}
	if sourceSpec.Namespace != nil {

		matchProperties(&sb, firstMatch, "namespace", "namespace", "$srcNamespace")
		queryValues["srcNamespace"] = sourceSpec.Namespace
	}
	sb.WriteString(" RETURN type.type, namespace.namespace")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {

			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			srcTypes := map[string][]*model.SourceNamespace{}
			for result.Next() {

				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				srcNamespace := &model.SourceNamespace{
					Namespace: namespaceString,
					Names:     []*model.SourceName{},
				}
				srcTypes[typeString] = append(srcTypes[typeString], srcNamespace)

			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			sources := []*model.Source{}
			for srcType, namespaces := range srcTypes {
				source := &model.Source{
					Type:       srcType,
					Namespaces: namespaces,
				}
				sources = append(sources, source)
			}

			return sources, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.Source), nil
}

func generateModelSource(srcType, namespaceStr, nameStr string, commitValue, tagValue interface{}) *model.Source {
	tag := (*string)(nil)
	if tagValue != nil {
		tagStr := tagValue.(string)
		tag = &tagStr
	}
	commit := (*string)(nil)
	if commitValue != nil {
		commitStr := commitValue.(string)
		commit = &commitStr
	}
	name := &model.SourceName{
		Name:   nameStr,
		Tag:    tag,
		Commit: commit,
	}

	namespace := &model.SourceNamespace{
		Namespace: namespaceStr,
		Names:     []*model.SourceName{name},
	}

	src := model.Source{
		Type:       srcType,
		Namespaces: []*model.SourceNamespace{namespace},
	}
	return &src
}
