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
	"strings"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
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
		values["typeID"] = c.srcTypeMap[sources[i].Type].Id
		values["typeKey"] = c.srcTypeMap[sources[i].Type].Key
		values["typeValue"] = c.srcTypeMap[sources[i].Type].SrcType

		guacIds := guacSrcId(*sources[i])
		values["guacNsKey"] = guacIds.NamespaceId
		values["guacNameKey"] = guacIds.NameId

		values["name"] = sources[i].Name

		values["namespace"] = sources[i].Namespace

		if sources[i].Tag != nil {
			values["tag"] = *sources[i].Tag
		} else {
			values["tag"] = ""
		}
		if sources[i].Commit != nil {
			values["commit"] = *sources[i].Commit
		} else {
			values["commit"] = ""
		}

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
	  IN SrcNamespaces OPTIONS { indexHint: "byNsGuacKey" }
	  RETURN NEW
	)
	
	LET name = FIRST(
	  UPSERT { name: doc.name, commit: doc.commit, tag: doc.tag, _parent: ns._id, guacKey: doc.guacNameKey}
	  INSERT { name: doc.name, commit: doc.commit, tag: doc.tag, _parent: ns._id, guacKey: doc.guacNameKey}
	  UPDATE {}
	  IN SrcNames OPTIONS { indexHint: "byNameGuacKey" }
	  RETURN NEW
	)
  
	LET pkgHasNamespaceCollection = (
	  INSERT { _key: CONCAT("srcHasNamespace", doc.typeKey, ns._key), _from: doc.typeID, _to: ns._id, label : "SrcHasNamespace"} INTO SrcHasNamespace OPTIONS { overwriteMode: "ignore" }
	)
	
	LET pkgHasNameCollection = (
	  INSERT { _key: CONCAT("srcHasName", ns._key, name._key), _from: ns._id, _to: name._id, label : "SrcHasName"} INTO SrcHasName OPTIONS { overwriteMode: "ignore" }
	)
	  
    RETURN {
  	  "type": doc.typeValue,
  	  "namespace": ns.namespace,
  	  "name": name.name,
  	  "commit": name.commit,
  	  "tag": name.tag,
	}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestSources")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w", err)
	}

	type ingestedSource struct {
		SrcType   string `json:"type"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Commit    string `json:"commit"`
		Tag       string `json:"tag"`
	}

	var ingestedSources []ingestedSource
	for {
		var doc ingestedSource
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				cursor.Close()
				break
			} else {
				return nil, fmt.Errorf("failed to ingest source: %w", err)
			}
		} else {
			ingestedSources = append(ingestedSources, doc)
		}
	}

	var sourceList []*model.Source
	for _, is := range ingestedSources {
		src := generateModelSource(is.SrcType, is.Namespace, is.Name, &is.Commit, &is.Tag)
		sourceList = append(sourceList, src)
	}

	return sourceList, nil
}

func (c *arangoClient) IngestSource(ctx context.Context, source model.SourceInputSpec) (*model.Source, error) {

	values := map[string]any{}
	values["typeID"] = c.srcTypeMap[source.Type].Id
	values["typeKey"] = c.srcTypeMap[source.Type].Key
	values["typeValue"] = c.srcTypeMap[source.Type].SrcType

	guacIds := guacSrcId(source)
	values["guacNsKey"] = guacIds.NamespaceId
	values["guacNameKey"] = guacIds.NameId

	values["name"] = source.Name

	values["namespace"] = source.Namespace

	if source.Tag != nil {
		values["tag"] = *source.Tag
	} else {
		values["tag"] = ""
	}
	if source.Commit != nil {
		values["commit"] = *source.Commit
	} else {
		values["commit"] = ""
	}

	query := `	  
	LET ns = FIRST(
	  UPSERT { namespace: doc.namespace, _parent: doc.typeID , guacKey: doc.guacNsKey}
	  INSERT { namespace: doc.namespace, _parent: doc.typeID , guacKey: doc.guacNsKey}
	  UPDATE {}
	  IN SrcNamespaces OPTIONS { indexHint: "byNsGuacKey" }
	  RETURN NEW
	)
	
	LET name = FIRST(
	  UPSERT { name: doc.name, commit: doc.commit, tag: doc.tag, _parent: ns._id, guacKey: doc.guacNameKey}
	  INSERT { name: doc.name, commit: doc.commit, tag: doc.tag, _parent: ns._id, guacKey: doc.guacNameKey}
	  UPDATE {}
	  IN SrcNames OPTIONS { indexHint: "byNameGuacKey" }
	  RETURN NEW
	)
  
	LET pkgHasNamespaceCollection = (
	  INSERT { _key: CONCAT("srcHasNamespace", doc.typeKey, ns._key), _from: doc.typeID, _to: ns._id, label : "SrcHasNamespace"} INTO SrcHasNamespace OPTIONS { overwriteMode: "ignore" }
	)
	
	LET pkgHasNameCollection = (
	  INSERT { _key: CONCAT("srcHasName", ns._key, name._key), _from: ns._id, _to: name._id, label : "SrcHasName"} INTO SrcHasName OPTIONS { overwriteMode: "ignore" }
	)
	  
    RETURN {
  	  "type": doc.typeValue,
  	  "namespace": ns.namespace,
  	  "name": name.name,
  	  "commit": name.commit,
  	  "tag": name.tag,
	}`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestSource")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}

	type ingestedSource struct {
		SrcType   string `json:"type"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Commit    string `json:"commit"`
		Tag       string `json:"tag"`
	}

	var ingestedSources []ingestedSource
	for {
		var doc ingestedSource
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				cursor.Close()
				break
			} else {
				return nil, fmt.Errorf("failed to ingest source: %w", err)
			}
		} else {
			ingestedSources = append(ingestedSources, doc)
		}
	}
	if len(ingestedSources) == 1 {
		return generateModelSource(ingestedSources[0].SrcType, ingestedSources[0].Namespace, ingestedSources[0].Name, &ingestedSources[0].Commit, &ingestedSources[0].Tag), nil
	} else {
		return nil, fmt.Errorf("number of sources ingested is greater than one")
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
	} else if !nameRequired {
		return c.sourcesNamespace(ctx, sourceSpec)
	}

	values := map[string]any{}

	arangoQueryBuilder := newForQuery("SrcRoots", "sRoot")
	arangoQueryBuilder.filter("sRoot", "root", "==", "@src")
	values["src"] = "src"
	arangoQueryBuilder.ForOutBound("SrcHasType", "sType", "sRoot")
	if sourceSpec.Type != nil {
		arangoQueryBuilder.filter("sType", "type", "==", "@srcType")
		values["srcType"] = *sourceSpec.Type
	}
	arangoQueryBuilder.ForOutBound("SrcHasNamespace", "sNs", "sType")
	if sourceSpec.Namespace != nil {
		arangoQueryBuilder.filter("sNs", "namespace", "==", "@namespace")
		values["namespace"] = *sourceSpec.Namespace
	}
	arangoQueryBuilder.ForOutBound("SrcHasName", "sName", "sNs")
	if sourceSpec.Name != nil {
		arangoQueryBuilder.filter("sName", "name", "==", "@name")
		values["name"] = *sourceSpec.Name
	}
	if sourceSpec.Commit != nil {
		arangoQueryBuilder.filter("sName", "commit", "==", "@commit")
		values["commit"] = *sourceSpec.Commit
	}
	if sourceSpec.Tag != nil {
		arangoQueryBuilder.filter("sName", "tag", "==", "@tag")
		values["tag"] = *sourceSpec.Tag
	}

	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": sType._id,
		"type": sType.type,
		"namespace_id": sNs._id,
		"namespace": sNs.namespace,
		"name_id": sName._id,
		"name": sName.name,
		"commit": sName.commit,
		"tag": sName.tag
	  }`)

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Sources")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type ingestedSource struct {
		TypeID      string `json:"type_id"`
		SrcType     string `json:"type"`
		NamespaceID string `json:"namespace_id"`
		Namespace   string `json:"namespace"`
		NameID      string `json:"name_id"`
		Name        string `json:"name"`
		Commit      string `json:"commit"`
		Tag         string `json:"tag"`
	}

	srcTypes := map[string]map[string][]*model.SourceName{}
	var doc ingestedSource
	for {
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to query source: %w", err)
			}
		} else {
			commitString := doc.Commit
			tagString := doc.Tag
			nameString := doc.Name
			namespaceString := doc.Namespace + "," + doc.NamespaceID
			typeString := doc.SrcType + "," + doc.TypeID

			srcName := &model.SourceName{
				ID:     doc.NameID,
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
	}
	sources := []*model.Source{}
	for srcType, namespaces := range srcTypes {
		sourceNamespaces := []*model.SourceNamespace{}
		for namespace, sourceNames := range namespaces {
			namespaceValues := strings.Split(namespace, ",")
			srcNamespace := &model.SourceNamespace{
				ID:        namespaceValues[1],
				Namespace: namespaceValues[0],
				Names:     sourceNames,
			}
			sourceNamespaces = append(sourceNamespaces, srcNamespace)
		}
		typeValues := strings.Split(srcType, ",")
		source := &model.Source{
			ID:         typeValues[1],
			Type:       typeValues[0],
			Namespaces: sourceNamespaces,
		}
		sources = append(sources, source)
	}
	return sources, nil
}

func (c *arangoClient) sourcesType(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {

	values := map[string]any{}

	arangoQueryBuilder := newForQuery("SrcRoots", "sRoot")
	arangoQueryBuilder.filter("sRoot", "root", "==", "@src")
	values["src"] = "src"
	arangoQueryBuilder.ForOutBound("SrcHasType", "sType", "sRoot")
	if sourceSpec.Type != nil {
		arangoQueryBuilder.filter("sType", "type", "==", "@srcType")
		values["srcType"] = *sourceSpec.Type
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": sType._id,
		"type": sType.type
	}`)

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "sourcesType")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type collectedData struct {
		TypeID  string `json:"type_id"`
		SrcType string `json:"type"`
	}

	var sources []*model.Source
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to query source type: %w", err)
			}
		} else {
			collectedSource := &model.Source{
				ID:         doc.TypeID,
				Type:       doc.SrcType,
				Namespaces: []*model.SourceNamespace{},
			}
			sources = append(sources, collectedSource)
		}
	}

	return sources, nil
}

func (c *arangoClient) sourcesNamespace(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {
	values := map[string]any{}

	arangoQueryBuilder := newForQuery("SrcRoots", "sRoot")
	arangoQueryBuilder.filter("sRoot", "root", "==", "@src")
	values["src"] = "src"
	arangoQueryBuilder.ForOutBound("SrcHasType", "sType", "sRoot")
	if sourceSpec.Type != nil {
		arangoQueryBuilder.filter("sType", "type", "==", "@srcType")
		values["srcType"] = *sourceSpec.Type
	}
	arangoQueryBuilder.ForOutBound("SrcHasNamespace", "sNs", "sType")
	if sourceSpec.Namespace != nil {
		arangoQueryBuilder.filter("sNs", "namespace", "==", "@namespace")
		values["namespace"] = *sourceSpec.Namespace
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": sType._id,
		"type": sType.type,
		"namespace_id": sNs._id,
		"namespace": sNs.namespace
	  }`)

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "sourcesNamespace")
	if err != nil {
		return nil, fmt.Errorf("failed to create vertex documents: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type collectedData struct {
		TypeID      string `json:"type_id"`
		SrcType     string `json:"type"`
		NamespaceID string `json:"namespace_id"`
		Namespace   string `json:"namespace"`
	}

	srcTypes := map[string][]*model.SourceNamespace{}
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to query source namespace: %w", err)
			}
		} else {
			namespaceString := doc.Namespace
			typeString := doc.SrcType + "," + doc.TypeID

			srcNamespace := &model.SourceNamespace{
				ID:        doc.NamespaceID,
				Namespace: namespaceString,
				Names:     []*model.SourceName{},
			}
			srcTypes[typeString] = append(srcTypes[typeString], srcNamespace)
		}
	}
	sources := []*model.Source{}
	for pkgType, namespaces := range srcTypes {
		typeValues := strings.Split(pkgType, ",")
		collectedSource := &model.Source{
			ID:         typeValues[1],
			Type:       typeValues[0],
			Namespaces: namespaces,
		}
		sources = append(sources, collectedSource)
	}

	return sources, nil
}

func generateModelSource(srcType, namespaceStr, nameStr string, commitValue, tagValue *string) *model.Source {
	name := &model.SourceName{
		Name:   nameStr,
		Tag:    tagValue,
		Commit: commitValue,
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
