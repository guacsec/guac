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
	"fmt"
	"strings"

	"github.com/99designs/gqlgen/graphql"
	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

type dbSrcName struct {
	TypeID      string `json:"type_id"`
	SrcType     string `json:"type"`
	NamespaceID string `json:"namespace_id"`
	Namespace   string `json:"namespace"`
	NameID      string `json:"name_id"`
	Name        string `json:"name"`
	Commit      string `json:"commit"`
	Tag         string `json:"tag"`
}

type dbSrcNamespace struct {
	TypeID      string `json:"type_id"`
	SrcType     string `json:"type"`
	NamespaceID string `json:"namespace_id"`
	Namespace   string `json:"namespace"`
}

type dbSrcType struct {
	TypeID  string `json:"type_id"`
	SrcType string `json:"type"`
}

type srcIds struct {
	TypeId      string
	NamespaceId string
	NameId      string
}

func guacSrcId(src model.SourceInputSpec) srcIds {
	ids := srcIds{}

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

func getSourceQueryValues(source *model.SourceInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	guacIds := guacSrcId(*source)
	values["guacNsKey"] = guacIds.NamespaceId
	values["guacNameKey"] = guacIds.NameId

	values["name"] = source.Name

	values["namespace"] = source.Namespace

	values["srcType"] = source.Type

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
	return values
}

func (c *arangoClient) IngestSources(ctx context.Context, sources []*model.SourceInputSpec) ([]*model.Source, error) {
	var listOfValues []map[string]any

	for i := range sources {
		listOfValues = append(listOfValues, getSourceQueryValues(sources[i]))
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
	LET type = FIRST(
		UPSERT { type: doc.srcType }
		INSERT { type: doc.srcType }
		UPDATE {}
		IN srcTypes OPTIONS { indexHint: "bySrcType" }
		RETURN NEW
    )

	LET ns = FIRST(
	  UPSERT { namespace: doc.namespace, _parent: type._id , guacKey: doc.guacNsKey}
	  INSERT { namespace: doc.namespace, _parent: type._id , guacKey: doc.guacNsKey}
	  UPDATE {}
	  IN srcNamespaces OPTIONS { indexHint: "byNsGuacKey" }
	  RETURN NEW
	)
	
	LET name = FIRST(
	  UPSERT { name: doc.name, commit: doc.commit, tag: doc.tag, _parent: ns._id, guacKey: doc.guacNameKey}
	  INSERT { name: doc.name, commit: doc.commit, tag: doc.tag, _parent: ns._id, guacKey: doc.guacNameKey}
	  UPDATE {}
	  IN srcNames OPTIONS { indexHint: "byNameGuacKey" }
	  RETURN NEW
	)

	LET srcHasNamespaceCollection = (
	  INSERT { _key: CONCAT("srcHasNamespace", type._key, ns._key), _from: type._id, _to: ns._id } INTO srcHasNamespace OPTIONS { overwriteMode: "ignore" }
	)
	
	LET srcHasNameCollection = (
	  INSERT { _key: CONCAT("srcHasName", ns._key, name._key), _from: ns._id, _to: name._id } INTO srcHasName OPTIONS { overwriteMode: "ignore" }
	)
	  
    RETURN {
	  "type_id": type._id,
	  "type": type.type,
	  "namespace_id": ns._id,
	  "namespace": ns.namespace,
	  "name_id": name._id,
	  "name": name.name,
	  "commit": name.commit,
	  "tag": name.tag
	}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestSources")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest source: %w", err)
	}

	return getSources(ctx, cursor)
}

func (c *arangoClient) IngestSource(ctx context.Context, source model.SourceInputSpec) (*model.Source, error) {
	query := `
	LET type = FIRST(
		UPSERT { type: @srcType }
		INSERT { type: @srcType }
		UPDATE {}
		IN srcTypes OPTIONS { indexHint: "bySrcType" }
		RETURN NEW
    )

	LET ns = FIRST(
	  UPSERT { namespace: @namespace, _parent: type._id , guacKey: @guacNsKey}
	  INSERT { namespace: @namespace, _parent: type._id , guacKey: @guacNsKey}
	  UPDATE {}
	  IN srcNamespaces OPTIONS { indexHint: "byNsGuacKey" }
	  RETURN NEW
	)
	
	LET name = FIRST(
	  UPSERT { name: @name, commit: @commit, tag: @tag, _parent: ns._id, guacKey: @guacNameKey}
	  INSERT { name: @name, commit: @commit, tag: @tag, _parent: ns._id, guacKey: @guacNameKey}
	  UPDATE {}
	  IN srcNames OPTIONS { indexHint: "byNameGuacKey" }
	  RETURN NEW
	) 
  
	LET srcHasNamespaceCollection = (
	  INSERT { _key: CONCAT("srcHasNamespace", type._key, ns._key), _from: type._id, _to: ns._id } INTO srcHasNamespace OPTIONS { overwriteMode: "ignore" }
	)
	
	LET srcHasNameCollection = (
	  INSERT { _key: CONCAT("srcHasName", ns._key, name._key), _from: ns._id, _to: name._id } INTO srcHasName OPTIONS { overwriteMode: "ignore" }
	)
	  
    RETURN {
	  "type_id": type._id,
	  "type": type.type,
	  "namespace_id": ns._id,
	  "namespace": ns.namespace,
	  "name_id": name._id,
	  "name": name.name,
	  "commit": name.commit,
	  "tag": name.tag
	}`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getSourceQueryValues(&source), "IngestSource")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest source: %w", err)
	}

	createdSources, err := getSources(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get sources from arango cursor: %w", err)
	}
	if len(createdSources) == 1 {
		return createdSources[0], nil
	} else {
		return nil, fmt.Errorf("number of sources ingested is greater than one")
	}
}

func setSrcMatchValues(srcSpec *model.SourceSpec, queryValues map[string]any) *arangoQueryBuilder {
	var arangoQueryBuilder *arangoQueryBuilder
	if srcSpec != nil {
		arangoQueryBuilder = newForQuery(srcTypesStr, "sType")
		if srcSpec.Type != nil {
			arangoQueryBuilder.filter("sType", "type", "==", "@srcType")
			queryValues["srcType"] = *srcSpec.Type
		}
		arangoQueryBuilder.forOutBound(srcHasNamespaceStr, "sNs", "sType")
		if srcSpec.Namespace != nil {
			arangoQueryBuilder.filter("sNs", "namespace", "==", "@namespace")
			queryValues["namespace"] = *srcSpec.Namespace
		}
		arangoQueryBuilder.forOutBound(srcHasNameStr, "sName", "sNs")
		if srcSpec.ID != nil {
			arangoQueryBuilder.filter("sName", "_id", "==", "@id")
			queryValues["id"] = *srcSpec.ID
		}
		if srcSpec.Name != nil {
			arangoQueryBuilder.filter("sName", "name", "==", "@name")
			queryValues["name"] = *srcSpec.Name
		}
		if srcSpec.Commit != nil {
			arangoQueryBuilder.filter("sName", "commit", "==", "@commit")
			queryValues["commit"] = *srcSpec.Commit
		}
		if srcSpec.Tag != nil {
			arangoQueryBuilder.filter("sName", "tag", "==", "@tag")
			queryValues["tag"] = *srcSpec.Tag
		}
	} else {
		arangoQueryBuilder = newForQuery(srcTypesStr, "sType")
		arangoQueryBuilder.forOutBound(srcHasNamespaceStr, "sNs", "sType")
		arangoQueryBuilder.forOutBound(srcHasNameStr, "sName", "sNs")
	}
	return arangoQueryBuilder
}

func (c *arangoClient) Sources(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {

	// fields: [type namespaces namespaces.namespace namespaces.names namespaces.names.name namespaces.names.tag namespaces.names.commit]
	if _, ok := ctx.Value("graphql").(graphql.OperationContext); ok {
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
	}

	values := map[string]any{}

	arangoQueryBuilder := setSrcMatchValues(sourceSpec, values)

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

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Sources")
	if err != nil {
		return nil, fmt.Errorf("failed to query for sources: %w", err)
	}
	defer cursor.Close()

	return getSources(ctx, cursor)
}

func (c *arangoClient) sourcesType(ctx context.Context, sourceSpec *model.SourceSpec) ([]*model.Source, error) {

	values := map[string]any{}

	arangoQueryBuilder := newForQuery(srcTypesStr, "sType")
	if sourceSpec.Type != nil {
		arangoQueryBuilder.filter("sType", "type", "==", "@srcType")
		values["srcType"] = *sourceSpec.Type
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": sType._id,
		"type": sType.type
	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "sourcesType")
	if err != nil {
		return nil, fmt.Errorf("failed to query for source type: %w", err)
	}
	defer cursor.Close()

	var sources []*model.Source
	for {
		var doc dbSrcType
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

	arangoQueryBuilder := newForQuery(srcTypesStr, "sType")
	if sourceSpec.Type != nil {
		arangoQueryBuilder.filter("sType", "type", "==", "@srcType")
		values["srcType"] = *sourceSpec.Type
	}
	arangoQueryBuilder.forOutBound(srcHasNamespaceStr, "sNs", "sType")
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

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "sourcesNamespace")
	if err != nil {
		return nil, fmt.Errorf("failed to query for source namespace: %w", err)
	}
	defer cursor.Close()

	srcTypes := map[string][]*model.SourceNamespace{}
	for {
		var doc dbSrcNamespace
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
	var sources []*model.Source
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

func getSources(ctx context.Context, cursor driver.Cursor) ([]*model.Source, error) {
	srcTypes := map[string]map[string][]*model.SourceName{}
	var doc dbSrcName
	for {
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get sources from cursor: %w", err)
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
	var sources []*model.Source
	for srcType, namespaces := range srcTypes {
		var sourceNamespaces []*model.SourceNamespace
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

func generateModelSource(srcTypeID, srcType, namespaceID, namespaceStr, nameID, nameStr string, commitValue, tagValue string) *model.Source {
	name := &model.SourceName{
		ID:     nameID,
		Name:   nameStr,
		Tag:    &tagValue,
		Commit: &commitValue,
	}

	namespace := &model.SourceNamespace{
		ID:        namespaceID,
		Namespace: namespaceStr,
		Names:     []*model.SourceName{name},
	}

	src := model.Source{
		ID:         srcTypeID,
		Type:       srcType,
		Namespaces: []*model.SourceNamespace{namespace},
	}
	return &src
}

// Builds a model.Source to send as GraphQL response, starting from id.
// The optional filter allows restricting output (on selection operations).
func (c *arangoClient) buildSourceResponseFromID(ctx context.Context, id string, filter *model.SourceSpec) (*model.Source, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	snl := []*model.SourceName{}
	if idSplit[0] == srcNamesStr {
		var foundSrcName *model.SourceName
		var err error

		foundSrcName, id, err = c.querySrcNameNodeByID(ctx, id, filter)
		if err != nil {
			return nil, fmt.Errorf("failed to get src name node by ID with error: %w", err)
		}
		snl = append(snl, foundSrcName)
	}

	idSplit = strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	snsl := []*model.SourceNamespace{}
	if idSplit[0] == srcNamespacesStr {
		var foundSrcNamespace *model.SourceNamespace
		var err error

		foundSrcNamespace, id, err = c.querySrcNamespaceNodeByID(ctx, id, filter, snl)
		if err != nil {
			return nil, fmt.Errorf("failed to get src namespace node by ID with error: %w", err)
		}
		snsl = append(snsl, foundSrcNamespace)
	}

	idSplit = strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	var s *model.Source
	if idSplit[0] == srcTypesStr {
		var err error
		s, err = c.querySrcTypeNodeByID(ctx, id, filter, snsl)
		if err != nil {
			return nil, fmt.Errorf("failed to get src type node by ID with error: %w", err)
		}
	}
	return s, nil
}

func (c *arangoClient) querySrcNameNodeByID(ctx context.Context, id string, filter *model.SourceSpec) (*model.SourceName, string, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
	arangoQueryBuilder.filter("sName", "_id", "==", "@id")
	values["id"] = id
	if filter != nil {
		if filter.Name != nil {
			arangoQueryBuilder.filter("sName", "name", "==", "@name")
			values["name"] = *filter.Name
		}
		if filter.Commit != nil {
			arangoQueryBuilder.filter("sName", "commit", "==", "@commit")
			values["commit"] = *filter.Commit
		}
		if filter.Tag != nil {
			arangoQueryBuilder.filter("sName", "tag", "==", "@tag")
			values["tag"] = *filter.Tag
		}
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"name_id": sName._id,
		"name": sName.name,
		"commit": sName.commit,
		"tag": sName.tag,
		'parent': sName._parent
  	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "querySrcNameNodeByID")
	if err != nil {
		return nil, "", fmt.Errorf("failed to query for source name: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type parsedSrcName struct {
		NameID string `json:"name_id"`
		Name   string `json:"name"`
		Commit string `json:"commit"`
		Tag    string `json:"tag"`
		Parent string `json:"parent"`
	}

	var collectedValues []parsedSrcName
	for {
		var doc parsedSrcName
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, "", fmt.Errorf("failed to source name from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, "", fmt.Errorf("number of source name nodes found for ID: %s is greater than one", id)
	}

	return &model.SourceName{
		ID:     collectedValues[0].NameID,
		Name:   collectedValues[0].Name,
		Tag:    &collectedValues[0].Tag,
		Commit: &collectedValues[0].Commit,
	}, collectedValues[0].Parent, nil
}

func (c *arangoClient) querySrcNamespaceNodeByID(ctx context.Context, id string, filter *model.SourceSpec, snl []*model.SourceName) (*model.SourceNamespace, string, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(srcNamespacesStr, "sNs")
	arangoQueryBuilder.filter("sNs", "_id", "==", "@id")
	values["id"] = id

	if filter != nil && filter.Namespace != nil {
		arangoQueryBuilder.filter("sNs", "namespace", "==", "@namespace")
		values["namespace"] = *filter.Namespace
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"namespace_id": sNs._id,
		"namespace": sNs.namespace,
		'parent': sNs._parent
  	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "querySrcNamespaceNodeByID")
	if err != nil {
		return nil, "", fmt.Errorf("failed to query for source namespace: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type parsedSrcNamespace struct {
		NamespaceID string `json:"namespace_id"`
		Namespace   string `json:"namespace"`
		Parent      string `json:"parent"`
	}

	var collectedValues []parsedSrcNamespace
	for {
		var doc parsedSrcNamespace
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, "", fmt.Errorf("failed to source namespace from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, "", fmt.Errorf("number of source namespace nodes found for ID: %s is greater than one", id)
	}

	return &model.SourceNamespace{
		ID:        collectedValues[0].NamespaceID,
		Namespace: collectedValues[0].Namespace,
		Names:     snl,
	}, collectedValues[0].Parent, nil
}

func (c *arangoClient) querySrcTypeNodeByID(ctx context.Context, id string, filter *model.SourceSpec, snsl []*model.SourceNamespace) (*model.Source, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(srcTypesStr, "sType")
	arangoQueryBuilder.filter("sType", "_id", "==", "@id")
	values["id"] = id

	if filter != nil && filter.Type != nil {
		arangoQueryBuilder.filter("sType", "type", "==", "@srcType")
		values["srcType"] = *filter.Type
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"type_id": sType._id,
		"type":sType.type,
  	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "querySrcTypeNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for source type: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type parsedSrcType struct {
		TypeID  string `json:"type_id"`
		SrcType string `json:"type"`
	}

	var collectedValues []parsedSrcType
	for {
		var doc parsedSrcType
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to source type from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of source type nodes found for ID: %s is greater than one", id)
	}

	return &model.Source{
		ID:         collectedValues[0].TypeID,
		Type:       collectedValues[0].SrcType,
		Namespaces: snsl,
	}, nil
}
