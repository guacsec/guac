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
	"sort"
	"strings"

	"github.com/99designs/gqlgen/graphql"
	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/guacsec/guac/pkg/assembler/helpers"
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

func getSourceQueryValues(source *model.SourceInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	guacIds := helpers.GetKey[*model.SourceInputSpec, helpers.SrcIds](source, helpers.SrcServerKey)
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

func (c *arangoClient) IngestSources(ctx context.Context, sources []*model.IDorSourceInput) ([]*model.SourceIDs, error) {
	var listOfValues []map[string]any

	for i := range sources {
		listOfValues = append(listOfValues, getSourceQueryValues(sources[i].SourceInput))
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
	  "namespace_id": ns._id,
	  "name_id": name._id
	}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestSources")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest source: %w", err)
	}

	return getSourceIDs(ctx, cursor)
}

func (c *arangoClient) IngestSource(ctx context.Context, source model.IDorSourceInput) (*model.SourceIDs, error) {
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
	  "namespace_id": ns._id,
	  "name_id": name._id
	}`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getSourceQueryValues(source.SourceInput), "IngestSource")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest source: %w", err)
	}

	createdSourceIDs, err := getSourceIDs(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get sources from arango cursor: %w", err)
	}
	if len(createdSourceIDs) == 1 {
		return createdSourceIDs[0], nil
	} else {
		return nil, fmt.Errorf("number of sources ingested is greater than one")
	}
}

func getSourceIDs(ctx context.Context, cursor driver.Cursor) ([]*model.SourceIDs, error) {
	var sourceIDs []*model.SourceIDs
	for {
		var doc dbSrcName
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get packages from cursor: %w", err)
			}
		} else {
			sourceIDs = append(sourceIDs, &model.SourceIDs{
				SourceTypeID:      doc.TypeID,
				SourceNamespaceID: doc.NamespaceID,
				SourceNameID:      doc.NameID})
		}
	}
	return sourceIDs, nil
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
	if sourceSpec != nil && sourceSpec.ID != nil {
		p, err := c.buildSourceResponseFromID(ctx, *sourceSpec.ID, sourceSpec)
		if err != nil {
			return nil, fmt.Errorf("buildSourceResponseFromID failed with an error: %w", err)
		}
		return []*model.Source{p}, nil
	}

	// fields: [type namespaces namespaces.namespace namespaces.names namespaces.names.name namespaces.names.tag namespaces.names.commit]
	if graphql.HasOperationContext(ctx) {
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
				ID:   doc.NameID,
				Name: nameString,
			}
			if tagString != "" {
				srcName.Tag = &tagString
			}
			if commitString != "" {
				srcName.Commit = &commitString
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
		ID:   nameID,
		Name: nameStr,
	}
	if tagValue != "" {
		name.Tag = &tagValue
	}
	if commitValue != "" {
		name.Commit = &commitValue
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

	sn := &model.SourceName{
		ID:   collectedValues[0].NameID,
		Name: collectedValues[0].Name,
	}
	if collectedValues[0].Tag != "" {
		sn.Tag = &collectedValues[0].Tag
	}
	if collectedValues[0].Commit != "" {
		sn.Commit = &collectedValues[0].Commit
	}

	return sn, collectedValues[0].Parent, nil
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

func (c *arangoClient) srcTypeNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := []string{}
	if allowedEdges[model.EdgeSourceTypeSourceNamespace] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcTypesStr, "sType")
		arangoQueryBuilder.filter("sType", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(srcHasNamespaceStr, "sNs", "sType")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: sNs._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcTypeNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	return out, nil
}

func (c *arangoClient) srcNamespaceNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := []string{}
	if allowedEdges[model.EdgeSourceNamespaceSourceName] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamespacesStr, "sNs")
		arangoQueryBuilder.filter("sNs", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(srcHasNameStr, "sName", "sNs")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: sName._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNamespaceNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourceNamespaceSourceType] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamespacesStr, "sNs")
		arangoQueryBuilder.filter("sNs", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.query.WriteString("\nRETURN { parent: sNs._parent }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNamespaceNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	return out, nil
}

func (c *arangoClient) srcNameNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := []string{}
	if allowedEdges[model.EdgeSourceNameSourceNamespace] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.query.WriteString("\nRETURN { parent: sName._parent}")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourceHasSourceAt] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forInBound(hasSourceAtEdgesStr, "hasSourceAt", "sName")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: hasSourceAt._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		sort.Strings(foundIDs)
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourceCertifyScorecard] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(scorecardSrcEdgesStr, "scorecard", "sName")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: scorecard._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourceIsOccurrence] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(isOccurrenceSubjectSrcEdgesStr, "isOccurrence", "sName")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: isOccurrence._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourceCertifyBad] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(certifyBadSrcEdgesStr, "certifyBad", "sName")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: certifyBad._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourceCertifyGood] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(certifyGoodSrcEdgesStr, "certifyGood", "sName")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: certifyGood._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourceHasMetadata] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(hasMetadataSrcEdgesStr, "hasMetadata", "sName")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: hasMetadata._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourcePointOfContact] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(pointOfContactSrcEdgesStr, "pointOfContact", "sName")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: pointOfContact._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeSourceCertifyLegal] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(srcNamesStr, "sName")
		arangoQueryBuilder.filter("sName", "_id", "==", "@id")
		values["id"] = nodeID
		arangoQueryBuilder.forOutBound(certifyLegalSrcEdgesStr, "certifyLegal", "sName")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: certifyLegal._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "srcNameNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}

func matchSources(ctx context.Context, filter []*model.SourceSpec, sources []*model.Source) bool {
	// collect all IDs for sources
	var srcIDs []string
	for _, src := range sources {
		srcIDs = append(srcIDs, src.Namespaces[0].Names[0].ID)
	}
	for _, srSpec := range filter {
		if srSpec != nil {
			if srSpec.ID != nil {
				// Check by ID if present from the list of collected pkg IDs
				if !helper.IsIDPresent(*srSpec.ID, srcIDs) {
					return false
				}
			} else {
				// Otherwise match spec information
				match := false
				for _, src := range sources {
					srcName := src.Namespaces[0].Names[0]
					if noMatch(srSpec.Name, srcName.Name) {
						continue
					}
					if srcName.Tag != nil && noMatch(srSpec.Tag, *srcName.Tag) {
						continue
					}
					if srcName.Tag == nil && srSpec.Tag != nil {
						continue
					}
					if srcName.Commit != nil && noMatch(srSpec.Commit, *srcName.Commit) {
						continue
					}
					if srcName.Commit == nil && srSpec.Commit != nil {
						continue
					}
					srcNamespace := src.Namespaces[0]
					if noMatch(srSpec.Namespace, srcNamespace.Namespace) {
						continue
					}
					srcType := src.Type
					if noMatch(srSpec.Type, srcType) {
						continue
					}
					match = true
					break
				}
				if !match {
					return false
				}
			}
		}
	}
	return true
}
