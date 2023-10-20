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

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) Builders(ctx context.Context, builderSpec *model.BuilderSpec) ([]*model.Builder, error) {
	values := map[string]any{}
	arangoQueryBuilder := setBuilderMatchValues(builderSpec, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		"id": build._id,
		"uri": build.uri,
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Builders")
	if err != nil {
		return nil, fmt.Errorf("failed to query for builder: %w", err)
	}
	defer cursor.Close()

	return getBuilders(ctx, cursor)
}

func setBuilderMatchValues(builderSpec *model.BuilderSpec, queryValues map[string]any) *arangoQueryBuilder {
	arangoQueryBuilder := newForQuery(buildersStr, "build")
	if builderSpec != nil {
		if builderSpec.ID != nil {
			arangoQueryBuilder.filter("build", "_id", "==", "@id")
			queryValues["id"] = *builderSpec.ID
		}
		if builderSpec.URI != nil {
			arangoQueryBuilder.filter("build", "uri", "==", "@uri")
			queryValues["uri"] = *builderSpec.URI
		}
	}
	return arangoQueryBuilder
}

func getBuilderQueryValues(builder *model.BuilderInputSpec) map[string]any {
	values := map[string]any{}
	values["uri"] = builder.URI
	return values
}

func (c *arangoClient) IngestBuilders(ctx context.Context, builders []*model.BuilderInputSpec) ([]*model.Builder, error) {

	var listOfValues []map[string]any

	for i := range builders {
		listOfValues = append(listOfValues, getBuilderQueryValues(builders[i]))
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
UPSERT { uri:doc.uri } 
INSERT { uri:doc.uri } 
UPDATE {} IN builders OPTIONS { indexHint: "byUri" }
RETURN {
	"id": NEW._id,
	"uri": NEW.uri,
  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestBuilders")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest builder: %w", err)
	}
	defer cursor.Close()

	return getBuilders(ctx, cursor)

}

func (c *arangoClient) IngestBuilder(ctx context.Context, builder *model.BuilderInputSpec) (*model.Builder, error) {
	query := `
UPSERT { uri:@uri } 
INSERT { uri:@uri } 
UPDATE {} IN builders OPTIONS { indexHint: "byUri" }
RETURN {
	"id": NEW._id,
	"uri": NEW.uri,
  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getBuilderQueryValues(builder), "IngestBuilder")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest builder: %w", err)
	}
	defer cursor.Close()

	createdBuilders, err := getBuilders(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get builders from arango cursor: %w", err)
	}
	if len(createdBuilders) == 1 {
		return createdBuilders[0], nil
	} else {
		return nil, fmt.Errorf("number of builders ingested is greater than one")
	}
}

func getBuilders(ctx context.Context, cursor driver.Cursor) ([]*model.Builder, error) {
	var createdBuilders []*model.Builder
	for {
		var doc *model.Builder
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get builder from cursor: %w", err)
			}
		} else {
			createdBuilders = append(createdBuilders, doc)
		}
	}
	return createdBuilders, nil
}

func (c *arangoClient) buildBuilderResponseByID(ctx context.Context, id string, filter *model.BuilderSpec) (*model.Builder, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}
	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == buildersStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.BuilderSpec{
				ID: ptrfrom.String(id),
			}
		}
		foundBuilders, err := c.Builders(ctx, filter)
		if err != nil {
			return nil, fmt.Errorf("failed to get builder node by ID with error: %w", err)
		}
		if len(foundBuilders) != 1 {
			return nil, fmt.Errorf("number of builder nodes found for ID: %s is greater than one", id)
		}
		return foundBuilders[0], nil
	} else {
		return nil, fmt.Errorf("id type does not match for builder query: %s", id)
	}
}

func (c *arangoClient) builderNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := []string{}
	if allowedEdges[model.EdgeBuilderHasSlsa] {
		values := map[string]any{}
		arangoQueryBuilder := setBuilderMatchValues(&model.BuilderSpec{ID: &nodeID}, values)
		arangoQueryBuilder.forInBound(hasSLSABuiltByEdgesStr, "hasSLSA", "build")
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor: hasSLSA._id }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "builderNeighbors")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	return out, nil
}
