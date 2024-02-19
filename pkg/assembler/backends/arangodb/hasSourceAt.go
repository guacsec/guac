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
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) HasSourceAt(ctx context.Context, hasSourceAtSpec *model.HasSourceAtSpec) ([]*model.HasSourceAt, error) {

	if hasSourceAtSpec != nil && hasSourceAtSpec.ID != nil {
		hs, err := c.buildHasSourceAtByID(ctx, *hasSourceAtSpec.ID, hasSourceAtSpec)
		if err != nil {
			return nil, fmt.Errorf("buildHasSourceAtByID failed with an error: %w", err)
		}
		return []*model.HasSourceAt{hs}, nil
	}

	var arangoQueryBuilder *arangoQueryBuilder
	if hasSourceAtSpec.Package != nil {
		var combinedHasSourceAt []*model.HasSourceAt

		values := map[string]any{}
		// pkgVersion hasSourceAt
		arangoQueryBuilder = setPkgVersionMatchValues(hasSourceAtSpec.Package, values)
		arangoQueryBuilder.forOutBound(hasSourceAtPkgVersionEdgesStr, "hasSourceAt", "pVersion")
		setHasSourceAtMatchValues(arangoQueryBuilder, hasSourceAtSpec, values)

		pkgVersionHasSourceAt, err := getPkgHasSourceAtForQuery(ctx, c, arangoQueryBuilder, values, true)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package version hasSourceAt with error: %w", err)
		}

		combinedHasSourceAt = append(combinedHasSourceAt, pkgVersionHasSourceAt...)

		if hasSourceAtSpec.Package.ID == nil {
			// pkgName hasSourceAt
			values = map[string]any{}
			arangoQueryBuilder = setPkgNameMatchValues(hasSourceAtSpec.Package, values)
			arangoQueryBuilder.forOutBound(hasSourceAtPkgNameEdgesStr, "hasSourceAt", "pName")
			setHasSourceAtMatchValues(arangoQueryBuilder, hasSourceAtSpec, values)

			pkgNameHasSourceAt, err := getPkgHasSourceAtForQuery(ctx, c, arangoQueryBuilder, values, false)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package name hasSourceAt with error: %w", err)
			}

			combinedHasSourceAt = append(combinedHasSourceAt, pkgNameHasSourceAt...)
		}

		return combinedHasSourceAt, nil
	} else {
		values := map[string]any{}
		var combinedHasSourceAt []*model.HasSourceAt

		// pkgVersion hasSourceAt
		arangoQueryBuilder = newForQuery(hasSourceAtsStr, "hasSourceAt")
		setHasSourceAtMatchValues(arangoQueryBuilder, hasSourceAtSpec, values)
		arangoQueryBuilder.forInBound(hasSourceAtPkgVersionEdgesStr, "pVersion", "hasSourceAt")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgVersionHasSourceAt, err := getPkgHasSourceAtForQuery(ctx, c, arangoQueryBuilder, values, true)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package version hasSourceAt  with error: %w", err)
		}
		combinedHasSourceAt = append(combinedHasSourceAt, pkgVersionHasSourceAt...)

		// pkgName hasSourceAt
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(hasSourceAtsStr, "hasSourceAt")
		setHasSourceAtMatchValues(arangoQueryBuilder, hasSourceAtSpec, values)
		arangoQueryBuilder.forInBound(hasSourceAtPkgNameEdgesStr, "pName", "hasSourceAt")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgNameHasSourceAt, err := getPkgHasSourceAtForQuery(ctx, c, arangoQueryBuilder, values, false)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package name hasSourceAt  with error: %w", err)
		}
		combinedHasSourceAt = append(combinedHasSourceAt, pkgNameHasSourceAt...)

		return combinedHasSourceAt, nil
	}
}

func getPkgHasSourceAtForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, includeDepPkgVersion bool) ([]*model.HasSourceAt, error) {
	if includeDepPkgVersion {
		arangoQueryBuilder.query.WriteString("\n")
		arangoQueryBuilder.query.WriteString(`RETURN {
			'pkgVersion': {
				'type_id': pType._id,
				'type': pType.type,
				'namespace_id': pNs._id,
				'namespace': pNs.namespace,
				'name_id': pName._id,
				'name': pName.name,
				'version_id': pVersion._id,
				'version': pVersion.version,
				'subpath': pVersion.subpath,
				'qualifier_list': pVersion.qualifier_list
			},
			'srcName': {
				'type_id': sType._id,
				'type': sType.type,
				'namespace_id': sNs._id,
				'namespace': sNs.namespace,
				'name_id': sName._id,
				'name': sName.name,
				'commit': sName.commit,
				'tag': sName.tag
			},
			'hasSourceAt_id': hasSourceAt._id,
			'knownSince': hasSourceAt.knownSince,
			'justification': hasSourceAt.justification,
			'collector': hasSourceAt.collector,
			'origin': hasSourceAt.origin
		  }`)
	} else {
		arangoQueryBuilder.query.WriteString("\n")
		arangoQueryBuilder.query.WriteString(`RETURN {
			'pkgVersion': {
				'type_id': pType._id,
				'type': pType.type,
				'namespace_id': pNs._id,
				'namespace': pNs.namespace,
				'name_id': pName._id,
				'name': pName.name
			},
			'srcName': {
				'type_id': sType._id,
				'type': sType.type,
				'namespace_id': sNs._id,
				'namespace': sNs.namespace,
				'name_id': sName._id,
				'name': sName.name,
				'commit': sName.commit,
				'tag': sName.tag
			},
			'hasSourceAt_id': hasSourceAt._id,
			'knownSince': hasSourceAt.knownSince,
			'justification': hasSourceAt.justification,
			'collector': hasSourceAt.collector,
			'origin': hasSourceAt.origin
		  }`)
	}

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasSourceAt")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasSourceAt: %w", err)
	}
	defer cursor.Close()

	return getHasSourceAtFromCursor(ctx, cursor, false)
}

func queryHasSourceAtBasedOnFilter(arangoQueryBuilder *arangoQueryBuilder, hasSourceAtSpec *model.HasSourceAtSpec, queryValues map[string]any) {
	if hasSourceAtSpec.ID != nil {
		arangoQueryBuilder.filter("hasSourceAt", "_id", "==", "@hasSourceAtId")
		queryValues["hasSourceAtId"] = *hasSourceAtSpec.ID
	}
	if hasSourceAtSpec.KnownSince != nil {
		arangoQueryBuilder.filter("hasSourceAt", knownSinceStr, ">=", "@"+knownSinceStr)
		queryValues[knownSinceStr] = hasSourceAtSpec.KnownSince.UTC()
	}
	if hasSourceAtSpec.Justification != nil {
		arangoQueryBuilder.filter("hasSourceAt", justification, "==", "@"+justification)
		queryValues[justification] = *hasSourceAtSpec.Justification
	}
	if hasSourceAtSpec.Origin != nil {
		arangoQueryBuilder.filter("hasSourceAt", origin, "==", "@"+origin)
		queryValues[origin] = *hasSourceAtSpec.Origin
	}
	if hasSourceAtSpec.Collector != nil {
		arangoQueryBuilder.filter("hasSourceAt", collector, "==", "@"+collector)
		queryValues[collector] = *hasSourceAtSpec.Collector
	}
}

func setHasSourceAtMatchValues(arangoQueryBuilder *arangoQueryBuilder, hasSourceAtSpec *model.HasSourceAtSpec, queryValues map[string]any) {
	queryHasSourceAtBasedOnFilter(arangoQueryBuilder, hasSourceAtSpec, queryValues)
	if hasSourceAtSpec.Source != nil {
		arangoQueryBuilder.forOutBound(hasSourceAtEdgesStr, "sName", "hasSourceAt")
		if hasSourceAtSpec.Source.ID != nil {
			arangoQueryBuilder.filter("sName", "_id", "==", "@srcId")
			queryValues["srcId"] = *hasSourceAtSpec.Source.ID
		}
		if hasSourceAtSpec.Source.Name != nil {
			arangoQueryBuilder.filter("sName", "name", "==", "@srcName")
			queryValues["srcName"] = *hasSourceAtSpec.Source.Name
		}
		if hasSourceAtSpec.Source.Commit != nil {
			arangoQueryBuilder.filter("sName", "commit", "==", "@srcCommit")
			queryValues["srcCommit"] = *hasSourceAtSpec.Source.Commit
		}
		if hasSourceAtSpec.Source.Tag != nil {
			arangoQueryBuilder.filter("sName", "tag", "==", "@srcTag")
			queryValues["srcTag"] = *hasSourceAtSpec.Source.Tag
		}
		arangoQueryBuilder.forInBound(srcHasNameStr, "sNs", "sName")
		if hasSourceAtSpec.Source.Namespace != nil {
			arangoQueryBuilder.filter("sNs", "namespace", "==", "@srcNamespace")
			queryValues["srcNamespace"] = *hasSourceAtSpec.Source.Namespace
		}
		arangoQueryBuilder.forInBound(srcHasNamespaceStr, "sType", "sNs")
		if hasSourceAtSpec.Source.Type != nil {
			arangoQueryBuilder.filter("sType", "type", "==", "@srcType")
			queryValues["srcType"] = *hasSourceAtSpec.Source.Type
		}
	} else {
		arangoQueryBuilder.forOutBound(hasSourceAtEdgesStr, "sName", "hasSourceAt")
		arangoQueryBuilder.forInBound(srcHasNameStr, "sNs", "sName")
		arangoQueryBuilder.forInBound(srcHasNamespaceStr, "sType", "sNs")
	}
}

func getHasSourceAtQueryValues(pkg *model.PkgInputSpec, pkgMatchType *model.MatchFlags, source *model.SourceInputSpec, hasSourceAt *model.HasSourceAtInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	pkgId := helper.GuacPkgId(*pkg)
	if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
		values["pkgNameGuacKey"] = pkgId.NameId
	} else {
		values["pkgVersionGuacKey"] = pkgId.VersionId
	}

	src := helper.GuacSrcId(*source)
	values["srcNameGuacKey"] = src.NameId

	values[knownSinceStr] = hasSourceAt.KnownSince.UTC()
	values[justification] = hasSourceAt.Justification
	values[origin] = hasSourceAt.Origin
	values[collector] = hasSourceAt.Collector

	return values
}

func (c *arangoClient) IngestHasSourceAt(ctx context.Context, pkg model.IDorPkgInput, pkgMatchType model.MatchFlags, source model.IDorSourceInput, hasSourceAt model.HasSourceAtInputSpec) (string, error) {
	var cursor driver.Cursor
	var err error
	if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
		query := `
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == @pkgVersionGuacKey
			  RETURN {
				'version_id': pVersion._id,
				'version_key': pVersion._key
			  }
		)

		LET firstSrc = FIRST(
			FOR sName in srcNames
			  FILTER sName.guacKey == @srcNameGuacKey
			  RETURN {
				'name_id': sName._id,
				'name_key': sName._key,
			  }
		)
		  
		  LET hasSourceAt = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, sourceID:firstSrc.name_id, knownSince:@knownSince, justification:@justification, collector:@collector, origin:@origin } 
				  INSERT {  packageID:firstPkg.version_id, sourceID:firstSrc.name_id, knownSince:@knownSince, justification:@justification, collector:@collector, origin:@origin } 
				  UPDATE {} IN hasSourceAts
				  RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		  )
	
		  INSERT { _key: CONCAT("hasSourceAtPkgVersionEdges", firstPkg.version_key, hasSourceAt._key), _from: firstPkg.version_id, _to: hasSourceAt._id } INTO hasSourceAtPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("hasSourceAtEdges", hasSourceAt._key, firstSrc.name_key), _from: hasSourceAt._id, _to: firstSrc.name_id } INTO hasSourceAtEdges OPTIONS { overwriteMode: "ignore" }
		  
		  RETURN { 'hasSourceAt_id': hasSourceAt._id }`

		cursor, err = executeQueryWithRetry(ctx, c.db, query, getHasSourceAtQueryValues(pkg.PackageInput, &pkgMatchType, source.SourceInput, &hasSourceAt), "IngestHasSourceAt - PkgVersion")
		if err != nil {
			return "", fmt.Errorf("failed to ingest package hasSourceAt: %w", err)
		}
		defer cursor.Close()
	} else {
		query := `
			LET firstPkg = FIRST(
				FOR pName in pkgNames
				  FILTER pName.guacKey == @pkgNameGuacKey		
				  RETURN {
					'name_id': pName._id,
					'name_key': pName._key,
				  }
			)

			LET firstSrc = FIRST(
				FOR sName in srcNames
				  FILTER sName.guacKey == @srcNameGuacKey
				  RETURN {
					'name_id': sName._id,
					'name_key': sName._key,
				  }
			)
			  
			  LET hasSourceAt = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, sourceID:firstSrc.name_id, knownSince:@knownSince, justification:@justification, collector:@collector, origin:@origin } 
					  INSERT {  packageID:firstPkg.name_id, sourceID:firstSrc.name_id, knownSince:@knownSince, justification:@justification, collector:@collector, origin:@origin } 
					  UPDATE {} IN hasSourceAts
					  RETURN {
						'_id': NEW._id,
						'_key': NEW._key
					}
			  )
			  
			  INSERT { _key: CONCAT("hasSourceAtPkgNameEdges", firstPkg.name_key, hasSourceAt._key), _from: firstPkg.name_id, _to: hasSourceAt._id } INTO hasSourceAtPkgNameEdges OPTIONS { overwriteMode: "ignore" }
		  	  INSERT { _key: CONCAT("hasSourceAtEdges", hasSourceAt._key, firstSrc.name_key), _from: hasSourceAt._id, _to:firstSrc.name_id } INTO hasSourceAtEdges OPTIONS { overwriteMode: "ignore" }
			  
			  RETURN { 'hasSourceAt_id': hasSourceAt._id }`

		cursor, err = executeQueryWithRetry(ctx, c.db, query, getHasSourceAtQueryValues(pkg.PackageInput, &pkgMatchType, source.SourceInput, &hasSourceAt), "IngestHasSourceAt - PkgName")
		if err != nil {
			return "", fmt.Errorf("failed to ingest package hasSourceAt: %w", err)
		}
		defer cursor.Close()
	}
	hasSourceAtList, err := getHasSourceAtFromCursor(ctx, cursor, true)
	if err != nil {
		return "", fmt.Errorf("failed to get hasSourceAt from arango cursor: %w", err)
	}

	if len(hasSourceAtList) == 1 {
		return hasSourceAtList[0].ID, nil
	} else {
		return "", fmt.Errorf("number of hasSourceAt ingested is greater than one")
	}
}

func (c *arangoClient) IngestHasSourceAts(ctx context.Context, pkgs []*model.IDorPkgInput, pkgMatchType *model.MatchFlags, sources []*model.IDorSourceInput, hasSourceAts []*model.HasSourceAtInputSpec) ([]string, error) {
	var cursor driver.Cursor
	var err error
	var listOfValues []map[string]any

	for i := range pkgs {
		listOfValues = append(listOfValues, getHasSourceAtQueryValues(pkgs[i].PackageInput, pkgMatchType, sources[i].SourceInput, hasSourceAts[i]))
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

	if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
		query := `
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == doc.pkgVersionGuacKey
			RETURN {
			  'version_id': pVersion._id,
			  'version_key': pVersion._key
			}
		)

		LET firstSrc = FIRST(
			FOR sName in srcNames
			  FILTER sName.guacKey == doc.srcNameGuacKey
			RETURN {
			  'name_id': sName._id,
			  'name_key': sName._key
			}
		)
		  
		  LET hasSourceAt = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, sourceID:firstSrc.name_id, knownSince:doc.knownSince, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				  INSERT {  packageID:firstPkg.version_id, sourceID:firstSrc.name_id, knownSince:doc.knownSince, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				  UPDATE {} IN hasSourceAts
				  RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		  )

		   			
		  INSERT { _key: CONCAT("hasSourceAtPkgVersionEdges", firstPkg.version_key, hasSourceAt._key), _from: firstPkg.version_id, _to: hasSourceAt._id } INTO hasSourceAtPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("hasSourceAtEdges", hasSourceAt._key, firstSrc.name_key), _from: hasSourceAt._id, _to: firstSrc.name_id } INTO hasSourceAtEdges OPTIONS { overwriteMode: "ignore" }
		  
		  RETURN { 'hasSourceAt_id': hasSourceAt._id }`

		sb.WriteString(query)

		cursor, err = executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestHasSourceAts - PkgVersion")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package hasSourceAt: %w", err)
		}
		defer cursor.Close()
	} else {
		query := `
		LET firstPkg = FIRST(
			FOR pName in pkgNames
			  FILTER pName.guacKey == doc.pkgNameGuacKey
			RETURN {
			  'name_id': pName._id,
			  'name_key': pName._key
			}
		)

		LET firstSrc = FIRST(
			FOR sName in srcNames
			  FILTER sName.guacKey == doc.srcNameGuacKey
			RETURN {
			  'name_id': sName._id,
			  'name_key': sName._key
			}
		)
		  
		  LET hasSourceAt = FIRST(
			  UPSERT {  packageID:firstPkg.name_id, sourceID:firstSrc.name_id, knownSince:doc.knownSince, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				  INSERT {  packageID:firstPkg.name_id, sourceID:firstSrc.name_id, knownSince:doc.knownSince, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				  UPDATE {} IN hasSourceAts
				  RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				  }
		  )
		  
		  INSERT { _key: CONCAT("hasSourceAtPkgNameEdges", firstPkg.name_key, hasSourceAt._key), _from: firstPkg.name_id, _to: hasSourceAt._id } INTO hasSourceAtPkgNameEdges OPTIONS { overwriteMode: "ignore" }
		  INSERT { _key: CONCAT("hasSourceAtEdges", hasSourceAt._key, firstSrc.name_key), _from: hasSourceAt._id, _to:firstSrc.name_id } INTO hasSourceAtEdges OPTIONS { overwriteMode: "ignore" }
		  
 		  RETURN { 'hasSourceAt_id': hasSourceAt._id }`

		sb.WriteString(query)

		cursor, err = executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestHasSourceAts - PkgName")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package hasSourceAt: %w", err)
		}
		defer cursor.Close()
	}
	ingestHasSourceAtList, err := getHasSourceAtFromCursor(ctx, cursor, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get hasSourceAt from arango cursor: %w", err)
	}

	var hasSourceAtIDList []string
	for _, ingestedHasSourceAt := range ingestHasSourceAtList {
		hasSourceAtIDList = append(hasSourceAtIDList, ingestedHasSourceAt.ID)
	}

	return hasSourceAtIDList, nil
}

func getHasSourceAtFromCursor(ctx context.Context, cursor driver.Cursor, ingestion bool) ([]*model.HasSourceAt, error) {
	type collectedData struct {
		PkgVersion    *dbPkgVersion `json:"pkgVersion"`
		SrcName       *dbSrcName    `json:"srcName"`
		HasSourceAtID string        `json:"hasSourceAt_id"`
		KnownSince    time.Time     `json:"knownSince"`
		Justification string        `json:"justification"`
		Collector     string        `json:"collector"`
		Origin        string        `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to hasSourceAt from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var hasSourceAtList []*model.HasSourceAt
	for _, createdValue := range createdValues {
		var hasSourceAt *model.HasSourceAt
		if !ingestion {
			pkg := generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)
			src := generateModelSource(createdValue.SrcName.TypeID, createdValue.SrcName.SrcType, createdValue.SrcName.NamespaceID, createdValue.SrcName.Namespace,
				createdValue.SrcName.NameID, createdValue.SrcName.Name, createdValue.SrcName.Commit, createdValue.SrcName.Tag)

			hasSourceAt = &model.HasSourceAt{
				ID:            createdValue.HasSourceAtID,
				Package:       pkg,
				Source:        src,
				KnownSince:    createdValue.KnownSince,
				Justification: createdValue.Justification,
				Origin:        createdValue.Origin,
				Collector:     createdValue.Collector,
			}
		} else {
			hasSourceAt = &model.HasSourceAt{ID: createdValue.HasSourceAtID}
		}
		hasSourceAtList = append(hasSourceAtList, hasSourceAt)
	}
	return hasSourceAtList, nil
}

func (c *arangoClient) buildHasSourceAtByID(ctx context.Context, id string, filter *model.HasSourceAtSpec) (*model.HasSourceAt, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == hasSourceAtsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.HasSourceAtSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryHasSourceAtNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for hasSourceAt query: %s", id)
	}
}

func (c *arangoClient) queryHasSourceAtNodeByID(ctx context.Context, filter *model.HasSourceAtSpec) (*model.HasSourceAt, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(hasSourceAtsStr, "hasSourceAt")
	queryHasSourceAtBasedOnFilter(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN hasSourceAt`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryHasSourceAtNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for hasSourceAt: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbHasSourceAt struct {
		HasSourceAtID string    `json:"_id"`
		PackageID     string    `json:"packageID"`
		SourceID      string    `json:"sourceID"`
		KnownSince    time.Time `json:"knownSince"`
		Justification string    `json:"justification"`
		Collector     string    `json:"collector"`
		Origin        string    `json:"origin"`
	}

	var collectedValues []dbHasSourceAt
	for {
		var doc dbHasSourceAt
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to hasSourceAt from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of hasSourceAt nodes found for ID: %s is greater than one", *filter.ID)
	}

	builtPackage, err := c.buildPackageResponseFromID(ctx, collectedValues[0].PackageID, filter.Package)
	if err != nil {
		return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", collectedValues[0].PackageID, err)
	}

	builtSource, err := c.buildSourceResponseFromID(ctx, collectedValues[0].SourceID, filter.Source)
	if err != nil {
		return nil, fmt.Errorf("failed to get source from ID: %s, with error: %w", collectedValues[0].SourceID, err)
	}

	return &model.HasSourceAt{
		ID:            collectedValues[0].HasSourceAtID,
		Package:       builtPackage,
		Source:        builtSource,
		KnownSince:    collectedValues[0].KnownSince,
		Justification: collectedValues[0].Justification,
		Origin:        collectedValues[0].Origin,
	}, nil
}

func (c *arangoClient) hasSourceAtNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 2)
	if allowedEdges[model.EdgeHasSourceAtPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSourceAtsStr, "hasSourceAt")
		queryHasSourceAtBasedOnFilter(arangoQueryBuilder, &model.HasSourceAtSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSourceAt.packageID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasSourceAtNeighbors - package")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeHasSourceAtSource] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSourceAtsStr, "hasSourceAt")
		queryHasSourceAtBasedOnFilter(arangoQueryBuilder, &model.HasSourceAtSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSourceAt.sourceID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasSourceAtNeighbors - source")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}
