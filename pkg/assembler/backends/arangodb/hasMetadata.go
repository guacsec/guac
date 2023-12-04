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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	keyStr   string = "key"
	valueStr string = "value"
)

func (c *arangoClient) HasMetadata(ctx context.Context, hasMetadataSpec *model.HasMetadataSpec) ([]*model.HasMetadata, error) {

	if hasMetadataSpec != nil && hasMetadataSpec.ID != nil {
		hm, err := c.buildHasMetadataByID(ctx, *hasMetadataSpec.ID, hasMetadataSpec)
		if err != nil {
			return nil, fmt.Errorf("buildHasMetadataByID failed with an error: %w", err)
		}
		return []*model.HasMetadata{hm}, nil
	}

	var arangoQueryBuilder *arangoQueryBuilder
	if hasMetadataSpec.Subject != nil {
		var combinedHasMetadata []*model.HasMetadata
		if hasMetadataSpec.Subject.Package != nil {
			values := map[string]any{}
			// pkgVersion hasMetadata
			arangoQueryBuilder = setPkgVersionMatchValues(hasMetadataSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(hasMetadataPkgVersionEdgesStr, "hasMetadata", "pVersion")
			setHasMetadataMatchValues(arangoQueryBuilder, hasMetadataSpec, values)

			pkgVersionHasMetadata, err := getPkgHasMetadataForQuery(ctx, c, arangoQueryBuilder, values, true)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version hasMetadata with error: %w", err)
			}

			combinedHasMetadata = append(combinedHasMetadata, pkgVersionHasMetadata...)

			if hasMetadataSpec.Subject.Package.ID == nil {
				// pkgName hasMetadata
				values = map[string]any{}
				arangoQueryBuilder = setPkgNameMatchValues(hasMetadataSpec.Subject.Package, values)
				arangoQueryBuilder.forOutBound(hasMetadataPkgNameEdgesStr, "hasMetadata", "pName")
				setHasMetadataMatchValues(arangoQueryBuilder, hasMetadataSpec, values)

				pkgNameHasMetadata, err := getPkgHasMetadataForQuery(ctx, c, arangoQueryBuilder, values, false)
				if err != nil {
					return nil, fmt.Errorf("failed to retrieve package name hasMetadata with error: %w", err)
				}

				combinedHasMetadata = append(combinedHasMetadata, pkgNameHasMetadata...)
			}
		}
		if hasMetadataSpec.Subject.Source != nil {
			values := map[string]any{}
			arangoQueryBuilder = setSrcMatchValues(hasMetadataSpec.Subject.Source, values)
			arangoQueryBuilder.forOutBound(hasMetadataSrcEdgesStr, "hasMetadata", "sName")
			setHasMetadataMatchValues(arangoQueryBuilder, hasMetadataSpec, values)

			srcHasMetadata, err := getSrcHasMetadataForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve source hasMetadata with error: %w", err)
			}

			combinedHasMetadata = append(combinedHasMetadata, srcHasMetadata...)
		}
		if hasMetadataSpec.Subject.Artifact != nil {
			values := map[string]any{}
			arangoQueryBuilder = setArtifactMatchValues(hasMetadataSpec.Subject.Artifact, values)
			arangoQueryBuilder.forOutBound(hasMetadataArtEdgesStr, "hasMetadata", "art")
			setHasMetadataMatchValues(arangoQueryBuilder, hasMetadataSpec, values)

			artHasMetadata, err := getArtHasMetadataForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve artifact hasMetadata with error: %w", err)
			}

			combinedHasMetadata = append(combinedHasMetadata, artHasMetadata...)
		}
		return combinedHasMetadata, nil
	} else {
		values := map[string]any{}
		var combinedHasMetadata []*model.HasMetadata

		// pkgVersion hasMetadata
		arangoQueryBuilder = newForQuery(hasMetadataStr, "hasMetadata")
		setHasMetadataMatchValues(arangoQueryBuilder, hasMetadataSpec, values)
		arangoQueryBuilder.forInBound(hasMetadataPkgVersionEdgesStr, "pVersion", "hasMetadata")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgVersionHasMetadata, err := getPkgHasMetadataForQuery(ctx, c, arangoQueryBuilder, values, true)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package version hasMetadata  with error: %w", err)
		}
		combinedHasMetadata = append(combinedHasMetadata, pkgVersionHasMetadata...)

		// pkgName hasMetadata
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(hasMetadataStr, "hasMetadata")
		setHasMetadataMatchValues(arangoQueryBuilder, hasMetadataSpec, values)
		arangoQueryBuilder.forInBound(hasMetadataPkgNameEdgesStr, "pName", "hasMetadata")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgNameHasMetadata, err := getPkgHasMetadataForQuery(ctx, c, arangoQueryBuilder, values, false)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package name hasMetadata  with error: %w", err)
		}
		combinedHasMetadata = append(combinedHasMetadata, pkgNameHasMetadata...)

		// get sources
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(hasMetadataStr, "hasMetadata")
		setHasMetadataMatchValues(arangoQueryBuilder, hasMetadataSpec, values)
		arangoQueryBuilder.forInBound(hasMetadataSrcEdgesStr, "sName", "hasMetadata")
		arangoQueryBuilder.forInBound(srcHasNameStr, "sNs", "sName")
		arangoQueryBuilder.forInBound(srcHasNamespaceStr, "sType", "sNs")

		srcHasMetadata, err := getSrcHasMetadataForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve source hasMetadata with error: %w", err)
		}
		combinedHasMetadata = append(combinedHasMetadata, srcHasMetadata...)

		// get artifacts
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(hasMetadataStr, "hasMetadata")
		setHasMetadataMatchValues(arangoQueryBuilder, hasMetadataSpec, values)
		arangoQueryBuilder.forInBound(hasMetadataArtEdgesStr, "art", "hasMetadata")

		artHasMetadata, err := getArtHasMetadataForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve artifact hasMetadata with error: %w", err)
		}
		combinedHasMetadata = append(combinedHasMetadata, artHasMetadata...)

		return combinedHasMetadata, nil
	}
}

func getSrcHasMetadataForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.HasMetadata, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
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
		'hasMetadata_id': hasMetadata._id,
		'key': hasMetadata.key,
		'value': hasMetadata.value,
		'timestamp': hasMetadata.timestamp,
		'justification': hasMetadata.justification,
		'collector': hasMetadata.collector,
		'origin': hasMetadata.origin  
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasMetadata")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasMetadata: %w", err)
	}
	defer cursor.Close()

	return getHasMetadataFromCursor(ctx, cursor, false)
}

func getArtHasMetadataForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.HasMetadata, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'hasMetadata_id': hasMetadata._id,
		'key': hasMetadata.key,
		'value': hasMetadata.value,
		'timestamp': hasMetadata.timestamp,
		'justification': hasMetadata.justification,
		'collector': hasMetadata.collector,
		'origin': hasMetadata.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasMetadata")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasMetadata: %w", err)
	}
	defer cursor.Close()

	return getHasMetadataFromCursor(ctx, cursor, false)
}

func getPkgHasMetadataForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, includeDepPkgVersion bool) ([]*model.HasMetadata, error) {
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
			'hasMetadata_id': hasMetadata._id,
			'key': hasMetadata.key,
			'value': hasMetadata.value,
			'timestamp': hasMetadata.timestamp,
			'justification': hasMetadata.justification,
			'collector': hasMetadata.collector,
			'origin': hasMetadata.origin
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
			'hasMetadata_id': hasMetadata._id,
			'key': hasMetadata.key,
			'value': hasMetadata.value,
			'timestamp': hasMetadata.timestamp,
			'justification': hasMetadata.justification,
			'collector': hasMetadata.collector,
			'origin': hasMetadata.origin
		  }`)
	}

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasMetadata")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasMetadata: %w", err)
	}
	defer cursor.Close()

	return getHasMetadataFromCursor(ctx, cursor, false)
}

func setHasMetadataMatchValues(arangoQueryBuilder *arangoQueryBuilder, hasMetadataSpec *model.HasMetadataSpec, queryValues map[string]any) {
	if hasMetadataSpec.ID != nil {
		arangoQueryBuilder.filter("hasMetadata", "_id", "==", "@id")
		queryValues["id"] = *hasMetadataSpec.ID
	}
	if hasMetadataSpec.Key != nil {
		arangoQueryBuilder.filter("hasMetadata", keyStr, "==", "@"+keyStr)
		queryValues[keyStr] = *hasMetadataSpec.Key
	}
	if hasMetadataSpec.Value != nil {
		arangoQueryBuilder.filter("hasMetadata", valueStr, "==", "@"+valueStr)
		queryValues[valueStr] = *hasMetadataSpec.Value
	}
	if hasMetadataSpec.Since != nil {
		arangoQueryBuilder.filter("hasMetadata", timeStampStr, ">=", "@"+timeStampStr)
		queryValues[timeStampStr] = hasMetadataSpec.Since.UTC()
	}
	if hasMetadataSpec.Justification != nil {
		arangoQueryBuilder.filter("hasMetadata", justification, "==", "@"+justification)
		queryValues[justification] = *hasMetadataSpec.Justification
	}
	if hasMetadataSpec.Origin != nil {
		arangoQueryBuilder.filter("hasMetadata", origin, "==", "@"+origin)
		queryValues[origin] = *hasMetadataSpec.Origin
	}
	if hasMetadataSpec.Collector != nil {
		arangoQueryBuilder.filter("hasMetadata", collector, "==", "@"+collector)
		queryValues[collector] = *hasMetadataSpec.Collector
	}
}

func getHasMetadataQueryValues(pkg *model.PkgInputSpec, pkgMatchType *model.MatchFlags, artifact *model.ArtifactInputSpec, source *model.SourceInputSpec, hasMetadata *model.HasMetadataInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := guacPkgId(*pkg)
		if pkgMatchType.Pkg == model.PkgMatchTypeAllVersions {
			values["pkgNameGuacKey"] = pkgId.NameId
		} else {
			values["pkgVersionGuacKey"] = pkgId.VersionId
		}
	} else if artifact != nil {
		values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
		values["art_digest"] = strings.ToLower(artifact.Digest)
	} else {
		source := guacSrcId(*source)
		values["srcNameGuacKey"] = source.NameId
	}

	values[keyStr] = hasMetadata.Key
	values[valueStr] = hasMetadata.Value
	values[timeStampStr] = hasMetadata.Timestamp.UTC()
	values[justification] = hasMetadata.Justification
	values[origin] = hasMetadata.Origin
	values[collector] = hasMetadata.Collector

	return values
}

func (c *arangoClient) IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (string, error) {
	var cursor driver.Cursor
	var err error
	if subject.Package != nil {
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
		  
		  LET hasMetadata = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				  INSERT {  packageID:firstPkg.version_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				  UPDATE {} IN hasMetadataCollection
				  RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				  }
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasMetadataPkgVersionEdges", firstPkg.version_key, hasMetadata._key), _from: firstPkg.version_id, _to: hasMetadata._id } INTO hasMetadataPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
		  RETURN { 'hasMetadata_id': hasMetadata._id }`

			cursor, err = executeQueryWithRetry(ctx, c.db, query, getHasMetadataQueryValues(subject.Package, pkgMatchType, nil, nil, &hasMetadata), "IngestHasMetadata - PkgVersion")
			if err != nil {
				return "", fmt.Errorf("failed to ingest package hasMetadata: %w", err)
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
			  
			  LET hasMetadata = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
					  INSERT {  packageID:firstPkg.name_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
					  UPDATE {} IN hasMetadataCollection
					  RETURN {
						'_id': NEW._id,
						'_key': NEW._key
					  }
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("hasMetadataPkgNameEdges", firstPkg.name_key, hasMetadata._key), _from: firstPkg.name_id, _to: hasMetadata._id } INTO hasMetadataPkgNameEdges OPTIONS { overwriteMode: "ignore" }
			  )
			  
			  RETURN { 'hasMetadata_id': hasMetadata._id }`

			cursor, err = executeQueryWithRetry(ctx, c.db, query, getHasMetadataQueryValues(subject.Package, pkgMatchType, nil, nil, &hasMetadata), "IngestHasMetadata - PkgName")
			if err != nil {
				return "", fmt.Errorf("failed to ingest package hasMetadata: %w", err)
			}
			defer cursor.Close()
		}
	} else if subject.Artifact != nil {
		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
		  
		LET hasMetadata = FIRST(
			UPSERT { artifactID:artifact._id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				INSERT { artifactID:artifact._id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				UPDATE {} IN hasMetadataCollection
				RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("hasMetadataArtEdges", artifact._key, hasMetadata._key), _from: artifact._id, _to: hasMetadata._id } INTO hasMetadataArtEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN { 'hasMetadata_id': hasMetadata._id }`

		cursor, err = executeQueryWithRetry(ctx, c.db, query, getHasMetadataQueryValues(nil, nil, subject.Artifact, nil, &hasMetadata), "IngestHasMetadata - artifact")
		if err != nil {
			return "", fmt.Errorf("failed to ingest artifact hasMetadata: %w", err)
		}
		defer cursor.Close()
	} else if subject.Source != nil {
		query := `
		LET firstSrc = FIRST(
			FOR sName in srcNames
			  FILTER sName.guacKey == @srcNameGuacKey
			  RETURN {
				'name_id': sName._id,
				'name_key': sName._key,
			  }
		)
		  
		LET hasMetadata = FIRST(
			UPSERT { sourceID:firstSrc.name_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				INSERT { sourceID:firstSrc.name_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				UPDATE {} IN hasMetadataCollection
				RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("hasMetadataSrcEdges", firstSrc.name_key, hasMetadata._key), _from: firstSrc.name_id, _to: hasMetadata._id } INTO hasMetadataSrcEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN { 'hasMetadata_id': hasMetadata._id }`

		cursor, err = executeQueryWithRetry(ctx, c.db, query, getHasMetadataQueryValues(nil, nil, nil, subject.Source, &hasMetadata), "IngestHasMetadata - source")
		if err != nil {
			return "", fmt.Errorf("failed to ingest source hasMetadata: %w", err)
		}
		defer cursor.Close()
	} else {
		return "", fmt.Errorf("package, artifact, or source is specified for IngestHasMetadata")
	}

	hasMetadataList, err := getHasMetadataFromCursor(ctx, cursor, true)
	if err != nil {
		return "", fmt.Errorf("failed to get hasMetadata from arango cursor: %w", err)
	}

	if len(hasMetadataList) == 1 {
		return hasMetadataList[0].ID, nil
	} else {
		return "", fmt.Errorf("number of hasMetadata ingested is greater than one")
	}
}

func (c *arangoClient) IngestBulkHasMetadata(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) ([]string, error) {
	var cursor driver.Cursor
	var err error
	if len(subjects.Packages) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getHasMetadataQueryValues(subjects.Packages[i], pkgMatchType, nil, nil, hasMetadataList[i]))
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
			  
			  LET hasMetadata = FIRST(
				  UPSERT {  packageID:firstPkg.version_id, key:doc.key, value:doc.value, timestamp:doc.timestamp, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
					  INSERT {  packageID:firstPkg.version_id, key:doc.key, value:doc.value, timestamp:doc.timestamp, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
					  UPDATE {} IN hasMetadataCollection
					  RETURN {
						'_id': NEW._id,
						'_key': NEW._key
					  }
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("hasMetadataPkgVersionEdges", firstPkg.version_key, hasMetadata._key), _from: firstPkg.version_id, _to: hasMetadata._id } INTO hasMetadataPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
			  )
			  
			  RETURN { 'hasMetadata_id': hasMetadata._id }`

			sb.WriteString(query)

			cursor, err = executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestBulkHasMetadata - PkgVersion")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package hasMetadata: %w", err)
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
			  
			  LET hasMetadata = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, key:doc.key, value:doc.value, timestamp:doc.timestamp, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
					  INSERT {  packageID:firstPkg.name_id, key:doc.key, value:doc.value, timestamp:doc.timestamp, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
					  UPDATE {} IN hasMetadataCollection
					  RETURN {
						'_id': NEW._id,
						'_key': NEW._key
					}
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("hasMetadataPkgNameEdges", firstPkg.name_key, hasMetadata._key), _from: firstPkg.name_id, _to: hasMetadata._id } INTO hasMetadataPkgNameEdges OPTIONS { overwriteMode: "ignore" }
			  )
			  
			  RETURN { 'hasMetadata_id': hasMetadata._id }`

			sb.WriteString(query)

			cursor, err = executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestBulkHasMetadata - PkgName")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package hasMetadata: %w", err)
			}
			defer cursor.Close()
		}
	} else if len(subjects.Artifacts) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Artifacts {
			listOfValues = append(listOfValues, getHasMetadataQueryValues(nil, nil, subjects.Artifacts[i], nil, hasMetadataList[i]))
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

		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == doc.art_algorithm FILTER art.digest == doc.art_digest RETURN art)
		  
		LET hasMetadata = FIRST(
			UPSERT { artifactID:artifact._id, key:doc.key, value:doc.value, timestamp:doc.timestamp, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				INSERT { artifactID:artifact._id, key:doc.key, value:doc.value, timestamp:doc.timestamp, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				UPDATE {} IN hasMetadataCollection
				RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("hasMetadataArtEdges", artifact._key, hasMetadata._key), _from: artifact._id, _to: hasMetadata._id } INTO hasMetadataArtEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN { 'hasMetadata_id': hasMetadata._id }`

		sb.WriteString(query)

		cursor, err = executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestBulkHasMetadata - artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact hasMetadata: %w", err)
		}
		defer cursor.Close()
	} else if len(subjects.Sources) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Sources {
			listOfValues = append(listOfValues, getHasMetadataQueryValues(nil, nil, nil, subjects.Sources[i], hasMetadataList[i]))
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
		LET firstSrc = FIRST(
			FOR sName in srcNames
			  FILTER sName.guacKey == doc.srcNameGuacKey
			RETURN {
			  'name_id': sName._id,
			  'name_key': sName._key
			}
		)
		  
		LET hasMetadata = FIRST(
			UPSERT { sourceID:firstSrc.name_id, key:doc.key, value:doc.value, timestamp:doc.timestamp, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				INSERT { sourceID:firstSrc.name_id, key:doc.key, value:doc.value, timestamp:doc.timestamp, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				UPDATE {} IN hasMetadataCollection
				RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("hasMetadataSrcEdges", firstSrc.name_key, hasMetadata._key), _from: firstSrc.name_id, _to: hasMetadata._id } INTO hasMetadataSrcEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN { 'hasMetadata_id': hasMetadata._id }`

		sb.WriteString(query)

		cursor, err = executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestBulkHasMetadata - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source hasMetadata: %w", err)
		}
		defer cursor.Close()
	} else {
		return nil, fmt.Errorf("packages, artifacts, or sources not specified for IngestBulkHasMetadata")
	}

	ingestHasMetadataList, err := getHasMetadataFromCursor(ctx, cursor, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get hasMetadata from arango cursor: %w", err)
	}

	var hasMetadataIDList []string
	for _, ingestedHasMetadata := range ingestHasMetadataList {
		hasMetadataIDList = append(hasMetadataIDList, ingestedHasMetadata.ID)
	}

	return hasMetadataIDList, nil
}

func getHasMetadataFromCursor(ctx context.Context, cursor driver.Cursor, ingestion bool) ([]*model.HasMetadata, error) {
	type collectedData struct {
		PkgVersion    *dbPkgVersion   `json:"pkgVersion"`
		Artifact      *model.Artifact `json:"artifact"`
		SrcName       *dbSrcName      `json:"srcName"`
		HasMetadataID string          `json:"hasMetadata_id"`
		Key           string          `json:"key"`
		Value         string          `json:"value"`
		Timestamp     time.Time       `json:"timestamp"`
		Justification string          `json:"justification"`
		Collector     string          `json:"collector"`
		Origin        string          `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to hasMetadata from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var hasMetadataList []*model.HasMetadata
	for _, createdValue := range createdValues {
		var pkg *model.Package = nil
		var src *model.Source = nil
		if createdValue.PkgVersion != nil {
			pkg = generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
				createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)
		} else if createdValue.SrcName != nil {
			src = generateModelSource(createdValue.SrcName.TypeID, createdValue.SrcName.SrcType, createdValue.SrcName.NamespaceID, createdValue.SrcName.Namespace,
				createdValue.SrcName.NameID, createdValue.SrcName.Name, createdValue.SrcName.Commit, createdValue.SrcName.Tag)
		}

		hasMetadata := &model.HasMetadata{
			ID:            createdValue.HasMetadataID,
			Key:           createdValue.Key,
			Value:         createdValue.Value,
			Timestamp:     createdValue.Timestamp,
			Justification: createdValue.Justification,
			Origin:        createdValue.Origin,
			Collector:     createdValue.Collector,
		}

		if pkg != nil {
			hasMetadata.Subject = pkg
		} else if src != nil {
			hasMetadata.Subject = src
		} else if createdValue.Artifact != nil {
			hasMetadata.Subject = createdValue.Artifact
		} else {
			if !ingestion {
				return nil, fmt.Errorf("failed to get subject from cursor for hasMetadata")
			}
		}
		hasMetadataList = append(hasMetadataList, hasMetadata)
	}
	return hasMetadataList, nil
}

func (c *arangoClient) buildHasMetadataByID(ctx context.Context, id string, filter *model.HasMetadataSpec) (*model.HasMetadata, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == hasMetadataStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.HasMetadataSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryHasMetadataNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for hasMetadata query: %s", id)
	}
}

func (c *arangoClient) queryHasMetadataNodeByID(ctx context.Context, filter *model.HasMetadataSpec) (*model.HasMetadata, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(hasMetadataStr, "hasMetadata")
	setHasMetadataMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN hasMetadata`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryHasMetadataNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for hasMetadata: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbHasMetadata struct {
		HasMetadataID string    `json:"_id"`
		PackageID     *string   `json:"packageID"`
		SourceID      *string   `json:"sourceID"`
		ArtifactID    *string   `json:"artifactID"`
		Key           string    `json:"key"`
		Value         string    `json:"value"`
		Timestamp     time.Time `json:"timestamp"`
		Justification string    `json:"justification"`
		Collector     string    `json:"collector"`
		Origin        string    `json:"origin"`
	}

	var collectedValues []dbHasMetadata
	for {
		var doc dbHasMetadata
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to hasMetadata from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of hasMetadata nodes found for ID: %s is greater than one", *filter.ID)
	}

	hasMetadata := &model.HasMetadata{
		ID:            collectedValues[0].HasMetadataID,
		Key:           collectedValues[0].Key,
		Value:         collectedValues[0].Value,
		Timestamp:     collectedValues[0].Timestamp,
		Justification: collectedValues[0].Justification,
		Origin:        collectedValues[0].Origin,
		Collector:     collectedValues[0].Collector,
	}

	if collectedValues[0].PackageID != nil {
		var builtPackage *model.Package
		if filter.Subject != nil && filter.Subject.Package != nil {
			builtPackage, err = c.buildPackageResponseFromID(ctx, *collectedValues[0].PackageID, filter.Subject.Package)
			if err != nil {
				return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", *collectedValues[0].PackageID, err)
			}
		} else {
			builtPackage, err = c.buildPackageResponseFromID(ctx, *collectedValues[0].PackageID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get package from ID: %s, with error: %w", *collectedValues[0].PackageID, err)
			}
		}
		hasMetadata.Subject = builtPackage
	} else if collectedValues[0].SourceID != nil {
		var builtSource *model.Source
		if filter.Subject != nil && filter.Subject.Source != nil {
			builtSource, err = c.buildSourceResponseFromID(ctx, *collectedValues[0].SourceID, filter.Subject.Source)
			if err != nil {
				return nil, fmt.Errorf("failed to get source from ID: %s, with error: %w", *collectedValues[0].SourceID, err)
			}
		} else {
			builtSource, err = c.buildSourceResponseFromID(ctx, *collectedValues[0].SourceID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get source from ID: %s, with error: %w", *collectedValues[0].SourceID, err)
			}
		}
		hasMetadata.Subject = builtSource
	} else if collectedValues[0].ArtifactID != nil {
		var builtArtifact *model.Artifact
		if filter.Subject != nil && filter.Subject.Artifact != nil {
			builtArtifact, err = c.buildArtifactResponseByID(ctx, *collectedValues[0].ArtifactID, filter.Subject.Artifact)
			if err != nil {
				return nil, fmt.Errorf("failed to get artifact from ID: %s, with error: %w", *collectedValues[0].ArtifactID, err)
			}
		} else {
			builtArtifact, err = c.buildArtifactResponseByID(ctx, *collectedValues[0].ArtifactID, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to get artifact from ID: %s, with error: %w", *collectedValues[0].ArtifactID, err)
			}
		}
		hasMetadata.Subject = builtArtifact
	} else {
		return nil, fmt.Errorf("failed to get subject from hasMetadata")
	}
	return hasMetadata, nil
}

func (c *arangoClient) hasMetadataNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 1)
	if allowedEdges[model.EdgeHasMetadataPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasMetadataStr, "hasMetadata")
		setHasMetadataMatchValues(arangoQueryBuilder, &model.HasMetadataSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasMetadata.packageID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasMetadataNeighbors - package")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeHasMetadataArtifact] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasMetadataStr, "hasMetadata")
		setHasMetadataMatchValues(arangoQueryBuilder, &model.HasMetadataSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasMetadata.artifactID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasMetadataNeighbors - artifact")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeHasMetadataSource] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasMetadataStr, "hasMetadata")
		setHasMetadataMatchValues(arangoQueryBuilder, &model.HasMetadataSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasMetadata.sourceID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasMetadataNeighbors - source")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	return out, nil
}
