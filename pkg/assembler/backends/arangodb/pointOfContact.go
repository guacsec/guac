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
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	emailStr string = "email"
	infoStr  string = "info"
	sinceStr string = "since"
)

func (c *arangoClient) PointOfContact(ctx context.Context, pointOfContactSpec *model.PointOfContactSpec) ([]*model.PointOfContact, error) {

	var arangoQueryBuilder *arangoQueryBuilder
	if pointOfContactSpec.Subject != nil {
		var combinedPointOfContact []*model.PointOfContact
		if pointOfContactSpec.Subject.Package != nil {
			values := map[string]any{}
			// pkgVersion pointOfContact
			arangoQueryBuilder = setPkgVersionMatchValues(pointOfContactSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(pointOfContactPkgVersionEdgesStr, "pointOfContact", "pVersion")
			setPointOfContactMatchValues(arangoQueryBuilder, pointOfContactSpec, values)

			pkgVersionPointOfContact, err := getPkgPointOfContactForQuery(ctx, c, arangoQueryBuilder, values, true)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version pointOfContact with error: %w", err)
			}

			combinedPointOfContact = append(combinedPointOfContact, pkgVersionPointOfContact...)

			if pointOfContactSpec.Subject.Package.ID == nil {
				// pkgName pointOfContact
				values = map[string]any{}
				arangoQueryBuilder = setPkgNameMatchValues(pointOfContactSpec.Subject.Package, values)
				arangoQueryBuilder.forOutBound(pointOfContactPkgNameEdgesStr, "pointOfContact", "pName")
				setPointOfContactMatchValues(arangoQueryBuilder, pointOfContactSpec, values)

				pkgNamePointOfContact, err := getPkgPointOfContactForQuery(ctx, c, arangoQueryBuilder, values, false)
				if err != nil {
					return nil, fmt.Errorf("failed to retrieve package name pointOfContact with error: %w", err)
				}

				combinedPointOfContact = append(combinedPointOfContact, pkgNamePointOfContact...)
			}
		}
		if pointOfContactSpec.Subject.Source != nil {
			values := map[string]any{}
			arangoQueryBuilder = setSrcMatchValues(pointOfContactSpec.Subject.Source, values)
			arangoQueryBuilder.forOutBound(pointOfContactSrcEdgesStr, "pointOfContact", "sName")
			setPointOfContactMatchValues(arangoQueryBuilder, pointOfContactSpec, values)

			srcPointOfContact, err := getSrcPointOfContactForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve source pointOfContact with error: %w", err)
			}

			combinedPointOfContact = append(combinedPointOfContact, srcPointOfContact...)
		}
		if pointOfContactSpec.Subject.Artifact != nil {
			values := map[string]any{}
			arangoQueryBuilder = setArtifactMatchValues(pointOfContactSpec.Subject.Artifact, values)
			arangoQueryBuilder.forOutBound(pointOfContactArtEdgesStr, "pointOfContact", "art")
			setPointOfContactMatchValues(arangoQueryBuilder, pointOfContactSpec, values)

			artPointOfContact, err := getArtPointOfContactForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve artifact pointOfContact with error: %w", err)
			}

			combinedPointOfContact = append(combinedPointOfContact, artPointOfContact...)
		}
		return combinedPointOfContact, nil
	} else {
		values := map[string]any{}
		var combinedPointOfContact []*model.PointOfContact

		// pkgVersion pointOfContact
		arangoQueryBuilder = newForQuery(pointOfContactStr, "pointOfContact")
		setPointOfContactMatchValues(arangoQueryBuilder, pointOfContactSpec, values)
		arangoQueryBuilder.forInBound(pointOfContactPkgVersionEdgesStr, "pVersion", "pointOfContact")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgVersionPointOfContact, err := getPkgPointOfContactForQuery(ctx, c, arangoQueryBuilder, values, true)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package version pointOfContact  with error: %w", err)
		}
		combinedPointOfContact = append(combinedPointOfContact, pkgVersionPointOfContact...)

		// pkgName pointOfContact
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(pointOfContactStr, "pointOfContact")
		setPointOfContactMatchValues(arangoQueryBuilder, pointOfContactSpec, values)
		arangoQueryBuilder.forInBound(pointOfContactPkgNameEdgesStr, "pName", "pointOfContact")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgNamePointOfContact, err := getPkgPointOfContactForQuery(ctx, c, arangoQueryBuilder, values, false)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package name pointOfContact  with error: %w", err)
		}
		combinedPointOfContact = append(combinedPointOfContact, pkgNamePointOfContact...)

		// get sources
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(pointOfContactStr, "pointOfContact")
		setPointOfContactMatchValues(arangoQueryBuilder, pointOfContactSpec, values)
		arangoQueryBuilder.forInBound(pointOfContactSrcEdgesStr, "sName", "pointOfContact")
		arangoQueryBuilder.forInBound(srcHasNameStr, "sNs", "sName")
		arangoQueryBuilder.forInBound(srcHasNamespaceStr, "sType", "sNs")

		srcPointOfContact, err := getSrcPointOfContactForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve source pointOfContact with error: %w", err)
		}
		combinedPointOfContact = append(combinedPointOfContact, srcPointOfContact...)

		// get artifacts
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(pointOfContactStr, "pointOfContact")
		setPointOfContactMatchValues(arangoQueryBuilder, pointOfContactSpec, values)
		arangoQueryBuilder.forInBound(pointOfContactArtEdgesStr, "art", "pointOfContact")

		artPointOfContact, err := getArtPointOfContactForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve artifact pointOfContact with error: %w", err)
		}
		combinedPointOfContact = append(combinedPointOfContact, artPointOfContact...)

		return combinedPointOfContact, nil
	}
}

func getSrcPointOfContactForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.PointOfContact, error) {
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
		'pointOfContact_id': pointOfContact._id,
		'email': pointOfContact.email,
		'info': pointOfContact.info,
		'since': pointOfContact.since,
		'justification': pointOfContact.justification,
		'collector': pointOfContact.collector,
		'origin': pointOfContact.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "PointOfContact")
	if err != nil {
		return nil, fmt.Errorf("failed to query for PointOfContact: %w", err)
	}
	defer cursor.Close()

	return getPointOfContactFromCursor(ctx, cursor)
}

func getArtPointOfContactForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.PointOfContact, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'pointOfContact_id': pointOfContact._id,
		'email': pointOfContact.email,
		'info': pointOfContact.info,
		'since': pointOfContact.since,
		'justification': pointOfContact.justification,
		'collector': pointOfContact.collector,
		'origin': pointOfContact.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "PointOfContact")
	if err != nil {
		return nil, fmt.Errorf("failed to query for PointOfContact: %w", err)
	}
	defer cursor.Close()

	return getPointOfContactFromCursor(ctx, cursor)
}

func getPkgPointOfContactForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, includeDepPkgVersion bool) ([]*model.PointOfContact, error) {
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
			'pointOfContact_id': pointOfContact._id,
			'email': pointOfContact.email,
			'info': pointOfContact.info,
			'since': pointOfContact.since,
			'justification': pointOfContact.justification,
			'collector': pointOfContact.collector,
			'origin': pointOfContact.origin
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
			'pointOfContact_id': pointOfContact._id,
			'email': pointOfContact.email,
			'info': pointOfContact.info,
			'since': pointOfContact.since,
			'justification': pointOfContact.justification,
			'collector': pointOfContact.collector,
			'origin': pointOfContact.origin
		  }`)
	}

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "PointOfContact")
	if err != nil {
		return nil, fmt.Errorf("failed to query for PointOfContact: %w", err)
	}
	defer cursor.Close()

	return getPointOfContactFromCursor(ctx, cursor)
}

func setPointOfContactMatchValues(arangoQueryBuilder *arangoQueryBuilder, PointOfContactSpec *model.PointOfContactSpec, queryValues map[string]any) {
	if PointOfContactSpec.ID != nil {
		arangoQueryBuilder.filter("pointOfContact", "_id", "==", "@id")
		queryValues["id"] = *PointOfContactSpec.ID
	}
	if PointOfContactSpec.Email != nil {
		arangoQueryBuilder.filter("pointOfContact", emailStr, "==", "@"+emailStr)
		queryValues[emailStr] = *PointOfContactSpec.Email
	}
	if PointOfContactSpec.Info != nil {
		arangoQueryBuilder.filter("pointOfContact", infoStr, "==", "@"+infoStr)
		queryValues[infoStr] = *PointOfContactSpec.Info
	}
	if PointOfContactSpec.Since != nil {
		arangoQueryBuilder.filter("pointOfContact", sinceStr, ">=", "@"+sinceStr)
		queryValues[sinceStr] = *PointOfContactSpec.Since
	}
	if PointOfContactSpec.Justification != nil {
		arangoQueryBuilder.filter("pointOfContact", justification, "==", "@"+justification)
		queryValues[justification] = *PointOfContactSpec.Justification
	}
	if PointOfContactSpec.Origin != nil {
		arangoQueryBuilder.filter("pointOfContact", origin, "==", "@"+origin)
		queryValues[origin] = *PointOfContactSpec.Origin
	}
	if PointOfContactSpec.Collector != nil {
		arangoQueryBuilder.filter("pointOfContact", collector, "==", "@"+collector)
		queryValues[collector] = *PointOfContactSpec.Collector
	}
}

func getPointOfContactQueryValues(pkg *model.PkgInputSpec, pkgMatchType *model.MatchFlags, artifact *model.ArtifactInputSpec, source *model.SourceInputSpec, pointOfContact *model.PointOfContactInputSpec) map[string]any {
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

	values[emailStr] = pointOfContact.Email
	values[infoStr] = pointOfContact.Info
	values[sinceStr] = pointOfContact.Since
	values[justification] = pointOfContact.Justification
	values[origin] = pointOfContact.Origin
	values[collector] = pointOfContact.Collector

	return values
}

func (c *arangoClient) IngestPointOfContact(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, pointOfContact model.PointOfContactInputSpec) (*model.PointOfContact, error) {
	if subject.Package != nil {
		if pkgMatchType.Pkg == model.PkgMatchTypeSpecificVersion {
			query := `
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == @pkgVersionGuacKey
			FOR pName in pkgNames
			  FILTER pName._id == pVersion._parent
			FOR pNs in pkgNamespaces
			  FILTER pNs._id == pName._parent
			FOR pType in pkgTypes
			  FILTER pType._id == pNs._parent
	
			RETURN {
			  'typeID': pType._id,
			  'type': pType.type,
			  'namespace_id': pNs._id,
			  'namespace': pNs.namespace,
			  'name_id': pName._id,
			  'name': pName.name,
			  'version_id': pVersion._id,
			  'version': pVersion.version,
			  'subpath': pVersion.subpath,
			  'qualifier_list': pVersion.qualifier_list,
			  'versionDoc': pVersion
			}
		)
		  
		  LET pointOfContact = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, email:@email, info:@info, since:@since, justification:@justification, collector:@collector, origin:@origin } 
				  INSERT {  packageID:firstPkg.version_id, email:@email, info:@info, since:@since, justification:@justification, collector:@collector, origin:@origin } 
				  UPDATE {} IN pointOfContacts
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("pointOfContactPkgVersionEdges", firstPkg.versionDoc._key, pointOfContact._key), _from: firstPkg.version_id, _to: pointOfContact._id } INTO pointOfContactPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
		  RETURN {
			'pkgVersion': {
				'type_id': firstPkg.typeID,
				'type': firstPkg.type,
				'namespace_id': firstPkg.namespace_id,
				'namespace': firstPkg.namespace,
				'name_id': firstPkg.name_id,
				'name': firstPkg.name,
				'version_id': firstPkg.version_id,
				'version': firstPkg.version,
				'subpath': firstPkg.subpath,
				'qualifier_list': firstPkg.qualifier_list
			},
			'pointOfContact_id': pointOfContact._id,
			'email': pointOfContact.email,
			'info': pointOfContact.info,
			'since': pointOfContact.since,
			'justification': pointOfContact.justification,
			'collector': pointOfContact.collector,
			'origin': pointOfContact.origin  
		  }`

			cursor, err := executeQueryWithRetry(ctx, c.db, query, getPointOfContactQueryValues(subject.Package, pkgMatchType, nil, nil, &pointOfContact), "IngestPointOfContact - PkgVersion")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package pointOfContact: %w", err)
			}
			defer cursor.Close()

			pointOfContacts, err := getPointOfContactFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get pointOfContact from arango cursor: %w", err)
			}

			if len(pointOfContacts) == 1 {
				return pointOfContacts[0], nil
			} else {
				return nil, fmt.Errorf("number of pointOfContact ingested is greater than one")
			}
		} else {
			query := `
			LET firstPkg = FIRST(
				FOR pName in pkgNames
				  FILTER pName.guacKey == @pkgNameGuacKey
				FOR pNs in pkgNamespaces
				  FILTER pNs._id == pName._parent
				FOR pType in pkgTypes
				  FILTER pType._id == pNs._parent
		
				RETURN {
				  'typeID': pType._id,
				  'type': pType.type,
				  'namespace_id': pNs._id,
				  'namespace': pNs.namespace,
				  'name_id': pName._id,
				  'name': pName.name,
				  'nameDoc': pName
				}
			)
			  
			  LET pointOfContact = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, email:@email, info:@info, since:@since, justification:@justification, collector:@collector, origin:@origin } 
					  INSERT {  packageID:firstPkg.name_id, email:@email, info:@info, since:@since, justification:@justification, collector:@collector, origin:@origin } 
					  UPDATE {} IN pointOfContacts
					  RETURN NEW
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("pointOfContactPkgNameEdges", firstPkg.nameDoc._key, pointOfContact._key), _from: firstPkg.name_id, _to: pointOfContact._id } INTO pointOfContactPkgNameEdges OPTIONS { overwriteMode: "ignore" }
			  )
			  
			  RETURN {
				'pkgVersion': {
					'type_id': firstPkg.typeID,
					'type': firstPkg.type,
					'namespace_id': firstPkg.namespace_id,
					'namespace': firstPkg.namespace,
					'name_id': firstPkg.name_id,
					'name': firstPkg.name
				},
				'pointOfContact_id': pointOfContact._id,
				'email': pointOfContact.email,
				'info': pointOfContact.info,
				'since': pointOfContact.since,
				'justification': pointOfContact.justification,
				'collector': pointOfContact.collector,
				'origin': pointOfContact.origin    
			  }`

			cursor, err := executeQueryWithRetry(ctx, c.db, query, getPointOfContactQueryValues(subject.Package, pkgMatchType, nil, nil, &pointOfContact), "IngestPointOfContact - PkgName")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package pointOfContact: %w", err)
			}
			defer cursor.Close()

			pointOfContacts, err := getPointOfContactFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get pointOfContact from arango cursor: %w", err)
			}

			if len(pointOfContacts) == 1 {
				return pointOfContacts[0], nil
			} else {
				return nil, fmt.Errorf("number of pointOfContact ingested is greater than one")
			}
		}

	} else if subject.Artifact != nil {
		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
		  
		LET pointOfContact = FIRST(
			UPSERT { artifactID:artifact._id, email:@email, info:@info, since:@since, justification:@justification, collector:@collector, origin:@origin } 
				INSERT { artifactID:artifact._id, email:@email, info:@info, since:@since, justification:@justification, collector:@collector, origin:@origin } 
				UPDATE {} IN pointOfContacts
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("pointOfContactArtEdges", artifact._key, pointOfContact._key), _from: artifact._id, _to: pointOfContact._id } INTO pointOfContactArtEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN {
		  'artifact': {
			  'id': artifact._id,
			  'algorithm': artifact.algorithm,
			  'digest': artifact.digest
		  },
		  'pointOfContact_id': pointOfContact._id,
		  'email': pointOfContact.email,
		  'info': pointOfContact.info,
		  'since': pointOfContact.since,
		  'justification': pointOfContact.justification,
		  'collector': pointOfContact.collector,
		  'origin': pointOfContact.origin    
		}`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getPointOfContactQueryValues(nil, nil, subject.Artifact, nil, &pointOfContact), "IngestPointOfContact - artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact pointOfContact: %w", err)
		}
		defer cursor.Close()
		pointOfContacts, err := getPointOfContactFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get pointOfContact from arango cursor: %w", err)
		}

		if len(pointOfContacts) == 1 {
			return pointOfContacts[0], nil
		} else {
			return nil, fmt.Errorf("number of pointOfContact ingested is greater than one")
		}

	} else if subject.Source != nil {
		query := `
		LET firstSrc = FIRST(
			FOR sName in srcNames
			  FILTER sName.guacKey == @srcNameGuacKey
			FOR sNs in srcNamespaces
			  FILTER sNs._id == sName._parent
			FOR sType in srcTypes
			  FILTER sType._id == sNs._parent
	
			RETURN {
			  'typeID': sType._id,
			  'type': sType.type,
			  'namespace_id': sNs._id,
			  'namespace': sNs.namespace,
			  'name_id': sName._id,
			  'name': sName.name,
			  'commit': sName.commit,
			  'tag': sName.tag,
			  'nameDoc': sName
			}
		)
		  
		LET pointOfContact = FIRST(
			UPSERT { sourceID:firstSrc.name_id, email:@email, info:@info, since:@since, justification:@justification, collector:@collector, origin:@origin } 
				INSERT { sourceID:firstSrc.name_id, email:@email, info:@info, since:@since, justification:@justification, collector:@collector, origin:@origin } 
				UPDATE {} IN pointOfContacts
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("pointOfContactSrcEdges", firstSrc.nameDoc._key, pointOfContact._key), _from: firstSrc.name_id, _to: pointOfContact._id } INTO pointOfContactSrcEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN {
		  'srcName': {
			  'type_id': firstSrc.typeID,
			  'type': firstSrc.type,
			  'namespace_id': firstSrc.namespace_id,
			  'namespace': firstSrc.namespace,
			  'name_id': firstSrc.name_id,
			  'name': firstSrc.name,
			  'commit': firstSrc.commit,
			  'tag': firstSrc.tag
		  },
		  'pointOfContact_id': pointOfContact._id,
		  'email': pointOfContact.email,
		  'info': pointOfContact.info,
		  'since': pointOfContact.since,
		  'justification': pointOfContact.justification,
		  'collector': pointOfContact.collector,
		  'origin': pointOfContact.origin    
		}`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getPointOfContactQueryValues(nil, nil, nil, subject.Source, &pointOfContact), "IngestPointOfContact - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source pointOfContact: %w", err)
		}
		defer cursor.Close()
		pointOfContacts, err := getPointOfContactFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get pointOfContact from arango cursor: %w", err)
		}

		if len(pointOfContacts) == 1 {
			return pointOfContacts[0], nil
		} else {
			return nil, fmt.Errorf("number of pointOfContact ingested is greater than one")
		}

	} else {
		return nil, fmt.Errorf("package, artifact, or source is specified for IngestPointOfContact")
	}
}

func (c *arangoClient) IngestPointOfContacts(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, pointOfContacts []*model.PointOfContactInputSpec) ([]string, error) {
	if len(subjects.Packages) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getPointOfContactQueryValues(subjects.Packages[i], pkgMatchType, nil, nil, pointOfContacts[i]))
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
			query := `LET firstPkg = FIRST(
				FOR pVersion in pkgVersions
				  FILTER pVersion.guacKey == doc.pkgVersionGuacKey
				FOR pName in pkgNames
				  FILTER pName._id == pVersion._parent
				FOR pNs in pkgNamespaces
				  FILTER pNs._id == pName._parent
				FOR pType in pkgTypes
				  FILTER pType._id == pNs._parent
		
				RETURN {
				  'typeID': pType._id,
				  'type': pType.type,
				  'namespace_id': pNs._id,
				  'namespace': pNs.namespace,
				  'name_id': pName._id,
				  'name': pName.name,
				  'version_id': pVersion._id,
				  'version': pVersion.version,
				  'subpath': pVersion.subpath,
				  'qualifier_list': pVersion.qualifier_list,
				  'versionDoc': pVersion
				}
			)
			  
			  LET pointOfContact = FIRST(
				  UPSERT {  packageID:firstPkg.version_id, email:doc.email, info:doc.info, since:doc.since, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
					  INSERT {  packageID:firstPkg.version_id, email:doc.email, info:doc.info, since:doc.since, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
					  UPDATE {} IN pointOfContacts
					  RETURN NEW
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("pointOfContactPkgVersionEdges", firstPkg.versionDoc._key, pointOfContact._key), _from: firstPkg.version_id, _to: pointOfContact._id } INTO pointOfContactPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
			  )
			  
			  RETURN {
				'pkgVersion': {
					'type_id': firstPkg.typeID,
					'type': firstPkg.type,
					'namespace_id': firstPkg.namespace_id,
					'namespace': firstPkg.namespace,
					'name_id': firstPkg.name_id,
					'name': firstPkg.name,
					'version_id': firstPkg.version_id,
					'version': firstPkg.version,
					'subpath': firstPkg.subpath,
					'qualifier_list': firstPkg.qualifier_list
				},
				'pointOfContact_id': pointOfContact._id,
				'email': pointOfContact.email,
				'info': pointOfContact.info,
				'since': pointOfContact.since,
				'justification': pointOfContact.justification,
				'collector': pointOfContact.collector,
				'origin': pointOfContact.origin    
			  }`

			sb.WriteString(query)

			cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestPointOfContacts - PkgVersion")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package pointOfContact: %w", err)
			}
			defer cursor.Close()

			ingestPointOfContactList, err := getPointOfContactFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get pointOfContact from arango cursor: %w", err)
			}

			var pointOfContactIDList []string
			for _, ingestedPointOfContact := range ingestPointOfContactList {
				pointOfContactIDList = append(pointOfContactIDList, ingestedPointOfContact.ID)
			}

			return pointOfContactIDList, nil

		} else {
			query := `
			LET firstPkg = FIRST(
				FOR pName in pkgNames
				  FILTER pName.guacKey == doc.pkgNameGuacKey
				FOR pNs in pkgNamespaces
				  FILTER pNs._id == pName._parent
				FOR pType in pkgTypes
				  FILTER pType._id == pNs._parent
		
				RETURN {
				  'typeID': pType._id,
				  'type': pType.type,
				  'namespace_id': pNs._id,
				  'namespace': pNs.namespace,
				  'name_id': pName._id,
				  'name': pName.name,
				  'nameDoc': pName
				}
			)
			  
			  LET pointOfContact = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, email:doc.email, info:doc.info, since:doc.since, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
					  INSERT {  packageID:firstPkg.name_id, email:doc.email, info:doc.info, since:doc.since, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
					  UPDATE {} IN pointOfContacts
					  RETURN NEW
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("pointOfContactPkgNameEdges", firstPkg.nameDoc._key, pointOfContact._key), _from: firstPkg.name_id, _to: pointOfContact._id } INTO pointOfContactPkgNameEdges OPTIONS { overwriteMode: "ignore" }
			  )
			  
			  RETURN {
				'pkgVersion': {
					'type_id': firstPkg.typeID,
					'type': firstPkg.type,
					'namespace_id': firstPkg.namespace_id,
					'namespace': firstPkg.namespace,
					'name_id': firstPkg.name_id,
					'name': firstPkg.name
				},
				'pointOfContact_id': pointOfContact._id,
				'email': pointOfContact.email,
				'info': pointOfContact.info,
				'since': pointOfContact.since,
				'justification': pointOfContact.justification,
				'collector': pointOfContact.collector,
				'origin': pointOfContact.origin    
			  }`

			sb.WriteString(query)

			cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestPointOfContacts - PkgName")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package pointOfContact: %w", err)
			}
			defer cursor.Close()

			ingestPointOfContactList, err := getPointOfContactFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get pointOfContact from arango cursor: %w", err)
			}

			var pointOfContactIDList []string
			for _, ingestedPointOfContact := range ingestPointOfContactList {
				pointOfContactIDList = append(pointOfContactIDList, ingestedPointOfContact.ID)
			}

			return pointOfContactIDList, nil
		}

	} else if len(subjects.Artifacts) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Artifacts {
			listOfValues = append(listOfValues, getPointOfContactQueryValues(nil, nil, subjects.Artifacts[i], nil, pointOfContacts[i]))
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
		  
		LET pointOfContact = FIRST(
			UPSERT { artifactID:artifact._id, email:doc.email, info:doc.info, since:doc.since, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				INSERT { artifactID:artifact._id, email:doc.email, info:doc.info, since:doc.since, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				UPDATE {} IN pointOfContacts
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("pointOfContactArtEdges", artifact._key, pointOfContact._key), _from: artifact._id, _to: pointOfContact._id } INTO pointOfContactArtEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN {
		  'artifact': {
			  'id': artifact._id,
			  'algorithm': artifact.algorithm,
			  'digest': artifact.digest
		  },
		  'pointOfContact_id': pointOfContact._id,
		  'email': pointOfContact.email,
		  'info': pointOfContact.info,
		  'since': pointOfContact.since,
		  'justification': pointOfContact.justification,
		  'collector': pointOfContact.collector,
		  'origin': pointOfContact.origin    
		}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestPointOfContacts - artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact pointOfContact: %w", err)
		}
		defer cursor.Close()

		ingestPointOfContactList, err := getPointOfContactFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get pointOfContact from arango cursor: %w", err)
		}

		var pointOfContactIDList []string
		for _, ingestedPointOfContact := range ingestPointOfContactList {
			pointOfContactIDList = append(pointOfContactIDList, ingestedPointOfContact.ID)
		}

		return pointOfContactIDList, nil

	} else if len(subjects.Sources) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Sources {
			listOfValues = append(listOfValues, getPointOfContactQueryValues(nil, nil, nil, subjects.Sources[i], pointOfContacts[i]))
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
			FOR sNs in srcNamespaces
			  FILTER sNs._id == sName._parent
			FOR sType in srcTypes
			  FILTER sType._id == sNs._parent
	
			RETURN {
			  'typeID': sType._id,
			  'type': sType.type,
			  'namespace_id': sNs._id,
			  'namespace': sNs.namespace,
			  'name_id': sName._id,
			  'name': sName.name,
			  'commit': sName.commit,
			  'tag': sName.tag,
			  'nameDoc': sName
			}
		)
		  
		LET pointOfContact = FIRST(
			UPSERT { sourceID:firstSrc.name_id, email:doc.email, info:doc.info, since:doc.since, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				INSERT { sourceID:firstSrc.name_id, email:doc.email, info:doc.info, since:doc.since, justification:doc.justification, collector:doc.collector, origin:doc.origin } 
				UPDATE {} IN pointOfContacts
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("pointOfContactSrcEdges", firstSrc.nameDoc._key, pointOfContact._key), _from: firstSrc.name_id, _to: pointOfContact._id } INTO pointOfContactSrcEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN {
		  'srcName': {
			  'type_id': firstSrc.typeID,
			  'type': firstSrc.type,
			  'namespace_id': firstSrc.namespace_id,
			  'namespace': firstSrc.namespace,
			  'name_id': firstSrc.name_id,
			  'name': firstSrc.name,
			  'commit': firstSrc.commit,
			  'tag': firstSrc.tag
		  },
		  'pointOfContact_id': pointOfContact._id,
		  'email': pointOfContact.email,
		  'info': pointOfContact.info,
		  'since': pointOfContact.since,
		  'justification': pointOfContact.justification,
		  'collector': pointOfContact.collector,
		  'origin': pointOfContact.origin    
		}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestPointOfContacts - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source pointOfContact: %w", err)
		}
		defer cursor.Close()

		ingestPointOfContactList, err := getPointOfContactFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get pointOfContact from arango cursor: %w", err)
		}

		var pointOfContactIDList []string
		for _, ingestedPointOfContact := range ingestPointOfContactList {
			pointOfContactIDList = append(pointOfContactIDList, ingestedPointOfContact.ID)
		}

		return pointOfContactIDList, nil

	} else {
		return nil, fmt.Errorf("packages, artifacts, or sources not specified for IngestPointOfContacts")
	}
}

func getPointOfContactFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.PointOfContact, error) {
	type collectedData struct {
		PkgVersion       *dbPkgVersion   `json:"pkgVersion"`
		Artifact         *model.Artifact `json:"artifact"`
		SrcName          *dbSrcName      `json:"srcName"`
		PointOfContactID string          `json:"pointOfContact_id"`
		Email            string          `json:"email"`
		Info             string          `json:"info"`
		Since            time.Time       `json:"since"`
		Justification    string          `json:"justification"`
		Collector        string          `json:"collector"`
		Origin           string          `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to pointOfContact from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var pocList []*model.PointOfContact
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

		poc := &model.PointOfContact{
			ID:            createdValue.PointOfContactID,
			Email:         createdValue.Email,
			Info:          createdValue.Info,
			Since:         createdValue.Since,
			Justification: createdValue.Justification,
			Origin:        createdValue.Collector,
			Collector:     createdValue.Origin,
		}

		if pkg != nil {
			poc.Subject = pkg
		} else if src != nil {
			poc.Subject = src
		} else if createdValue.Artifact != nil {
			poc.Subject = createdValue.Artifact
		} else {
			return nil, fmt.Errorf("failed to get subject from cursor for pointOfContact")
		}
		pocList = append(pocList, poc)
	}
	return pocList, nil
}
