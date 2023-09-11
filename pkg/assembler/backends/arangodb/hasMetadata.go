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
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) HasMetadata(ctx context.Context, hasMetadataSpec *model.HasMetadataSpec) ([]*model.HasMetadata, error) {
	return nil, fmt.Errorf("not implemented: HasMetadata")
}

func setHasMetadataMatchValues(arangoQueryBuilder *arangoQueryBuilder, certifyBadSpec *model.CertifyBadSpec, queryValues map[string]any) {
	if certifyBadSpec.ID != nil {
		arangoQueryBuilder.filter("certifyBad", "_id", "==", "@id")
		queryValues["id"] = *certifyBadSpec.ID
	}
	if certifyBadSpec.Justification != nil {
		arangoQueryBuilder.filter("certifyBad", justification, "==", "@"+justification)
		queryValues[justification] = *certifyBadSpec.Justification
	}
	if certifyBadSpec.Origin != nil {
		arangoQueryBuilder.filter("certifyBad", origin, "==", "@"+origin)
		queryValues[origin] = *certifyBadSpec.Origin
	}
	if certifyBadSpec.Collector != nil {
		arangoQueryBuilder.filter("certifyBad", collector, "==", "@"+collector)
		queryValues[collector] = *certifyBadSpec.Collector
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

	values["key"] = hasMetadata.Key
	values["value"] = hasMetadata.Value
	values[timeStampStr] = hasMetadata.Justification
	values[justification] = hasMetadata.Justification
	values[origin] = hasMetadata.Origin
	values[collector] = hasMetadata.Collector

	return values
}

func (c *arangoClient) IngestHasMetadata(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, hasMetadata model.HasMetadataInputSpec) (*model.HasMetadata, error) {
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
		  
		  LET hasMetadata = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				  INSERT {  packageID:firstPkg.version_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				  UPDATE {} IN hasMetadataCollection
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasMetadataPkgVersionEdges", firstPkg.versionDoc._key, hasMetadata._key), _from: firstPkg.version_id, _to: hasMetadata._id } INTO hasMetadataPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
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
			'hasMetadata_id': hasMetadata._id,
			'key': hasMetadata.key,
			'value': hasMetadata.value,
			'timestamp': hasMetadata.timestamp,
			'justification': hasMetadata.justification,
			'collector': hasMetadata.collector,
			'origin': hasMetadata.origin  
		  }`

			cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyBadQueryValues(subject.Package, pkgMatchType, nil, nil, &certifyBad), "IngestCertifyBad - PkgVersion")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package certifyBad: %w", err)
			}
			defer cursor.Close()

			certifyBadList, err := getCertifyBadFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get certifyBads from arango cursor: %w", err)
			}

			if len(certifyBadList) == 1 {
				return certifyBadList[0], nil
			} else {
				return nil, fmt.Errorf("number of certifyBad ingested is greater than one")
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
			  
			  LET hasMetadata = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
					  INSERT {  packageID:firstPkg.name_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
					  UPDATE {} IN hasMetadataCollection
					  RETURN NEW
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("hasMetadataPkgNameEdges", firstPkg.nameDoc._key, hasMetadata._key), _from: firstPkg.name_id, _to: hasMetadata._id } INTO hasMetadataPkgNameEdges OPTIONS { overwriteMode: "ignore" }
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
				'hasMetadata_id': hasMetadata._id,
			    'key': hasMetadata.key,
			    'value': hasMetadata.value,
			 	'timestamp': hasMetadata.timestamp,
				'justification': hasMetadata.justification,
				'collector': hasMetadata.collector,
				'origin': hasMetadata.origin  
			  }`

			cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyBadQueryValues(subject.Package, pkgMatchType, nil, nil, &certifyBad), "IngestCertifyBad - PkgName")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package certifyBad: %w", err)
			}
			defer cursor.Close()

			certifyBadList, err := getCertifyBadFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get certifyBads from arango cursor: %w", err)
			}

			if len(certifyBadList) == 1 {
				return certifyBadList[0], nil
			} else {
				return nil, fmt.Errorf("number of certifyBad ingested is greater than one")
			}
		}

	} else if subject.Artifact != nil {
		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
		  
		LET hasMetadata = FIRST(
			UPSERT { artifactID:artifact._id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				INSERT { artifactID:artifact._id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				UPDATE {} IN hasMetadataCollection
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("hasMetadataArtEdges", artifact._key, hasMetadata._key), _from: artifact._id, _to: hasMetadata._id } INTO hasMetadataArtEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN {
		  'artifact': {
			  'id': artifact._id,
			  'algorithm': artifact.algorithm,
			  'digest': artifact.digest
		  },
		  'hasMetadata_id': hasMetadata._id,
		  'key': hasMetadata.key,
		  'value': hasMetadata.value,
		  'timestamp': hasMetadata.timestamp,
		  'justification': hasMetadata.justification,
		  'collector': hasMetadata.collector,
		  'origin': hasMetadata.origin  
		}`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyBadQueryValues(nil, nil, subject.Artifact, nil, &certifyBad), "IngestCertifyBad - artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact certifyBad: %w", err)
		}
		defer cursor.Close()
		certifyBadList, err := getCertifyBadFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyBads from arango cursor: %w", err)
		}

		if len(certifyBadList) == 1 {
			return certifyBadList[0], nil
		} else {
			return nil, fmt.Errorf("number of certifyBad ingested is greater than one")
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
		  
		LET hasMetadata = FIRST(
			UPSERT { sourceID:firstSrc.name_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				INSERT { sourceID:firstSrc.name_id, key:@key, value:@value, timestamp:@timestamp, justification:@justification, collector:@collector, origin:@origin } 
				UPDATE {} IN hasMetadataCollection
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("hasMetadataSrcEdges", firstSrc.nameDoc._key, hasMetadata._key), _from: firstSrc.name_id, _to: hasMetadata._id } INTO hasMetadataSrcEdges OPTIONS { overwriteMode: "ignore" }
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
		  'hasMetadata_id': hasMetadata._id,
		  'key': hasMetadata.key,
		  'value': hasMetadata.value,
		  'timestamp': hasMetadata.timestamp,
		  'justification': hasMetadata.justification,
		  'collector': hasMetadata.collector,
		  'origin': hasMetadata.origin  
		}`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyBadQueryValues(nil, nil, nil, subject.Source, &certifyBad), "IngestCertifyBad - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source certifyBad: %w", err)
		}
		defer cursor.Close()
		certifyBadList, err := getCertifyBadFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyBads from arango cursor: %w", err)
		}

		if len(certifyBadList) == 1 {
			return certifyBadList[0], nil
		} else {
			return nil, fmt.Errorf("number of certifyBad ingested is greater than one")
		}

	} else {
		return nil, fmt.Errorf("package, artifact, or source is specified for IngestCertifyBad")
	}
}

func (c *arangoClient) IngestBulkHasMetadata(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, hasMetadataList []*model.HasMetadataInputSpec) ([]string, error) {
	return nil, fmt.Errorf("not implemented: IngestBulkHasMetadata")
}

func getHasMetadataFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.HasMetadata, error) {
	type collectedData struct {
		PkgVersion    *dbPkgVersion   `json:"pkgVersion"`
		Artifact      *model.Artifact `json:"artifact"`
		SrcName       *dbSrcName      `json:"srcName"`
		CertifyBadID  string          `json:"certifyBad_id"`
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
				return nil, fmt.Errorf("failed to certifyBad from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var certifyBadList []*model.CertifyBad
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

		certifyBad := &model.CertifyBad{
			ID:            createdValue.CertifyBadID,
			Justification: createdValue.Justification,
			Origin:        createdValue.Collector,
			Collector:     createdValue.Origin,
		}

		if pkg != nil {
			certifyBad.Subject = pkg
		} else if src != nil {
			certifyBad.Subject = src
		} else if createdValue.Artifact != nil {
			certifyBad.Subject = createdValue.Artifact
		} else {
			return nil, fmt.Errorf("failed to get subject from cursor for certifyBad")
		}
		certifyBadList = append(certifyBadList, certifyBad)
	}
	return certifyBadList, nil
}
