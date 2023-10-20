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

func (c *arangoClient) CertifyBad(ctx context.Context, certifyBadSpec *model.CertifyBadSpec) ([]*model.CertifyBad, error) {

	if certifyBadSpec != nil && certifyBadSpec.ID != nil {
		cb, err := c.buildCertifyBadByID(ctx, *certifyBadSpec.ID, certifyBadSpec)
		if err != nil {
			return nil, fmt.Errorf("buildCertifyBadByID failed with an error: %w", err)
		}
		return []*model.CertifyBad{cb}, nil
	}

	var arangoQueryBuilder *arangoQueryBuilder
	if certifyBadSpec.Subject != nil {
		var combinedCertifyBad []*model.CertifyBad
		if certifyBadSpec.Subject.Package != nil {
			values := map[string]any{}
			// pkgVersion certifyBad
			arangoQueryBuilder = setPkgVersionMatchValues(certifyBadSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(certifyBadPkgVersionEdgesStr, "certifyBad", "pVersion")
			setCertifyBadMatchValues(arangoQueryBuilder, certifyBadSpec, values)

			pkgVersionCertifyBads, err := getPkgCertifyBadForQuery(ctx, c, arangoQueryBuilder, values, true)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version certifyBad with error: %w", err)
			}

			combinedCertifyBad = append(combinedCertifyBad, pkgVersionCertifyBads...)

			if certifyBadSpec.Subject.Package.ID == nil {
				// pkgName certifyBad
				values = map[string]any{}
				arangoQueryBuilder = setPkgNameMatchValues(certifyBadSpec.Subject.Package, values)
				arangoQueryBuilder.forOutBound(certifyBadPkgNameEdgesStr, "certifyBad", "pName")
				setCertifyBadMatchValues(arangoQueryBuilder, certifyBadSpec, values)

				pkgNameCertifyBads, err := getPkgCertifyBadForQuery(ctx, c, arangoQueryBuilder, values, false)
				if err != nil {
					return nil, fmt.Errorf("failed to retrieve package name certifyBad with error: %w", err)
				}

				combinedCertifyBad = append(combinedCertifyBad, pkgNameCertifyBads...)
			}
		}
		if certifyBadSpec.Subject.Source != nil {
			values := map[string]any{}
			arangoQueryBuilder = setSrcMatchValues(certifyBadSpec.Subject.Source, values)
			arangoQueryBuilder.forOutBound(certifyBadSrcEdgesStr, "certifyBad", "sName")
			setCertifyBadMatchValues(arangoQueryBuilder, certifyBadSpec, values)

			srcCertifyBads, err := getSrcCertifyBadForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve source certifyBad with error: %w", err)
			}

			combinedCertifyBad = append(combinedCertifyBad, srcCertifyBads...)
		}
		if certifyBadSpec.Subject.Artifact != nil {
			values := map[string]any{}
			arangoQueryBuilder = setArtifactMatchValues(certifyBadSpec.Subject.Artifact, values)
			arangoQueryBuilder.forOutBound(certifyBadArtEdgesStr, "certifyBad", "art")
			setCertifyBadMatchValues(arangoQueryBuilder, certifyBadSpec, values)

			artCertifyBads, err := getArtCertifyBadForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve artifact certifyBad with error: %w", err)
			}

			combinedCertifyBad = append(combinedCertifyBad, artCertifyBads...)
		}
		return combinedCertifyBad, nil
	} else {
		values := map[string]any{}
		var combinedCertifyBad []*model.CertifyBad

		// pkgVersion certifyBad
		arangoQueryBuilder = newForQuery(certifyBadsStr, "certifyBad")
		setCertifyBadMatchValues(arangoQueryBuilder, certifyBadSpec, values)
		arangoQueryBuilder.forInBound(certifyBadPkgVersionEdgesStr, "pVersion", "certifyBad")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgVersionCertifyBads, err := getPkgCertifyBadForQuery(ctx, c, arangoQueryBuilder, values, true)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package version certifyBad  with error: %w", err)
		}
		combinedCertifyBad = append(combinedCertifyBad, pkgVersionCertifyBads...)

		// pkgName certifyBad
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(certifyBadsStr, "certifyBad")
		setCertifyBadMatchValues(arangoQueryBuilder, certifyBadSpec, values)
		arangoQueryBuilder.forInBound(certifyBadPkgNameEdgesStr, "pName", "certifyBad")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgNameCertifyBads, err := getPkgCertifyBadForQuery(ctx, c, arangoQueryBuilder, values, false)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package name certifyBad  with error: %w", err)
		}
		combinedCertifyBad = append(combinedCertifyBad, pkgNameCertifyBads...)

		// get sources
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(certifyBadsStr, "certifyBad")
		setCertifyBadMatchValues(arangoQueryBuilder, certifyBadSpec, values)
		arangoQueryBuilder.forInBound(certifyBadSrcEdgesStr, "sName", "certifyBad")
		arangoQueryBuilder.forInBound(srcHasNameStr, "sNs", "sName")
		arangoQueryBuilder.forInBound(srcHasNamespaceStr, "sType", "sNs")

		srcCertifyBads, err := getSrcCertifyBadForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve source certifyBad with error: %w", err)
		}
		combinedCertifyBad = append(combinedCertifyBad, srcCertifyBads...)

		// get artifacts
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(certifyBadsStr, "certifyBad")
		setCertifyBadMatchValues(arangoQueryBuilder, certifyBadSpec, values)
		arangoQueryBuilder.forInBound(certifyBadArtEdgesStr, "art", "certifyBad")

		artCertifyBads, err := getArtCertifyBadForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve artifact certifyBad with error: %w", err)
		}
		combinedCertifyBad = append(combinedCertifyBad, artCertifyBads...)

		return combinedCertifyBad, nil
	}
}

func getSrcCertifyBadForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyBad, error) {
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
		'certifyBad_id': certifyBad._id,
		'justification': certifyBad.justification,
		'collector': certifyBad.collector,
		'knownSince': certifyBad.knownSince,
		'origin': certifyBad.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "CertifyBad")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyBad: %w", err)
	}
	defer cursor.Close()

	return getCertifyBadFromCursor(ctx, cursor)
}

func getArtCertifyBadForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyBad, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'certifyBad_id': certifyBad._id,
		'justification': certifyBad.justification,
		'collector': certifyBad.collector,
		'knownSince': certifyBad.knownSince,
		'origin': certifyBad.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "CertifyBad")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyBad: %w", err)
	}
	defer cursor.Close()

	return getCertifyBadFromCursor(ctx, cursor)
}

func getPkgCertifyBadForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, includeDepPkgVersion bool) ([]*model.CertifyBad, error) {
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
			'certifyBad_id': certifyBad._id,
			'justification': certifyBad.justification,
			'collector': certifyBad.collector,
			'knownSince': certifyBad.knownSince,
			'origin': certifyBad.origin
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
			'certifyBad_id': certifyBad._id,
			'justification': certifyBad.justification,
			'collector': certifyBad.collector,
			'knownSince': certifyBad.knownSince,
			'origin': certifyBad.origin
		  }`)
	}

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "CertifyBad")
	if err != nil {
		return nil, fmt.Errorf("failed to query for CertifyBad: %w", err)
	}
	defer cursor.Close()

	return getCertifyBadFromCursor(ctx, cursor)
}

func setCertifyBadMatchValues(arangoQueryBuilder *arangoQueryBuilder, certifyBadSpec *model.CertifyBadSpec, queryValues map[string]any) {
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
	if certifyBadSpec.KnownSince != nil {
		certifyBadKnownSince := *certifyBadSpec.KnownSince
		arangoQueryBuilder.filter("certifyBad", "knownSince", ">=", "@"+knownSince)
		queryValues[knownSince] = certifyBadKnownSince.UTC()
	}
}

func getCertifyBadQueryValues(pkg *model.PkgInputSpec, pkgMatchType *model.MatchFlags, artifact *model.ArtifactInputSpec, source *model.SourceInputSpec, certifyBad *model.CertifyBadInputSpec) map[string]any {
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

	values["justification"] = certifyBad.Justification
	values["origin"] = certifyBad.Origin
	values["collector"] = certifyBad.Collector
	values[knownSince] = certifyBad.KnownSince.UTC()

	return values
}

func (c *arangoClient) IngestCertifyBad(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyBad model.CertifyBadInputSpec) (*model.CertifyBad, error) {
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
		  
		  LET certifyBad = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  INSERT {  packageID:firstPkg.version_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  UPDATE {} IN certifyBads
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("certifyBadPkgVersionEdges", firstPkg.versionDoc._key, certifyBad._key), _from: firstPkg.version_id, _to: certifyBad._id } INTO certifyBadPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
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
			'certifyBad_id': certifyBad._id,
			'justification': certifyBad.justification,
			'collector': certifyBad.collector,
			'knownSince': certifyBad.knownSince,
			'origin': certifyBad.origin  
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
			  
			  LET certifyBad = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince } 
					  INSERT {  packageID:firstPkg.name_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince } 
					  UPDATE {} IN certifyBads
					  RETURN NEW
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("certifyBadPkgNameEdges", firstPkg.nameDoc._key, certifyBad._key), _from: firstPkg.name_id, _to: certifyBad._id } INTO certifyBadPkgNameEdges OPTIONS { overwriteMode: "ignore" }
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
				'certifyBad_id': certifyBad._id,
				'justification': certifyBad.justification,
				'collector': certifyBad.collector,
				'knownSince': certifyBad.knownSince,
				'origin': certifyBad.origin  
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
		  
		LET certifyBad = FIRST(
			UPSERT { artifactID:artifact._id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince } 
				INSERT { artifactID:artifact._id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince } 
				UPDATE {} IN certifyBads
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("certifyBadArtEdges", artifact._key, certifyBad._key), _from: artifact._id, _to: certifyBad._id } INTO certifyBadArtEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN {
		  'artifact': {
			  'id': artifact._id,
			  'algorithm': artifact.algorithm,
			  'digest': artifact.digest
		  },
		  'certifyBad_id': certifyBad._id,
		  'justification': certifyBad.justification,
		  'collector': certifyBad.collector,
          'knownSince': certifyBad.knownSince,
		  'origin': certifyBad.origin
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
		  
		LET certifyBad = FIRST(
			UPSERT { sourceID:firstSrc.name_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince } 
				INSERT { sourceID:firstSrc.name_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince } 
				UPDATE {} IN certifyBads
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("certifyBadSrcEdges", firstSrc.nameDoc._key, certifyBad._key), _from: firstSrc.name_id, _to: certifyBad._id } INTO certifyBadSrcEdges OPTIONS { overwriteMode: "ignore" }
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
		  'certifyBad_id': certifyBad._id,
		  'justification': certifyBad.justification,
		  'collector': certifyBad.collector,
		  'knownSince': certifyBad.knownSince,
		  'origin': certifyBad.origin
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

func (c *arangoClient) IngestCertifyBads(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyBads []*model.CertifyBadInputSpec) ([]*model.CertifyBad, error) {
	if len(subjects.Packages) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getCertifyBadQueryValues(subjects.Packages[i], pkgMatchType, nil, nil, certifyBads[i]))
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
		  
		  LET certifyBad = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				  INSERT {  packageID:firstPkg.version_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				  UPDATE {} IN certifyBads
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("certifyBadPkgVersionEdges", firstPkg.versionDoc._key, certifyBad._key), _from: firstPkg.version_id, _to: certifyBad._id } INTO certifyBadPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
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
			'certifyBad_id': certifyBad._id,
			'justification': certifyBad.justification,
			'collector': certifyBad.collector,
			'knownSince': certifyBad.knownSince,
			'origin': certifyBad.origin  
		  }`

			sb.WriteString(query)

			cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyBads - PkgVersion")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package certifyBads: %w", err)
			}
			defer cursor.Close()

			certifyBadList, err := getCertifyBadFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get certifyBads from arango cursor: %w", err)
			}

			return certifyBadList, nil
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
			  
			  LET certifyBad = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
					  INSERT {  packageID:firstPkg.name_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
					  UPDATE {} IN certifyBads
					  RETURN NEW
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("certifyBadPkgNameEdges", firstPkg.nameDoc._key, certifyBad._key), _from: firstPkg.name_id, _to: certifyBad._id } INTO certifyBadPkgNameEdges OPTIONS { overwriteMode: "ignore" }
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
				'certifyBad_id': certifyBad._id,
				'justification': certifyBad.justification,
				'collector': certifyBad.collector,
				'knownSince': certifyBad.knownSince,
				'origin': certifyBad.origin  
			  }`

			sb.WriteString(query)

			cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyBads - PkgName")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package certifyBads: %w", err)
			}
			defer cursor.Close()

			certifyBadList, err := getCertifyBadFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get certifyBads from arango cursor: %w", err)
			}

			return certifyBadList, nil
		}

	} else if len(subjects.Artifacts) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Artifacts {
			listOfValues = append(listOfValues, getCertifyBadQueryValues(nil, nil, subjects.Artifacts[i], nil, certifyBads[i]))
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
		  
		LET certifyBad = FIRST(
			UPSERT { artifactID:artifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				INSERT { artifactID:artifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				UPDATE {} IN certifyBads
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("certifyBadArtEdges", artifact._key, certifyBad._key), _from: artifact._id, _to: certifyBad._id } INTO certifyBadArtEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN {
		  'artifact': {
			  'id': artifact._id,
			  'algorithm': artifact.algorithm,
			  'digest': artifact.digest
		  },
		  'certifyBad_id': certifyBad._id,
		  'justification': certifyBad.justification,
		  'collector': certifyBad.collector,
		  'knownSince': certifyBad.knownSince,
		  'origin': certifyBad.origin
		}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyBads - artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact certifyBad: %w", err)
		}
		defer cursor.Close()
		certifyBadList, err := getCertifyBadFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyBads from arango cursor: %w", err)
		}

		return certifyBadList, nil

	} else if len(subjects.Sources) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Sources {
			listOfValues = append(listOfValues, getCertifyBadQueryValues(nil, nil, nil, subjects.Sources[i], certifyBads[i]))
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
		  
		LET certifyBad = FIRST(
			UPSERT { sourceID:firstSrc.name_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				INSERT { sourceID:firstSrc.name_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				UPDATE {} IN certifyBads
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("certifyBadSrcEdges", firstSrc.nameDoc._key, certifyBad._key), _from: firstSrc.name_id, _to: certifyBad._id } INTO certifyBadSrcEdges OPTIONS { overwriteMode: "ignore" }
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
		  'certifyBad_id': certifyBad._id,
		  'justification': certifyBad.justification,
		  'collector': certifyBad.collector,
		  'knownSince': certifyBad.knownSince,
		  'origin': certifyBad.origin
		}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyBads - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source certifyBad: %w", err)
		}
		defer cursor.Close()
		certifyBadList, err := getCertifyBadFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyBads from arango cursor: %w", err)
		}

		return certifyBadList, nil

	} else {
		return nil, fmt.Errorf("packages, artifacts, or sources not specified for IngestCertifyBads")
	}
}

func getCertifyBadFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.CertifyBad, error) {
	type collectedData struct {
		PkgVersion    *dbPkgVersion   `json:"pkgVersion"`
		Artifact      *model.Artifact `json:"artifact"`
		SrcName       *dbSrcName      `json:"srcName"`
		CertifyBadID  string          `json:"certifyBad_id"`
		Justification string          `json:"justification"`
		Collector     string          `json:"collector"`
		KnownSince    time.Time       `json:"knownSince"`
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
			KnownSince:    createdValue.KnownSince,
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

func (c *arangoClient) buildCertifyBadByID(ctx context.Context, id string, filter *model.CertifyBadSpec) (*model.CertifyBad, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == certifyBadsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.CertifyBadSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryCertifyBadNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for certifyBad query: %s", id)
	}
}

func (c *arangoClient) queryCertifyBadNodeByID(ctx context.Context, filter *model.CertifyBadSpec) (*model.CertifyBad, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(certifyBadsStr, "certifyBad")
	setCertifyBadMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN certifyBad`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryCertifyBadNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for certifyBad: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbCertifyBad struct {
		CertifyBadID  string  `json:"_id"`
		PackageID     *string `json:"packageID"`
		SourceID      *string `json:"sourceID"`
		ArtifactID    *string `json:"artifactID"`
		Justification string  `json:"justification"`
		Collector     string  `json:"collector"`
		Origin        string  `json:"origin"`
	}

	var collectedValues []dbCertifyBad
	for {
		var doc dbCertifyBad
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to certifyBad from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of certifyBad nodes found for ID: %s is greater than one", *filter.ID)
	}

	certifyBad := &model.CertifyBad{
		ID:            collectedValues[0].CertifyBadID,
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
		certifyBad.Subject = builtPackage
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
		certifyBad.Subject = builtSource
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
		certifyBad.Subject = builtArtifact
	} else {
		return nil, fmt.Errorf("failed to get subject from certifyBad")
	}
	return certifyBad, nil
}

func (c *arangoClient) certifyBadNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 1)

	if allowedEdges[model.EdgeCertifyBadPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyBadsStr, "certifyBad")
		setCertifyBadMatchValues(arangoQueryBuilder, &model.CertifyBadSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyBad.packageID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyBadNeighbors - package")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeCertifyBadArtifact] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyBadsStr, "certifyBad")
		setCertifyBadMatchValues(arangoQueryBuilder, &model.CertifyBadSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyBad.artifactID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyBadNeighbors - artifact")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeCertifyBadSource] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyBadsStr, "certifyBad")
		setCertifyBadMatchValues(arangoQueryBuilder, &model.CertifyBadSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyBad.sourceID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyBadNeighbors - source")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	return out, nil
}
