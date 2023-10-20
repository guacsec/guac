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

func (c *arangoClient) CertifyGood(ctx context.Context, certifyGoodSpec *model.CertifyGoodSpec) ([]*model.CertifyGood, error) {

	if certifyGoodSpec != nil && certifyGoodSpec.ID != nil {
		cg, err := c.buildCertifyGoodByID(ctx, *certifyGoodSpec.ID, certifyGoodSpec)
		if err != nil {
			return nil, fmt.Errorf("buildCertifyGoodByID failed with an error: %w", err)
		}
		return []*model.CertifyGood{cg}, nil
	}

	var arangoQueryBuilder *arangoQueryBuilder
	if certifyGoodSpec.Subject != nil {
		var combinedCertifyGood []*model.CertifyGood
		if certifyGoodSpec.Subject.Package != nil {
			values := map[string]any{}
			// pkgVersion certifyGood
			arangoQueryBuilder = setPkgVersionMatchValues(certifyGoodSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(certifyGoodPkgVersionEdgesStr, "certifyGood", "pVersion")
			setCertifyGoodMatchValues(arangoQueryBuilder, certifyGoodSpec, values)

			pkgVersionCertifyGoods, err := getPkgCertifyGoodForQuery(ctx, c, arangoQueryBuilder, values, true)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version certifyGood with error: %w", err)
			}

			combinedCertifyGood = append(combinedCertifyGood, pkgVersionCertifyGoods...)

			if certifyGoodSpec.Subject.Package.ID == nil {
				// pkgName certifyGood
				values = map[string]any{}
				arangoQueryBuilder = setPkgNameMatchValues(certifyGoodSpec.Subject.Package, values)
				arangoQueryBuilder.forOutBound(certifyGoodPkgNameEdgesStr, "certifyGood", "pName")
				setCertifyGoodMatchValues(arangoQueryBuilder, certifyGoodSpec, values)

				pkgNameCertifyGoods, err := getPkgCertifyGoodForQuery(ctx, c, arangoQueryBuilder, values, false)
				if err != nil {
					return nil, fmt.Errorf("failed to retrieve package name certifyGood with error: %w", err)
				}

				combinedCertifyGood = append(combinedCertifyGood, pkgNameCertifyGoods...)
			}
		}
		if certifyGoodSpec.Subject.Source != nil {
			values := map[string]any{}
			arangoQueryBuilder = setSrcMatchValues(certifyGoodSpec.Subject.Source, values)
			arangoQueryBuilder.forOutBound(certifyGoodSrcEdgesStr, "certifyGood", "sName")
			setCertifyGoodMatchValues(arangoQueryBuilder, certifyGoodSpec, values)

			srcCertifyGoods, err := getSrcCertifyGoodForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve source certifyGood with error: %w", err)
			}

			combinedCertifyGood = append(combinedCertifyGood, srcCertifyGoods...)
		}
		if certifyGoodSpec.Subject.Artifact != nil {
			values := map[string]any{}
			arangoQueryBuilder = setArtifactMatchValues(certifyGoodSpec.Subject.Artifact, values)
			arangoQueryBuilder.forOutBound(certifyGoodArtEdgesStr, "certifyGood", "art")
			setCertifyGoodMatchValues(arangoQueryBuilder, certifyGoodSpec, values)

			artCertifyGoods, err := getArtCertifyGoodForQuery(ctx, c, arangoQueryBuilder, values)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve artifact certifyGood with error: %w", err)
			}

			combinedCertifyGood = append(combinedCertifyGood, artCertifyGoods...)
		}
		return combinedCertifyGood, nil
	} else {
		values := map[string]any{}
		var combinedCertifyGood []*model.CertifyGood

		// pkgVersion certifyGood
		arangoQueryBuilder = newForQuery(certifyGoodsStr, "certifyGood")
		setCertifyGoodMatchValues(arangoQueryBuilder, certifyGoodSpec, values)
		arangoQueryBuilder.forInBound(certifyGoodPkgVersionEdgesStr, "pVersion", "certifyGood")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgVersionCertifyGoods, err := getPkgCertifyGoodForQuery(ctx, c, arangoQueryBuilder, values, true)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package version certifyGood  with error: %w", err)
		}
		combinedCertifyGood = append(combinedCertifyGood, pkgVersionCertifyGoods...)

		// pkgName certifyGood
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(certifyGoodsStr, "certifyGood")
		setCertifyGoodMatchValues(arangoQueryBuilder, certifyGoodSpec, values)
		arangoQueryBuilder.forInBound(certifyGoodPkgNameEdgesStr, "pName", "certifyGood")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgNameCertifyGoods, err := getPkgCertifyGoodForQuery(ctx, c, arangoQueryBuilder, values, false)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package name certifyGood  with error: %w", err)
		}
		combinedCertifyGood = append(combinedCertifyGood, pkgNameCertifyGoods...)

		// get sources
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(certifyGoodsStr, "certifyGood")
		setCertifyGoodMatchValues(arangoQueryBuilder, certifyGoodSpec, values)
		arangoQueryBuilder.forInBound(certifyGoodSrcEdgesStr, "sName", "certifyGood")
		arangoQueryBuilder.forInBound(srcHasNameStr, "sNs", "sName")
		arangoQueryBuilder.forInBound(srcHasNamespaceStr, "sType", "sNs")

		srcCertifyGoods, err := getSrcCertifyGoodForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve source certifyGood with error: %w", err)
		}
		combinedCertifyGood = append(combinedCertifyGood, srcCertifyGoods...)

		// get artifacts
		values = map[string]any{}
		arangoQueryBuilder = newForQuery(certifyGoodsStr, "certifyGood")
		setCertifyGoodMatchValues(arangoQueryBuilder, certifyGoodSpec, values)
		arangoQueryBuilder.forInBound(certifyGoodArtEdgesStr, "art", "certifyGood")

		artCertifyGoods, err := getArtCertifyGoodForQuery(ctx, c, arangoQueryBuilder, values)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve artifact certifyGood with error: %w", err)
		}
		combinedCertifyGood = append(combinedCertifyGood, artCertifyGoods...)

		return combinedCertifyGood, nil
	}
}

func getSrcCertifyGoodForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyGood, error) {
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
		'certifyGood_id': certifyGood._id,
		'justification': certifyGood.justification,
		'collector': certifyGood.collector,
		'knownSince': certifyGood.knownSince,
		'origin': certifyGood.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "certifyGood")
	if err != nil {
		return nil, fmt.Errorf("failed to query for certifyGood: %w", err)
	}
	defer cursor.Close()

	return getCertifyGoodFromCursor(ctx, cursor)
}

func getArtCertifyGoodForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any) ([]*model.CertifyGood, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'certifyGood_id': certifyGood._id,
		'justification': certifyGood.justification,
		'collector': certifyGood.collector,
		'knownSince': certifyGood.knownSince,
		'origin': certifyGood.origin
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "certifyGood")
	if err != nil {
		return nil, fmt.Errorf("failed to query for certifyGood: %w", err)
	}
	defer cursor.Close()

	return getCertifyGoodFromCursor(ctx, cursor)
}

func getPkgCertifyGoodForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, includeDepPkgVersion bool) ([]*model.CertifyGood, error) {
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
			'certifyGood_id': certifyGood._id,
			'justification': certifyGood.justification,
			'collector': certifyGood.collector,
			'knownSince': certifyGood.knownSince,
			'origin': certifyGood.origin
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
			'certifyGood_id': certifyGood._id,
			'justification': certifyGood.justification,
			'collector': certifyGood.collector,
			'knownSince': certifyGood.knownSince,
			'origin': certifyGood.origin
		  }`)
	}

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "certifyGood")
	if err != nil {
		return nil, fmt.Errorf("failed to query for certifyGood: %w", err)
	}
	defer cursor.Close()

	return getCertifyGoodFromCursor(ctx, cursor)
}

func setCertifyGoodMatchValues(arangoQueryBuilder *arangoQueryBuilder, certifyGoodSpec *model.CertifyGoodSpec, queryValues map[string]any) {
	if certifyGoodSpec.ID != nil {
		arangoQueryBuilder.filter("certifyGood", "_id", "==", "@id")
		queryValues["id"] = *certifyGoodSpec.ID
	}
	if certifyGoodSpec.Justification != nil {
		arangoQueryBuilder.filter("certifyGood", justification, "==", "@"+justification)
		queryValues[justification] = *certifyGoodSpec.Justification
	}
	if certifyGoodSpec.Origin != nil {
		arangoQueryBuilder.filter("certifyGood", origin, "==", "@"+origin)
		queryValues[origin] = *certifyGoodSpec.Origin
	}
	if certifyGoodSpec.Collector != nil {
		arangoQueryBuilder.filter("certifyGood", collector, "==", "@"+collector)
		queryValues[collector] = *certifyGoodSpec.Collector
	}
	if certifyGoodSpec.KnownSince != nil {
		certifyGoodKnownSince := *certifyGoodSpec.KnownSince
		arangoQueryBuilder.filter("certifyGood", "knownSince", ">=", "@"+knownSince)
		queryValues[knownSince] = certifyGoodKnownSince.UTC()
	}
}

func getCertifyGoodQueryValues(pkg *model.PkgInputSpec, pkgMatchType *model.MatchFlags, artifact *model.ArtifactInputSpec, source *model.SourceInputSpec, certifyGood *model.CertifyGoodInputSpec) map[string]any {
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

	values["justification"] = certifyGood.Justification
	values["origin"] = certifyGood.Origin
	values["collector"] = certifyGood.Collector
	values["knownSince"] = certifyGood.KnownSince.UTC()

	return values
}

func (c *arangoClient) IngestCertifyGood(ctx context.Context, subject model.PackageSourceOrArtifactInput, pkgMatchType *model.MatchFlags, certifyGood model.CertifyGoodInputSpec) (*model.CertifyGood, error) {
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

		  LET certifyGood = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince }
				  INSERT {  packageID:firstPkg.version_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince }
				  UPDATE {} IN certifyGoods
				  RETURN NEW
		  )

		  LET edgeCollection = (
			INSERT {  _key: CONCAT("certifyGoodPkgVersionEdges", firstPkg.versionDoc._key, certifyGood._key), _from: firstPkg.version_id, _to: certifyGood._id } INTO certifyGoodPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
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
			'certifyGood_id': certifyGood._id,
			'justification': certifyGood.justification,
			'collector': certifyGood.collector,
			'knownSince': certifyGood.knownSince,
			'origin': certifyGood.origin
		  }`

			cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyGoodQueryValues(subject.Package, pkgMatchType, nil, nil, &certifyGood), "IngestCertifyGood - PkgVersion")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package certifyGood: %w", err)
			}
			defer cursor.Close()

			certifyGoodList, err := getCertifyGoodFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get certifyGoods from arango cursor: %w", err)
			}

			if len(certifyGoodList) == 1 {
				return certifyGoodList[0], nil
			} else {
				return nil, fmt.Errorf("number of certifyGood ingested is greater than one")
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

			  LET certifyGood = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince }
					  INSERT {  packageID:firstPkg.name_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince }
					  UPDATE {} IN certifyGoods
					  RETURN NEW
			  )

			  LET edgeCollection = (
				INSERT {  _key: CONCAT("certifyGoodPkgNameEdges", firstPkg.nameDoc._key, certifyGood._key), _from: firstPkg.name_id, _to: certifyGood._id } INTO certifyGoodPkgNameEdges OPTIONS { overwriteMode: "ignore" }
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
				'certifyGood_id': certifyGood._id,
				'justification': certifyGood.justification,
				'collector': certifyGood.collector,
				'knownSince': certifyGood.knownSince,
				'origin': certifyGood.origin
			  }`

			cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyGoodQueryValues(subject.Package, pkgMatchType, nil, nil, &certifyGood), "IngestCertifyGood - PkgName")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package certifyGood: %w", err)
			}
			defer cursor.Close()

			certifyGoodList, err := getCertifyGoodFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get certifyGoods from arango cursor: %w", err)
			}

			if len(certifyGoodList) == 1 {
				return certifyGoodList[0], nil
			} else {
				return nil, fmt.Errorf("number of certifyGood ingested is greater than one")
			}
		}

	} else if subject.Artifact != nil {
		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)

		LET certifyGood = FIRST(
			UPSERT { artifactID:artifact._id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince }
				INSERT { artifactID:artifact._id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince }
				UPDATE {} IN certifyGoods
				RETURN NEW
		)

		LET edgeCollection = (
		  INSERT {  _key: CONCAT("certifyGoodArtEdges", artifact._key, certifyGood._key), _from: artifact._id, _to: certifyGood._id } INTO certifyGoodArtEdges OPTIONS { overwriteMode: "ignore" }
		)

		RETURN {
		  'artifact': {
			  'id': artifact._id,
			  'algorithm': artifact.algorithm,
			  'digest': artifact.digest
		  },
		  'certifyGood_id': certifyGood._id,
		  'justification': certifyGood.justification,
		  'collector': certifyGood.collector,
		  'knownSince': certifyGood.knownSince,
		  'origin': certifyGood.origin
		}`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyGoodQueryValues(nil, nil, subject.Artifact, nil, &certifyGood), "IngestCertifyGood - artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact certifyGood: %w", err)
		}
		defer cursor.Close()
		certifyGoodList, err := getCertifyGoodFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyGoods from arango cursor: %w", err)
		}

		if len(certifyGoodList) == 1 {
			return certifyGoodList[0], nil
		} else {
			return nil, fmt.Errorf("number of certifyGood ingested is greater than one")
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

		LET certifyGood = FIRST(
			UPSERT { sourceID:firstSrc.name_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince }
				INSERT { sourceID:firstSrc.name_id, justification:@justification, collector:@collector, origin:@origin, knownSince:@knownSince }
				UPDATE {} IN certifyGoods
				RETURN NEW
		)

		LET edgeCollection = (
		  INSERT {  _key: CONCAT("certifyGoodSrcEdges", firstSrc.nameDoc._key, certifyGood._key), _from: firstSrc.name_id, _to: certifyGood._id } INTO certifyGoodSrcEdges OPTIONS { overwriteMode: "ignore" }
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
		  'certifyGood_id': certifyGood._id,
		  'justification': certifyGood.justification,
		  'collector': certifyGood.collector,
		  'knownSince': certifyGood.knownSince,
		  'origin': certifyGood.origin
		}`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, getCertifyGoodQueryValues(nil, nil, nil, subject.Source, &certifyGood), "IngestCertifyGood - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source certifyGood: %w", err)
		}
		defer cursor.Close()
		certifyGoodList, err := getCertifyGoodFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyGoods from arango cursor: %w", err)
		}

		if len(certifyGoodList) == 1 {
			return certifyGoodList[0], nil
		} else {
			return nil, fmt.Errorf("number of certifyGood ingested is greater than one")
		}

	} else {
		return nil, fmt.Errorf("package, artifact, or source is specified for IngestCertifyGood")
	}
}

func (c *arangoClient) IngestCertifyGoods(ctx context.Context, subjects model.PackageSourceOrArtifactInputs, pkgMatchType *model.MatchFlags, certifyGoods []*model.CertifyGoodInputSpec) ([]*model.CertifyGood, error) {
	if len(subjects.Packages) > 0 {
		if len(subjects.Packages) != len(certifyGoods) {
			return nil, fmt.Errorf("uneven packages and certifyGoods for ingestion")
		}

		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getCertifyGoodQueryValues(subjects.Packages[i], pkgMatchType, nil, nil, certifyGoods[i]))
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
		  
		  LET certifyGood = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				  INSERT {  packageID:firstPkg.version_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				  UPDATE {} IN certifyGoods
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("certifyGoodPkgVersionEdges", firstPkg.versionDoc._key, certifyGood._key), _from: firstPkg.version_id, _to: certifyGood._id } INTO certifyGoodPkgVersionEdges OPTIONS { overwriteMode: "ignore" }
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
			'certifyGood_id': certifyGood._id,
			'justification': certifyGood.justification,
			'collector': certifyGood.collector,
			'knownSince': certifyGood.knownSince,
			'origin': certifyGood.origin  
		  }`

			sb.WriteString(query)

			cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyGoods - PkgVersion")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package certifyGoods: %w", err)
			}
			defer cursor.Close()

			certifyGoodList, err := getCertifyGoodFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get certifyGoods from arango cursor: %w", err)
			}

			return certifyGoodList, nil
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
			  
			  LET certifyGood = FIRST(
				  UPSERT {  packageID:firstPkg.name_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
					  INSERT {  packageID:firstPkg.name_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
					  UPDATE {} IN certifyGoods
					  RETURN NEW
			  )
			  
			  LET edgeCollection = (
				INSERT {  _key: CONCAT("certifyGoodPkgNameEdges", firstPkg.nameDoc._key, certifyGood._key), _from: firstPkg.name_id, _to: certifyGood._id } INTO certifyGoodPkgNameEdges OPTIONS { overwriteMode: "ignore" }
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
				'certifyGood_id': certifyGood._id,
				'justification': certifyGood.justification,
				'collector': certifyGood.collector,
				'knownSince': certifyGood.knownSince,
				'origin': certifyGood.origin  
			  }`

			sb.WriteString(query)

			cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyGoods - PkgName")
			if err != nil {
				return nil, fmt.Errorf("failed to ingest package certifyGoods: %w", err)
			}
			defer cursor.Close()

			certifyGoodList, err := getCertifyGoodFromCursor(ctx, cursor)
			if err != nil {
				return nil, fmt.Errorf("failed to get certifyGoods from arango cursor: %w", err)
			}

			return certifyGoodList, nil
		}

	} else if len(subjects.Artifacts) > 0 {

		if len(subjects.Artifacts) != len(certifyGoods) {
			return nil, fmt.Errorf("uneven artifacts and certifyGoods for ingestion")
		}

		var listOfValues []map[string]any

		for i := range subjects.Artifacts {
			listOfValues = append(listOfValues, getCertifyGoodQueryValues(nil, nil, subjects.Artifacts[i], nil, certifyGoods[i]))
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
		  
		LET certifyGood = FIRST(
			UPSERT { artifactID:artifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				INSERT { artifactID:artifact._id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				UPDATE {} IN certifyGoods
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("certifyGoodArtEdges", artifact._key, certifyGood._key), _from: artifact._id, _to: certifyGood._id } INTO certifyGoodArtEdges OPTIONS { overwriteMode: "ignore" }
		)
		
		RETURN {
		  'artifact': {
			  'id': artifact._id,
			  'algorithm': artifact.algorithm,
			  'digest': artifact.digest
		  },
		  'certifyGood_id': certifyGood._id,
		  'justification': certifyGood.justification,
		  'collector': certifyGood.collector,
		  'knownSince': certifyGood.knownSince,
		  'origin': certifyGood.origin
		}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyGoods - artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact certifyGoods %w", err)
		}
		defer cursor.Close()
		certifyGoodList, err := getCertifyGoodFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyGoods from arango cursor: %w", err)
		}

		return certifyGoodList, nil

	} else if len(subjects.Sources) > 0 {

		if len(subjects.Sources) != len(certifyGoods) {
			return nil, fmt.Errorf("uneven sources and certifyGoods for ingestion")
		}

		var listOfValues []map[string]any

		for i := range subjects.Sources {
			listOfValues = append(listOfValues, getCertifyGoodQueryValues(nil, nil, nil, subjects.Sources[i], certifyGoods[i]))
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
		  
		LET certifyGood = FIRST(
			UPSERT { sourceID:firstSrc.name_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				INSERT { sourceID:firstSrc.name_id, justification:doc.justification, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				UPDATE {} IN certifyGoods
				RETURN NEW
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("certifyGoodSrcEdges", firstSrc.nameDoc._key, certifyGood._key), _from: firstSrc.name_id, _to: certifyGood._id } INTO certifyGoodSrcEdges OPTIONS { overwriteMode: "ignore" }
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
		  'certifyGood_id': certifyGood._id,
		  'justification': certifyGood.justification,
		  'collector': certifyGood.collector,
		  'knownSince': certifyGood.knownSince,
		  'origin': certifyGood.origin
		}`

		sb.WriteString(query)

		cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestCertifyGoods - source")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest source certifyGoods: %w", err)
		}
		defer cursor.Close()
		certifyGoodList, err := getCertifyGoodFromCursor(ctx, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to get certifyGoods from arango cursor: %w", err)
		}

		return certifyGoodList, nil

	} else {
		return nil, fmt.Errorf("packages, artifacts, or sources not specified for IngestCertifyGoods")
	}
}

func getCertifyGoodFromCursor(ctx context.Context, cursor driver.Cursor) ([]*model.CertifyGood, error) {
	type collectedData struct {
		PkgVersion    *dbPkgVersion   `json:"pkgVersion"`
		Artifact      *model.Artifact `json:"artifact"`
		SrcName       *dbSrcName      `json:"srcName"`
		CertifyGoodID string          `json:"certifyGood_id"`
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
				return nil, fmt.Errorf("failed to package certifyGood from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var certifyGoodList []*model.CertifyGood
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
		certifyGood := &model.CertifyGood{
			ID:            createdValue.CertifyGoodID,
			Justification: createdValue.Justification,
			Origin:        createdValue.Collector,
			Collector:     createdValue.Origin,
			KnownSince:    createdValue.KnownSince,
		}
		if pkg != nil {
			certifyGood.Subject = pkg
		} else if src != nil {
			certifyGood.Subject = src
		} else if createdValue.Artifact != nil {
			certifyGood.Subject = createdValue.Artifact
		} else {
			return nil, fmt.Errorf("failed to get subject from cursor for certifyGood")
		}
		certifyGoodList = append(certifyGoodList, certifyGood)
	}
	return certifyGoodList, nil
}

func (c *arangoClient) buildCertifyGoodByID(ctx context.Context, id string, filter *model.CertifyGoodSpec) (*model.CertifyGood, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == certifyGoodsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.CertifyGoodSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryCertifyGoodNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for certifyGood query: %s", id)
	}
}

func (c *arangoClient) queryCertifyGoodNodeByID(ctx context.Context, filter *model.CertifyGoodSpec) (*model.CertifyGood, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(certifyGoodsStr, "certifyGood")
	setCertifyGoodMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN certifyGood`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryCertifyGoodNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for certifyGood: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbCertifyGood struct {
		CertifyGoodID string  `json:"_id"`
		PackageID     *string `json:"packageID"`
		SourceID      *string `json:"sourceID"`
		ArtifactID    *string `json:"artifactID"`
		Justification string  `json:"justification"`
		Collector     string  `json:"collector"`
		Origin        string  `json:"origin"`
	}

	var collectedValues []dbCertifyGood
	for {
		var doc dbCertifyGood
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to certifyGood from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of certifyGood nodes found for ID: %s is greater than one", *filter.ID)
	}

	certifyGood := &model.CertifyGood{
		ID:            collectedValues[0].CertifyGoodID,
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
		certifyGood.Subject = builtPackage
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
		certifyGood.Subject = builtSource
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
		certifyGood.Subject = builtArtifact
	} else {
		return nil, fmt.Errorf("failed to get subject from certifyGood")
	}
	return certifyGood, nil
}

func (c *arangoClient) certifyGoodNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 1)

	if allowedEdges[model.EdgeCertifyGoodPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyGoodsStr, "certifyGood")
		setCertifyGoodMatchValues(arangoQueryBuilder, &model.CertifyGoodSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyGood.packageID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyGoodNeighbors - package")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeCertifyGoodArtifact] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyGoodsStr, "certifyGood")
		setCertifyGoodMatchValues(arangoQueryBuilder, &model.CertifyGoodSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyGood.artifactID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyGoodNeighbors - artifact")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeCertifyGoodSource] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(certifyGoodsStr, "certifyGood")
		setCertifyGoodMatchValues(arangoQueryBuilder, &model.CertifyGoodSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  certifyGood.sourceID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "certifyGoodNeighbors - source")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	return out, nil
}
