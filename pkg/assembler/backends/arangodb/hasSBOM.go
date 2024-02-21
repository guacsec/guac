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
	"sync"
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/helper"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {

	if hasSBOMSpec != nil && hasSBOMSpec.ID != nil {
		sbom, err := c.buildHasSbomByID(ctx, *hasSBOMSpec.ID, hasSBOMSpec)
		if err != nil {
			return nil, fmt.Errorf("buildHasSbomByID failed with an error: %w", err)
		}
		return []*model.HasSbom{sbom}, nil
	}

	// TODO (pxp928): Optimize/add other queries based on input and starting node/edge for most efficient retrieval
	var arangoQueryBuilder *arangoQueryBuilder
	if hasSBOMSpec.Subject != nil {
		var combinedHasSBOM []*model.HasSbom
		if hasSBOMSpec.Subject.Package != nil {
			values := map[string]any{}
			arangoQueryBuilder = setPkgVersionMatchValues(hasSBOMSpec.Subject.Package, values)
			arangoQueryBuilder.forOutBound(hasSBOMPkgEdgesStr, "hasSBOM", "pVersion")
			setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)

			pkgVersionHasSboms, err := getPkgHasSBOMForQuery(ctx, c, arangoQueryBuilder, values, hasSBOMSpec)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve package version hasSBOM with error: %w", err)
			}

			combinedHasSBOM = append(combinedHasSBOM, pkgVersionHasSboms...)
		}
		if hasSBOMSpec.Subject.Artifact != nil {
			values := map[string]any{}
			arangoQueryBuilder = setArtifactMatchValues(hasSBOMSpec.Subject.Artifact, values)
			arangoQueryBuilder.forOutBound(hasSBOMArtEdgesStr, "hasSBOM", "art")
			setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)

			artHasSboms, err := getArtifactHasSBOMForQuery(ctx, c, arangoQueryBuilder, values, hasSBOMSpec)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve artifact hasSBOM with error: %w", err)
			}
			combinedHasSBOM = append(combinedHasSBOM, artHasSboms...)
		}
		return combinedHasSBOM, nil
	} else {
		values := map[string]any{}
		var combinedHasSBOM []*model.HasSbom

		// get packages
		arangoQueryBuilder = newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)
		arangoQueryBuilder.forInBound(hasSBOMPkgEdgesStr, "pVersion", "hasSBOM")
		arangoQueryBuilder.forInBound(pkgHasVersionStr, "pName", "pVersion")
		arangoQueryBuilder.forInBound(pkgHasNameStr, "pNs", "pName")
		arangoQueryBuilder.forInBound(pkgHasNamespaceStr, "pType", "pNs")

		pkgHasSBOMs, err := getPkgHasSBOMForQuery(ctx, c, arangoQueryBuilder, values, hasSBOMSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve package SBOMs with error: %w", err)
		}
		combinedHasSBOM = append(combinedHasSBOM, pkgHasSBOMs...)

		// get artifacts
		arangoQueryBuilder = newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, hasSBOMSpec, values)
		arangoQueryBuilder.forInBound(hasSBOMArtEdgesStr, "art", "hasSBOM")

		artifactHasSBOMs, err := getArtifactHasSBOMForQuery(ctx, c, arangoQueryBuilder, values, hasSBOMSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve artifact SBOMs with error: %w", err)
		}
		combinedHasSBOM = append(combinedHasSBOM, artifactHasSBOMs...)

		return combinedHasSBOM, nil
	}
}

func getPkgHasSBOMForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, filter *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'pkgVersion': {
			"type_id": pType._id,
			"type": pType.type,
			"namespace_id": pNs._id,
			"namespace": pNs.namespace,
			"name_id": pName._id,
			"name": pName.name,
			"version_id": pVersion._id,
			"version": pVersion.version,
			"subpath": pVersion.subpath,
			"qualifier_list": pVersion.qualifier_list
		},
		'hasSBOM_id': hasSBOM._id,
		'uri': hasSBOM.uri,
		'algorithm': hasSBOM.algorithm,
		'digest': hasSBOM.digest,
		'downloadLocation': hasSBOM.downloadLocation,
		'collector': hasSBOM.collector,
		'knownSince': hasSBOM.knownSince,
		'origin': hasSBOM.origin,
		'includedSoftware': hasSBOM.includedSoftware,
		'includedDependencies': hasSBOM.includedDependencies,
		'includesOccurrences': hasSBOM.includesOccurrences
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasSBOM")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasSBOM: %w", err)
	}
	defer cursor.Close()

	return c.getHasSBOMFromCursor(ctx, cursor, filter, false)
}

func getArtifactHasSBOMForQuery(ctx context.Context, c *arangoClient, arangoQueryBuilder *arangoQueryBuilder, values map[string]any, filter *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'artifact': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'hasSBOM_id': hasSBOM._id,
		'uri': hasSBOM.uri,
		'algorithm': hasSBOM.algorithm,
		'digest': hasSBOM.digest,
		'downloadLocation': hasSBOM.downloadLocation,
		'collector': hasSBOM.collector,
		'knownSince': hasSBOM.knownSince,
		'origin': hasSBOM.origin,
		'includedSoftware': hasSBOM.includedSoftware,
		'includedDependencies': hasSBOM.includedDependencies,
		'includesOccurrences': hasSBOM.includesOccurrences
	  }`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasSBOM")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasSBOM: %w", err)
	}
	defer cursor.Close()

	return c.getHasSBOMFromCursor(ctx, cursor, filter, false)
}

func setHasSBOMMatchValues(arangoQueryBuilder *arangoQueryBuilder, hasSBOMSpec *model.HasSBOMSpec, queryValues map[string]any) {
	if hasSBOMSpec.ID != nil {
		arangoQueryBuilder.filter("hasSBOM", "_id", "==", "@id")
		queryValues["id"] = *hasSBOMSpec.ID
	}
	if hasSBOMSpec.URI != nil {
		arangoQueryBuilder.filter("hasSBOM", "uri", "==", "@uri")
		queryValues["uri"] = *hasSBOMSpec.URI
	}
	if hasSBOMSpec.Algorithm != nil {
		arangoQueryBuilder.filter("hasSBOM", "algorithm", "==", "@algorithm")
		queryValues["algorithm"] = strings.ToLower(*hasSBOMSpec.Algorithm)
	}
	if hasSBOMSpec.Digest != nil {
		arangoQueryBuilder.filter("hasSBOM", "digest", "==", "@digest")
		queryValues["digest"] = strings.ToLower(*hasSBOMSpec.Digest)
	}
	if hasSBOMSpec.DownloadLocation != nil {
		arangoQueryBuilder.filter("hasSBOM", "downloadLocation", "==", "@downloadLocation")
		queryValues["downloadLocation"] = *hasSBOMSpec.DownloadLocation
	}
	if hasSBOMSpec.Origin != nil {
		arangoQueryBuilder.filter("hasSBOM", origin, "==", "@"+origin)
		queryValues[origin] = *hasSBOMSpec.Origin
	}
	if hasSBOMSpec.Collector != nil {
		arangoQueryBuilder.filter("hasSBOM", collector, "==", "@"+collector)
		queryValues[collector] = *hasSBOMSpec.Collector
	}
	if hasSBOMSpec.KnownSince != nil {
		hasSBOMKnownSince := *hasSBOMSpec.KnownSince
		arangoQueryBuilder.filter("hasSBOM", "knownSince", ">=", "@"+knownSince)
		queryValues[knownSince] = hasSBOMKnownSince.UTC()
	}
}

func getHasSBOMQueryValues(pkg *model.PkgInputSpec, artifact *model.ArtifactInputSpec, hasSbom *model.HasSBOMInputSpec, includes *model.HasSBOMIncludesInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	if pkg != nil {
		pkgId := guacPkgId(*pkg)
		values["pkgVersionGuacKey"] = pkgId.VersionId
	} else {
		values["art_algorithm"] = strings.ToLower(artifact.Algorithm)
		values["art_digest"] = strings.ToLower(artifact.Digest)
	}

	// initialize as empty slices for the query to run. Nil slice will cause an error
	dedupedIncludedSoftwareIDs := make([]string, 0)
	dedupedIncludedDependenciesIDs := make([]string, 0)
	dedupedIncludesOccurrencesIDs := make([]string, 0)
	includedSoftwarePkgKeys := make([]string, 0)
	includedSoftwareArtKeys := make([]string, 0)
	includedDependenciesKeys := make([]string, 0)
	includedOccurrencesKeys := make([]string, 0)

	var includesSoftware []string
	includesSoftware = append(includesSoftware, includes.Packages...)
	includesSoftware = append(includesSoftware, includes.Artifacts...)

	if includesSoftware != nil {
		dedupedIncludedSoftwareIDs = helper.SortAndRemoveDups(includesSoftware)
	}
	if includes.Dependencies != nil {
		dedupedIncludedDependenciesIDs = helper.SortAndRemoveDups(includes.Dependencies)
	}
	if includes.Occurrences != nil {
		dedupedIncludesOccurrencesIDs = helper.SortAndRemoveDups(includes.Occurrences)
	}

	for _, id := range dedupedIncludedSoftwareIDs {
		idSplit := strings.Split(id, "/")
		switch idSplit[0] {
		case pkgVersionsStr:
			includedSoftwarePkgKeys = append(includedSoftwarePkgKeys, idSplit[1])
		case artifactsStr:
			includedSoftwareArtKeys = append(includedSoftwareArtKeys, idSplit[1])
		}
	}

	for _, id := range dedupedIncludedDependenciesIDs {
		splitID := strings.Split(id, "/")
		includedDependenciesKeys = append(includedDependenciesKeys, splitID[1])
	}

	for _, id := range dedupedIncludesOccurrencesIDs {
		splitID := strings.Split(id, "/")
		includedOccurrencesKeys = append(includedOccurrencesKeys, splitID[1])
	}

	values["includedSoftware"] = dedupedIncludedSoftwareIDs
	values["includedDependencies"] = dedupedIncludedDependenciesIDs
	values["includesOccurrences"] = dedupedIncludesOccurrencesIDs
	values["includedSoftwarePkgKeys"] = includedSoftwarePkgKeys
	values["includedSoftwareArtKeys"] = includedSoftwareArtKeys
	values["includedDependencyKeys"] = includedDependenciesKeys
	values["includesOccurrenceKeys"] = includedOccurrencesKeys
	values["uri"] = hasSbom.URI
	values["algorithm"] = strings.ToLower(hasSbom.Algorithm)
	values["digest"] = strings.ToLower(hasSbom.Digest)
	values["downloadLocation"] = hasSbom.DownloadLocation
	values["origin"] = hasSbom.Origin
	values["collector"] = hasSbom.Collector
	values[knownSince] = hasSbom.KnownSince.UTC()

	return values
}

func (c *arangoClient) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]string, error) {
	var cursor driver.Cursor
	var err error
	if len(subjects.Packages) > 0 {
		var listOfValues []map[string]any

		for i := range subjects.Packages {
			listOfValues = append(listOfValues, getHasSBOMQueryValues(subjects.Packages[i].PackageInput, nil, hasSBOMs[i], includes[i]))
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
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == doc.pkgVersionGuacKey
			RETURN {
			  'version_id': pVersion._id,
			  'version_key': pVersion._key
			}
		)
		  
		 LET hasSBOM = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, includedSoftware:doc.includedSoftware, includedDependencies:doc.includedDependencies, includesOccurrences:doc.includesOccurrences, uri:doc.uri, algorithm:doc.algorithm, digest:doc.digest, downloadLocation:doc.downloadLocation, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				  INSERT {  packageID:firstPkg.version_id, includedSoftware:doc.includedSoftware, includedDependencies:doc.includedDependencies, includesOccurrences:doc.includesOccurrences, uri:doc.uri, algorithm:doc.algorithm, digest:doc.digest, downloadLocation:doc.downloadLocation, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				  UPDATE {} IN hasSBOMs
				  RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				  }
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMPkgEdges", firstPkg.version_key, hasSBOM._key), _from: firstPkg.version_id, _to: hasSBOM._id } INTO hasSBOMPkgEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedSoftwarePkgEdgesCollection = (FOR pkgData IN doc.includedSoftwarePkgKeys
			INSERT { _key: CONCAT("hasSBOMIncludedSoftwarePkgEdges", hasSBOM._key, pkgData), _from: hasSBOM._id, _to: CONCAT("pkgVersions/", pkgData) } INTO hasSBOMIncludedSoftwarePkgEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedSoftwareArtEdgesCollection = (FOR artData IN doc.includedSoftwareArtKeys
			INSERT { _key: CONCAT("hasSBOMIncludedSoftwareArtEdges", hasSBOM._key, artData), _from: hasSBOM._id, _to: CONCAT("artifacts/", artData) } INTO hasSBOMIncludedSoftwareArtEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedDependencyEdgesCollection = (FOR inDepData IN doc.includedDependencyKeys
			INSERT { _key: CONCAT("hasSBOMIncludedDependencyEdges", hasSBOM._key, inDepData), _from: hasSBOM._id, _to: CONCAT("isDependencies/", inDepData) } INTO hasSBOMIncludedDependencyEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedOccurrenceEdgesCollection = (FOR inOccurData IN doc.includesOccurrenceKeys
			INSERT { _key: CONCAT("hasSBOMIncludedOccurrenceEdges", hasSBOM._key, inOccurData), _from: hasSBOM._id, _to: CONCAT("isOccurrences/", inOccurData) } INTO hasSBOMIncludedOccurrenceEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
		  RETURN { 'hasSBOM_id': hasSBOM._id }`

		sb.WriteString(query)

		cursor, err = executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestHasSBOMs - package")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest package hasSBOMs: %w", err)
		}
		defer cursor.Close()
	} else if len(subjects.Artifacts) > 0 {

		var listOfValues []map[string]any

		for i := range subjects.Artifacts {
			listOfValues = append(listOfValues, getHasSBOMQueryValues(nil, subjects.Artifacts[i].ArtifactInput, hasSBOMs[i], includes[i]))
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
		  
		LET hasSBOM = FIRST(
			UPSERT { artifactID:artifact._id, includedSoftware:doc.includedSoftware, includedDependencies:doc.includedDependencies, includesOccurrences:doc.includesOccurrences, uri:doc.uri, algorithm:doc.algorithm, digest:doc.digest, downloadLocation:doc.downloadLocation, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				INSERT { artifactID:artifact._id, includedSoftware:doc.includedSoftware, includedDependencies:doc.includedDependencies, includesOccurrences:doc.includesOccurrences, uri:doc.uri, algorithm:doc.algorithm, digest:doc.digest, downloadLocation:doc.downloadLocation, collector:doc.collector, origin:doc.origin, knownSince:doc.knownSince } 
				UPDATE {} IN hasSBOMs
				RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				}
		)
		
		LET edgeCollection = (
		  INSERT {  _key: CONCAT("hasSBOMArtEdges", artifact._key, hasSBOM._key), _from: artifact._id, _to: hasSBOM._id } INTO hasSBOMArtEdges OPTIONS { overwriteMode: "ignore" }
		)

		LET hasSBOMIncludedSoftwarePkgEdgesCollection = (FOR pkgData IN doc.includedSoftwarePkgKeys
			INSERT { _key: CONCAT("hasSBOMIncludedSoftwarePkgEdges", hasSBOM._key, pkgData), _from: hasSBOM._id, _to: CONCAT("pkgVersions/", pkgData) } INTO hasSBOMIncludedSoftwarePkgEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedSoftwareArtEdgesCollection = (FOR artData IN doc.includedSoftwareArtKeys
			INSERT { _key: CONCAT("hasSBOMIncludedSoftwareArtEdges", hasSBOM._key, artData), _from: hasSBOM._id, _to: CONCAT("artifacts/", artData) } INTO hasSBOMIncludedSoftwareArtEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedDependencyEdgesCollection = (FOR inDepData IN doc.includedDependencyKeys
			INSERT { _key: CONCAT("hasSBOMIncludedDependencyEdges", hasSBOM._key, inDepData), _from: hasSBOM._id, _to: CONCAT("isDependencies/", inDepData) } INTO hasSBOMIncludedDependencyEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedOccurrenceEdgesCollection = (FOR inOccurData IN doc.includesOccurrenceKeys
			INSERT { _key: CONCAT("hasSBOMIncludedOccurrenceEdges", hasSBOM._key, inOccurData), _from: hasSBOM._id, _to: CONCAT("isOccurrences/", inOccurData) } INTO hasSBOMIncludedOccurrenceEdges OPTIONS { overwriteMode: "ignore" }
		  )
		
		RETURN { 'hasSBOM_id': hasSBOM._id }`

		sb.WriteString(query)

		cursor, err = executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestHasSBOMs - artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to ingest artifact hasSBOM: %w", err)
		}
		defer cursor.Close()
	} else {
		return nil, fmt.Errorf("packages or artifacts not specified for IngestHasSBOMs")
	}

	hasSBOMList, err := c.getHasSBOMFromCursor(ctx, cursor, nil, true)
	if err != nil {
		return nil, fmt.Errorf("failed to get hasSBOMs from arango cursor: %w", err)
	}

	var hasSbomIDList []string
	for _, ingestHasSbom := range hasSBOMList {
		hasSbomIDList = append(hasSbomIDList, ingestHasSbom.ID)
	}

	return hasSbomIDList, nil
}

func (c *arangoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (string, error) {
	var cursor driver.Cursor
	var err error
	if subject.Artifact != nil {
		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
		  
		  LET hasSBOM = FIRST(
			  UPSERT { artifactID:artifact._id, includedSoftware:@includedSoftware, includedDependencies:@includedDependencies, includesOccurrences:@includesOccurrences, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  INSERT { artifactID:artifact._id, includedSoftware:@includedSoftware, includedDependencies:@includedDependencies, includesOccurrences:@includesOccurrences, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  UPDATE {} IN hasSBOMs
				  RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				  }
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMArtEdges", artifact._key, hasSBOM._key), _from: artifact._id, _to: hasSBOM._id } INTO hasSBOMArtEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedSoftwarePkgEdgesCollection = (FOR pkgData IN @includedSoftwarePkgKeys
			INSERT { _key: CONCAT("hasSBOMIncludedSoftwarePkgEdges", hasSBOM._key, pkgData), _from: hasSBOM._id, _to: CONCAT("pkgVersions/", pkgData) } INTO hasSBOMIncludedSoftwarePkgEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedSoftwareArtEdgesCollection = (FOR artData IN @includedSoftwareArtKeys
			INSERT { _key: CONCAT("hasSBOMIncludedSoftwareArtEdges", hasSBOM._key, artData), _from: hasSBOM._id, _to: CONCAT("artifacts/", artData) } INTO hasSBOMIncludedSoftwareArtEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedDependencyEdgesCollection = (FOR inDepData IN @includedDependencyKeys
			INSERT { _key: CONCAT("hasSBOMIncludedDependencyEdges", hasSBOM._key, inDepData), _from: hasSBOM._id, _to: CONCAT("isDependencies/", inDepData) } INTO hasSBOMIncludedDependencyEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedOccurrenceEdgesCollection = (FOR inOccurData IN @includesOccurrenceKeys
			INSERT { _key: CONCAT("hasSBOMIncludedOccurrenceEdges", hasSBOM._key, inOccurData), _from: hasSBOM._id, _to: CONCAT("isOccurrences/", inOccurData) } INTO hasSBOMIncludedOccurrenceEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
		  RETURN { 'hasSBOM_id': hasSBOM._id }`

		cursor, err = executeQueryWithRetry(ctx, c.db, query, getHasSBOMQueryValues(nil, subject.Artifact.ArtifactInput, &hasSbom, &includes), "IngestHasSbom - Artifact")
		if err != nil {
			return "", fmt.Errorf("failed to ingest hasSBOM: %w", err)
		}
		defer cursor.Close()
		hasSBOMList, err := c.getHasSBOMFromCursor(ctx, cursor, nil, true)
		if err != nil {
			return "", fmt.Errorf("failed to get hasSBOM from arango cursor: %w", err)
		}

		if len(hasSBOMList) == 1 {
			return hasSBOMList[0].ID, nil
		} else {
			return "", fmt.Errorf("number of hasSBOM ingested is greater than one")
		}
	} else {
		query := `
		LET firstPkg = FIRST(
			FOR pVersion in pkgVersions
			  FILTER pVersion.guacKey == @pkgVersionGuacKey
			  RETURN {
				'version_id': pVersion._id,
				'version_key': pVersion._key
			  }
		)
		  
		LET hasSBOM = FIRST(
			  UPSERT {  packageID:firstPkg.version_id, includedSoftware:@includedSoftware, includedDependencies:@includedDependencies, includesOccurrences:@includesOccurrences, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  INSERT {  packageID:firstPkg.version_id, includedSoftware:@includedSoftware, includedDependencies:@includedDependencies, includesOccurrences:@includesOccurrences, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, collector:@collector, origin:@origin, knownSince:@knownSince } 
				  UPDATE {} IN hasSBOMs
				  RETURN {
					'_id': NEW._id,
					'_key': NEW._key
				  }
		)
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMPkgEdges", firstPkg.version_key, hasSBOM._key), _from: firstPkg.version_id, _to: hasSBOM._id } INTO hasSBOMPkgEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedSoftwarePkgEdgesCollection = (FOR pkgData IN @includedSoftwarePkgKeys
			INSERT { _key: CONCAT("hasSBOMIncludedSoftwarePkgEdges", hasSBOM._key, pkgData), _from: hasSBOM._id, _to: CONCAT("pkgVersions/", pkgData) } INTO hasSBOMIncludedSoftwarePkgEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedSoftwareArtEdgesCollection = (FOR artData IN @includedSoftwareArtKeys
			INSERT { _key: CONCAT("hasSBOMIncludedSoftwareArtEdges", hasSBOM._key, artData), _from: hasSBOM._id, _to: CONCAT("artifacts/", artData) } INTO hasSBOMIncludedSoftwareArtEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedDependencyEdgesCollection = (FOR inDepData IN @includedDependencyKeys
			INSERT { _key: CONCAT("hasSBOMIncludedDependencyEdges", hasSBOM._key, inDepData), _from: hasSBOM._id, _to: CONCAT("isDependencies/", inDepData) } INTO hasSBOMIncludedDependencyEdges OPTIONS { overwriteMode: "ignore" }
		  )

		  LET hasSBOMIncludedOccurrenceEdgesCollection = (FOR inOccurData IN @includesOccurrenceKeys
			INSERT { _key: CONCAT("hasSBOMIncludedOccurrenceEdges", hasSBOM._key, inOccurData), _from: hasSBOM._id, _to: CONCAT("isOccurrences/", inOccurData) } INTO hasSBOMIncludedOccurrenceEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
		  RETURN { 'hasSBOM_id': hasSBOM._id }`

		cursor, err = executeQueryWithRetry(ctx, c.db, query, getHasSBOMQueryValues(subject.Package.PackageInput, nil, &hasSbom, &includes), "IngestHasSbom - Package")
		if err != nil {
			return "", fmt.Errorf("failed to create ingest hasSBOM: %w", err)
		}
		defer cursor.Close()

		hasSBOMList, err := c.getHasSBOMFromCursor(ctx, cursor, nil, true)
		if err != nil {
			return "", fmt.Errorf("failed to get hasSBOM from arango cursor: %w", err)
		}

		if len(hasSBOMList) == 1 {
			return hasSBOMList[0].ID, nil
		} else {
			return "", fmt.Errorf("number of hasSBOM ingested is greater than one")
		}
	}
}

func (c *arangoClient) getHasSBOMFromCursor(ctx context.Context, cursor driver.Cursor, filter *model.HasSBOMSpec, ingestion bool) ([]*model.HasSbom, error) {

	type collectedData struct {
		PkgVersion           *dbPkgVersion   `json:"pkgVersion"`
		Artifact             *model.Artifact `json:"artifact"`
		HasSBOMId            string          `json:"hasSBOM_id"`
		Uri                  string          `json:"uri"`
		Algorithm            string          `json:"algorithm"`
		Digest               string          `json:"digest"`
		DownloadLocation     string          `json:"downloadLocation"`
		Collector            string          `json:"collector"`
		Origin               string          `json:"origin"`
		KnownSince           time.Time       `json:"knownSince"`
		IncludedSoftware     []string        `json:"includedSoftware"`
		IncludedDependencies []string        `json:"includedDependencies"`
		IncludesOccurrences  []string        `json:"includesOccurrences"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to package hasSBOM from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var hasSBOMList []*model.HasSbom
	for _, createdValue := range createdValues {
		var hasSBOM *model.HasSbom
		if !ingestion {
			var pkg *model.Package = nil
			if createdValue.PkgVersion != nil {
				pkg = generateModelPackage(createdValue.PkgVersion.TypeID, createdValue.PkgVersion.PkgType, createdValue.PkgVersion.NamespaceID, createdValue.PkgVersion.Namespace, createdValue.PkgVersion.NameID,
					createdValue.PkgVersion.Name, createdValue.PkgVersion.VersionID, createdValue.PkgVersion.Version, createdValue.PkgVersion.Subpath, createdValue.PkgVersion.QualifierList)
			}

			var collectedSoftware []model.PackageOrArtifact
			collectedPkgs, collectedArts, collectedDeps, collectedOccurs, err := getHasSBOMIncludes(c, ctx, createdValue.IncludedSoftware, createdValue.IncludedDependencies, createdValue.IncludesOccurrences)
			if err != nil {
				return nil, fmt.Errorf("failed to getHasSBOMIncludes with error: %w", err)
			}

			for _, cPkg := range collectedPkgs {
				collectedSoftware = append(collectedSoftware, cPkg)
			}

			for _, cArt := range collectedArts {
				collectedSoftware = append(collectedSoftware, cArt)
			}

			matchingSoftware, matchingDeps, matchingOccur := checkMatchingIncludes(ctx, filter, collectedPkgs, collectedArts,
				collectedDeps, collectedOccurs)

			if !matchingSoftware || !matchingDeps || !matchingOccur {
				continue
			}
			hasSBOM = &model.HasSbom{
				ID:                   createdValue.HasSBOMId,
				URI:                  createdValue.Uri,
				Algorithm:            createdValue.Algorithm,
				Digest:               createdValue.Digest,
				DownloadLocation:     createdValue.DownloadLocation,
				Origin:               createdValue.Origin,
				Collector:            createdValue.Collector,
				KnownSince:           createdValue.KnownSince,
				IncludedSoftware:     collectedSoftware,
				IncludedDependencies: collectedDeps,
				IncludedOccurrences:  collectedOccurs,
			}
			if pkg != nil {
				hasSBOM.Subject = pkg
			} else if createdValue.Artifact != nil {
				hasSBOM.Subject = createdValue.Artifact
			} else {
				return nil, fmt.Errorf("failed to get subject from cursor for hasSBOM")
			}
		} else {
			hasSBOM = &model.HasSbom{ID: createdValue.HasSBOMId}
		}
		hasSBOMList = append(hasSBOMList, hasSBOM)
	}
	return hasSBOMList, nil
}

func getHasSBOMIncludes(c *arangoClient, ctx context.Context, includedSoftware []string, includedDependencies []string, includedOccurrences []string) ([]*model.Package, []*model.Artifact, []*model.IsDependency, []*model.IsOccurrence, error) {
	var wg sync.WaitGroup

	errChan := make(chan error)
	pkgChan := make(chan *model.Package, len(includedSoftware))
	artChan := make(chan *model.Artifact, len(includedSoftware))
	isDepChan := make(chan *model.IsDependency, len(includedDependencies))
	isOccurChan := make(chan *model.IsOccurrence, len(includedOccurrences))

	var collectedDeps []*model.IsDependency
	var collectedOccurs []*model.IsOccurrence

	var collectedPkgs []*model.Package
	var collectedArts []*model.Artifact

	for _, id := range includedSoftware {
		idSplit := strings.Split(id, "/")
		if len(idSplit) != 2 {
			return nil, nil, nil, nil, fmt.Errorf("invalid ID: %s", id)
		}
		switch idSplit[0] {
		case pkgVersionsStr:
			wg.Add(1)
			go concurrentBuildPackage(c, ctx, id, pkgChan, errChan, &wg)
		case artifactsStr:
			wg.Add(1)
			go concurrentBuildArtifact(c, ctx, id, artChan, errChan, &wg)
		default:
			return nil, nil, nil, nil, fmt.Errorf("expected Package or Artifact, found %s", idSplit[0])
		}
	}

	for _, id := range includedDependencies {
		wg.Add(1)
		go concurrentBuildIsDep(c, ctx, id, isDepChan, errChan, &wg)
	}

	for _, id := range includedOccurrences {
		wg.Add(1)
		go concurrentBuildIsOccur(c, ctx, id, isOccurChan, errChan, &wg)
	}

	// Close the result channel once all goroutines are done
	go func() {
		wg.Wait()
		close(pkgChan)
		close(artChan)
		close(isDepChan)
		close(isOccurChan)
		close(errChan)
	}()

	// check if any error and return
	for err := range errChan {
		return nil, nil, nil, nil, err
	}

	// Collect results from the pkgChan
	for cPkg := range pkgChan {
		collectedPkgs = append(collectedPkgs, cPkg)
	}

	// Collect results from the artChan
	for cArt := range artChan {
		collectedArts = append(collectedArts, cArt)
	}

	// Collect results from the isDepChan
	for cIsDep := range isDepChan {
		collectedDeps = append(collectedDeps, cIsDep)
	}

	// Collect results from the isOccurChan
	for cIsOccur := range isOccurChan {
		collectedOccurs = append(collectedOccurs, cIsOccur)
	}
	return collectedPkgs, collectedArts, collectedDeps, collectedOccurs, nil
}

func concurrentBuildPackage(c *arangoClient, ctx context.Context, pkgID string, resultPkgChan chan<- *model.Package, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	if pkg, err := c.buildPackageResponseFromID(ctx, pkgID, nil); err != nil {
		errChan <- fmt.Errorf("failed to get package from ID: %w", err)
	} else {
		// Send the results to the resultChan
		resultPkgChan <- pkg
	}
}

func concurrentBuildArtifact(c *arangoClient, ctx context.Context, artID string, resultArtChan chan<- *model.Artifact, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	if art, err := c.buildArtifactResponseByID(ctx, artID, nil); err != nil {
		errChan <- fmt.Errorf("failed to get artifact from ID: %w", err)
	} else {
		// Send the results to the resultChan
		resultArtChan <- art
	}
}

func concurrentBuildIsDep(c *arangoClient, ctx context.Context, isDepID string, resultDepChan chan<- *model.IsDependency, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	if isDep, err := c.buildIsDependencyByID(ctx, isDepID, nil); err != nil {
		errChan <- fmt.Errorf("failed to get isDependency from ID: %w", err)
	} else {
		// Send the results to the resultChan
		resultDepChan <- isDep
	}
}

func concurrentBuildIsOccur(c *arangoClient, ctx context.Context, isOccurID string, resultOccurChan chan<- *model.IsOccurrence, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	if isOccur, err := c.buildIsOccurrenceByID(ctx, isOccurID, nil); err != nil {
		errChan <- fmt.Errorf("failed to get isOccurrence from ID: %w", err)
	} else {
		// Send the results to the resultChan
		resultOccurChan <- isOccur
	}
}

func checkMatchingIncludes(ctx context.Context, filter *model.HasSBOMSpec, collectedPkgs []*model.Package, collectedArts []*model.Artifact,
	collectedDeps []*model.IsDependency, collectedOccurs []*model.IsOccurrence) (bool, bool, bool) {

	matchingSoftware := true
	if filter.IncludedSoftware != nil {
		pkgFilters, artFilters := helper.GetPackageAndArtifactFilters(filter.IncludedSoftware)
		matchingSoftware = matchPackages(ctx, pkgFilters, collectedPkgs)
		if matchingSoftware {
			for _, artFilter := range artFilters {
				if found := containsMatchingArtifact(collectedArts, artFilter.ID, artFilter.Algorithm, artFilter.Digest); !found {
					matchingSoftware = false
					break
				}
			}
		}
	}
	matchingDeps := true
	if filter.IncludedDependencies != nil {
		matchingDeps = matchDependencies(ctx, filter.IncludedDependencies, collectedDeps)
	}
	matchingOccur := true
	if filter.IncludedOccurrences != nil {
		matchingDeps = matchOccurrences(ctx, filter.IncludedOccurrences, collectedOccurs)
	}
	return matchingSoftware, matchingDeps, matchingOccur
}

func (c *arangoClient) buildHasSbomByID(ctx context.Context, id string, filter *model.HasSBOMSpec) (*model.HasSbom, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == hasSBOMsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.HasSBOMSpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryHasSbomNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for hasSBOM query: %s", id)
	}
}

func (c *arangoClient) queryHasSbomNodeByID(ctx context.Context, filter *model.HasSBOMSpec) (*model.HasSbom, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
	setHasSBOMMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN hasSBOM`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryHasSbomNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for hasSBOM: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbHasSbom struct {
		HasSbomID            string   `json:"_id"`
		PackageID            *string  `json:"packageID"`
		ArtifactID           *string  `json:"artifactID"`
		Uri                  string   `json:"uri"`
		Algorithm            string   `json:"algorithm"`
		Digest               string   `json:"digest"`
		DownloadLocation     string   `json:"downloadLocation"`
		Collector            string   `json:"collector"`
		Origin               string   `json:"origin"`
		IncludedSoftware     []string `json:"includedSoftware"`
		IncludedDependencies []string `json:"includedDependencies"`
		IncludesOccurrences  []string `json:"includesOccurrences"`
	}

	var collectedValues []dbHasSbom
	for {
		var doc dbHasSbom
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to hasSBOM from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of hasSBOM nodes found for ID: %s is greater than one", *filter.ID)
	}

	var collectedSoftware []model.PackageOrArtifact
	collectedPkgs, collectedArts, collectedDeps, collectedOccurs, err := getHasSBOMIncludes(c, ctx, collectedValues[0].IncludedSoftware, collectedValues[0].IncludedDependencies, collectedValues[0].IncludesOccurrences)
	if err != nil {
		return nil, fmt.Errorf("failed to getHasSBOMIncludes with error: %w", err)
	}

	for _, cPkg := range collectedPkgs {
		collectedSoftware = append(collectedSoftware, cPkg)
	}

	for _, cArt := range collectedArts {
		collectedSoftware = append(collectedSoftware, cArt)
	}

	matchingSoftware, matchingDeps, matchingOccur := checkMatchingIncludes(ctx, filter, collectedPkgs, collectedArts,
		collectedDeps, collectedOccurs)

	if !matchingSoftware && !matchingDeps && !matchingOccur {
		return nil, fmt.Errorf("includes failed to match specified filter")
	}

	hasSBOM := &model.HasSbom{
		ID:                   collectedValues[0].HasSbomID,
		URI:                  collectedValues[0].Uri,
		Algorithm:            collectedValues[0].Algorithm,
		Digest:               collectedValues[0].Digest,
		DownloadLocation:     collectedValues[0].DownloadLocation,
		Origin:               collectedValues[0].Origin,
		Collector:            collectedValues[0].Collector,
		IncludedSoftware:     collectedSoftware,
		IncludedDependencies: collectedDeps,
		IncludedOccurrences:  collectedOccurs,
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
		hasSBOM.Subject = builtPackage
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
		hasSBOM.Subject = builtArtifact
	} else {
		return nil, fmt.Errorf("failed to get subject from hasSBOM")
	}
	return hasSBOM, nil
}

func (c *arangoClient) hasSbomNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 1)

	if allowedEdges[model.EdgeHasSbomPackage] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, &model.HasSBOMSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSBOM.packageID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasSbomNeighbors - package")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeHasSbomArtifact] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, &model.HasSBOMSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSBOM.artifactID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasSbomNeighbors - artifact")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}

	if allowedEdges[model.EdgeHasSbomIncludedSoftware] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, &model.HasSBOMSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { includedSoftware:  hasSBOM.includedSoftware }")

		cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "hasSbomNeighbors - includedSoftware")
		if err != nil {
			return nil, fmt.Errorf("failed to query for Neighbors for %s with error: %w", "hasSbomNeighbors", err)
		}
		defer cursor.Close()

		type dbIncludedSoftware struct {
			IncludedSoftware []string `json:"includedSoftware"`
		}

		var collectedIncludedSoftwares []dbIncludedSoftware
		for {
			var doc dbIncludedSoftware
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					break
				} else {
					return nil, fmt.Errorf("failed to get neighbor id from cursor for %s with error: %w", "hasSbomNeighbors", err)
				}
			} else {
				collectedIncludedSoftwares = append(collectedIncludedSoftwares, doc)
			}
		}

		var foundIDs []string
		for _, inSoftware := range collectedIncludedSoftwares {
			if inSoftware.IncludedSoftware != nil {
				foundIDs = append(foundIDs, inSoftware.IncludedSoftware...)
			}
		}

		out = append(out, foundIDs...)
	}

	if allowedEdges[model.EdgeHasSbomIncludedDependencies] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, &model.HasSBOMSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { includedDependencies:  hasSBOM.includedDependencies }")

		cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "hasSbomNeighbors - includedDependencies")
		if err != nil {
			return nil, fmt.Errorf("failed to query for Neighbors for %s with error: %w", "hasSbomNeighbors", err)
		}
		defer cursor.Close()

		type dbIncludedDependencies struct {
			IncludedDependencies []string `json:"includedDependencies"`
		}

		var collectedIncludedDependencies []dbIncludedDependencies
		for {
			var doc dbIncludedDependencies
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					break
				} else {
					return nil, fmt.Errorf("failed to get neighbor id from cursor for %s with error: %w", "hasSbomNeighbors", err)
				}
			} else {
				collectedIncludedDependencies = append(collectedIncludedDependencies, doc)
			}
		}

		var foundIDs []string
		for _, inDep := range collectedIncludedDependencies {
			if inDep.IncludedDependencies != nil {
				foundIDs = append(foundIDs, inDep.IncludedDependencies...)
			}
		}

		out = append(out, foundIDs...)
	}

	if allowedEdges[model.EdgeHasSbomIncludedOccurrences] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSBOMsStr, "hasSBOM")
		setHasSBOMMatchValues(arangoQueryBuilder, &model.HasSBOMSpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { includesOccurrences:  hasSBOM.includesOccurrences }")

		cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "hasSbomNeighbors - includesOccurrences")
		if err != nil {
			return nil, fmt.Errorf("failed to query for Neighbors for %s with error: %w", "hasSbomNeighbors", err)
		}
		defer cursor.Close()

		type dbIncludesOccurrences struct {
			IncludesOccurrences []string `json:"includesOccurrences"`
		}

		var collectedIncludesOccurrences []dbIncludesOccurrences
		for {
			var doc dbIncludesOccurrences
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					break
				} else {
					return nil, fmt.Errorf("failed to get neighbor id from cursor for %s with error: %w", "hasSbomNeighbors", err)
				}
			} else {
				collectedIncludesOccurrences = append(collectedIncludesOccurrences, doc)
			}
		}

		var foundIDs []string
		for _, inOccur := range collectedIncludesOccurrences {
			if inOccur.IncludesOccurrences != nil {
				foundIDs = append(foundIDs, inOccur.IncludesOccurrences...)
			}
		}

		out = append(out, foundIDs...)
	}

	return out, nil
}
