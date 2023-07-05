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

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func (c *arangoClient) HasSBOM(ctx context.Context, hasSBOMSpec *model.HasSBOMSpec) ([]*model.HasSbom, error) {
	panic(fmt.Errorf("not implemented: HasSBOM - HasSBOM"))
}

func (c *arangoClient) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec) (*model.HasSbom, error) {
	values := map[string]any{}

	// TODO(pxp928): currently only supporting package for testing. Will add in source once testing is completed
	if subject.Artifact != nil {
		values["art_algorithm"] = strings.ToLower(subject.Artifact.Algorithm)
		values["art_digest"] = strings.ToLower(subject.Artifact.Digest)
		values["uri"] = hasSbom.URI
		values["algorithm"] = hasSbom.Algorithm
		values["digest"] = hasSbom.Digest
		values["downloadLocation"] = hasSbom.DownloadLocation
		values["annotations"] = hasSbom.Annotations
		values["origin"] = hasSbom.Origin
		values["collector"] = hasSbom.Collector

		// To ensure consistency, always sort the qualifiers by key
		annotationsMap := map[string]string{}
		keys := []string{}
		for _, kv := range hasSbom.Annotations {
			annotationsMap[kv.Key] = kv.Value
			keys = append(keys, kv.Key)
		}
		sort.Strings(keys)
		annotations := []string{}
		for _, k := range keys {
			annotations = append(annotations, k, annotationsMap[k])
		}
		values["annotations"] = annotations

		query := `LET artifact = FIRST(FOR art IN artifacts FILTER art.algorithm == @art_algorithm FILTER art.digest == @art_digest RETURN art)
		  
		  LET hasSBOM = FIRST(
			  UPSERT { artifactID:artifact._id, uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, annotations:@annotations, collector:@collector, origin:@origin } 
				  INSERT { uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, annotations:@annotations, collector:@collector, origin:@origin } 
				  UPDATE {} IN hasSBOMs
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMEdges", artifact._key, hasSBOM._key), _from: artifact._id, _to: hasSBOM._id, label : "hasSBOM" } INTO hasSBOMEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
		  RETURN {
			  "artAlgo": artifact.algorithm,
			  "artDigest": artifact.digest,
			  "uri": hasSBOM.uri,
			  "algorithm": hasSBOM.algorithm,
			  "digest": hasSBOM.digest,
			  "downloadLocation": hasSBOM.downloadLocation,
			  "annotations": hasSBOM.annotations,
			  "collector": hasSBOM.collector,
			  "origin": hasSBOM.origin
			  
		  }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestHasSbom - Artifact")
		if err != nil {
			return nil, fmt.Errorf("failed to create vertex documents: %w", err)
		}
		defer cursor.Close()

		type collectedData struct {
			ArtAlgo          string        `json:"artAlgo"`
			ArtDigest        string        `json:"artDigest"`
			Uri              string        `json:"uri"`
			Algorithm        string        `json:"algorithm"`
			Digest           string        `json:"digest"`
			DownloadLocation string        `json:"downloadLocation"`
			Annotations      []interface{} `json:"annotations"`
			Collector        string        `json:"collector"`
			Origin           string        `json:"origin"`
		}

		var createdValues []collectedData
		for {
			var doc collectedData
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					break
				} else {
					return nil, fmt.Errorf("failed to ingest hasSBOM: %w", err)
				}
			} else {
				createdValues = append(createdValues, doc)
			}
		}
		if len(createdValues) == 1 {

			algorithm := createdValues[0].ArtAlgo
			digest := createdValues[0].ArtDigest
			artifact := generateModelArtifact(algorithm, digest)

			annotations, err := getAnnotations(createdValues[0].Annotations)
			if err != nil {
				return nil, fmt.Errorf("failed to get hasSBOM annotations with error: %w", err)
			}

			isOccurrence := &model.HasSbom{
				Subject:          artifact,
				URI:              createdValues[0].Uri,
				Algorithm:        createdValues[0].Algorithm,
				Digest:           createdValues[0].Digest,
				DownloadLocation: createdValues[0].DownloadLocation,
				Annotations:      annotations,
				Origin:           createdValues[0].Collector,
				Collector:        createdValues[0].Origin,
			}

			return isOccurrence, nil
		} else {
			return nil, fmt.Errorf("number of hashEqual ingested is too great")
		}
	} else {
		// add guac keys
		pkgId := guacPkgId(*subject.Package)
		values["pkgVersionGuacKey"] = pkgId.VersionId

		values["uri"] = hasSbom.URI
		values["algorithm"] = hasSbom.Algorithm
		values["digest"] = hasSbom.Digest
		values["downloadLocation"] = hasSbom.DownloadLocation
		values["annotations"] = hasSbom.Annotations
		values["origin"] = hasSbom.Origin
		values["collector"] = hasSbom.Collector

		// To ensure consistency, always sort the qualifiers by key
		annotationsMap := map[string]string{}
		annotationsKeys := []string{}
		for _, kv := range hasSbom.Annotations {
			annotationsMap[kv.Key] = kv.Value
			annotationsKeys = append(annotationsKeys, kv.Key)
		}
		sort.Strings(annotationsKeys)
		annotations := []string{}
		for _, k := range annotationsKeys {
			annotations = append(annotations, k, annotationsMap[k])
		}
		values["annotations"] = annotations

		query := `
		LET firstPkg = FIRST(
			FOR pVersion in PkgVersion
			  FILTER pVersion.guacKey == @pkgVersionGuacKey
			FOR pName in PkgName
			  FILTER pName._id == pVersion._parent
			FOR pNs in PkgNamespace
			  FILTER pNs._id == pName._parent
			FOR pType in PkgType
			  FILTER pType._id == pNs._parent
	
			RETURN {
			  'type': pType.type,
			  'namespace': pNs.namespace,
			  'name': pName.name,
			  'version': pVersion.version,
			  'subpath': pVersion.subpath,
			  'qualifier_list': pVersion.qualifier_list,
			  'versionDoc': pVersion
			}
		)
		  
		  LET hasSBOM = FIRST(
			  UPSERT { uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, annotations:@annotations, collector:@collector, origin:@origin } 
				  INSERT { uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, annotations:@annotations, collector:@collector, origin:@origin } 
				  UPDATE {} IN hasSBOMs
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (
			INSERT {  _key: CONCAT("hasSBOMEdges", firstPkg.versionDoc._key, hasSBOM._key), _from: firstPkg.versionDoc._id, _to: hasSBOM._id, label : "hasSBOM" } INTO hasSBOMEdges OPTIONS { overwriteMode: "ignore" }
		  )
		  
		  RETURN {
			  "firstPkgType": firstPkg.type,
			  "firstPkgNamespace": firstPkg.namespace,
			  "firstPkgName": firstPkg.name,
			  "firstPkgVersion": firstPkg.version,
			  "firstPkgSubpath": firstPkg.subpath,
			  "firstPkgQualifier_list": firstPkg.qualifier_list,
			  "uri": hasSBOM.uri,
			  "algorithm": hasSBOM.algorithm,
			  "digest": hasSBOM.digest,
			  "downloadLocation": hasSBOM.downloadLocation,
			  "annotations": hasSBOM.annotations,
			  "collector": hasSBOM.collector,
			  "origin": hasSBOM.origin  
		  }`

		cursor, err := executeQueryWithRetry(ctx, c.db, query, values, "IngestHasSbom - Package")
		if err != nil {
			return nil, fmt.Errorf("failed to create vertex documents: %w", err)
		}
		defer cursor.Close()

		type collectedData struct {
			FirstPkgType          string        `json:"firstPkgType"`
			FirstPkgNamespace     string        `json:"firstPkgNamespace"`
			FirstPkgName          string        `json:"firstPkgName"`
			FirstPkgVersion       string        `json:"firstPkgVersion"`
			FirstPkgSubpath       string        `json:"firstPkgSubpath"`
			FirstPkgQualifierList interface{}   `json:"firstPkgQualifier_list"`
			Uri                   string        `json:"uri"`
			Algorithm             string        `json:"algorithm"`
			Digest                string        `json:"digest"`
			DownloadLocation      string        `json:"downloadLocation"`
			Annotations           []interface{} `json:"annotations"`
			Collector             string        `json:"collector"`
			Origin                string        `json:"origin"`
		}

		var createdValues []collectedData
		for {
			var doc collectedData
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					break
				} else {
					return nil, fmt.Errorf("failed to ingest hasSBOM: %w", err)
				}
			} else {
				createdValues = append(createdValues, doc)
			}
		}
		if len(createdValues) == 1 {

			pkg, err := generateModelPackage(createdValues[0].FirstPkgType, createdValues[0].FirstPkgNamespace,
				createdValues[0].FirstPkgName, createdValues[0].FirstPkgVersion, createdValues[0].FirstPkgSubpath, createdValues[0].FirstPkgQualifierList)
			if err != nil {
				return nil, fmt.Errorf("failed to get model.package with err: %w", err)
			}
			annotations, err := getAnnotations(createdValues[0].Annotations)
			if err != nil {
				return nil, fmt.Errorf("failed to get hasSBOM annotations with error: %w", err)
			}

			isOccurrence := &model.HasSbom{
				Subject:          pkg,
				URI:              createdValues[0].Uri,
				Algorithm:        createdValues[0].Algorithm,
				Digest:           createdValues[0].Digest,
				DownloadLocation: createdValues[0].DownloadLocation,
				Annotations:      annotations,
				Origin:           createdValues[0].Collector,
				Collector:        createdValues[0].Origin,
			}

			return isOccurrence, nil
		} else {
			return nil, fmt.Errorf("number of hashEqual ingested is too great")
		}
	}
}

func getAnnotations(annotationList []interface{}) ([]*model.Annotation, error) {
	annotations := []*model.Annotation{}
	for i := range annotationList {
		if i%2 == 0 {
			key, ok := annotationList[i].(string)
			if !ok {
				return nil, fmt.Errorf("failed to assert string value for hasSBOM annotation's key")
			}
			value, ok := annotationList[i+1].(string)
			if !ok {
				return nil, fmt.Errorf("failed to assert string value for hasSBOM annotation's value")
			}
			qualifier := &model.Annotation{
				Key:   key,
				Value: value,
			}
			annotations = append(annotations, qualifier)
		}
	}
	return annotations, nil
}
