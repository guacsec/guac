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

// TODO: noe4j backend does not match the schema. This needs updating before use!
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
		  
		  LET edgeCollection = (FOR edgeData IN [
			  {from: artifact._id, to: hasSBOM._id, label: "hasSBOM"}]
		  
			UPSERT { _from: edgeData.from, _to: edgeData.to, label : edgeData.label }
			  INSERT { _from: edgeData.from, _to: edgeData.to, label : edgeData.label }
			  UPDATE {} IN hasSBOMEdges
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
					return nil, fmt.Errorf("failed to ingest artifact: %w", err)
				}
			} else {
				createdValues = append(createdValues, doc)
			}
		}
		if len(createdValues) == 1 {

			algorithm := createdValues[0].ArtAlgo
			digest := createdValues[0].ArtDigest
			artifact := generateModelArtifact(algorithm, digest)

			isOccurrence := &model.HasSbom{
				Subject:          artifact,
				URI:              createdValues[0].Uri,
				Algorithm:        createdValues[0].Algorithm,
				Digest:           createdValues[0].Digest,
				DownloadLocation: createdValues[0].DownloadLocation,
				Annotations:      getAnnotations(createdValues[0].Annotations),
				Origin:           createdValues[0].Collector,
				Collector:        createdValues[0].Origin,
			}

			return isOccurrence, nil
		} else {
			return nil, fmt.Errorf("number of hashEqual ingested is too great")
		}
	} else {
		values["pkgType"] = subject.Package.Type
		values["name"] = subject.Package.Name
		if subject.Package.Namespace != nil {
			values["namespace"] = *subject.Package.Namespace
		} else {
			values["namespace"] = ""
		}
		if subject.Package.Version != nil {
			values["version"] = *subject.Package.Version
		} else {
			values["version"] = ""
		}
		if subject.Package.Subpath != nil {
			values["subpath"] = *subject.Package.Subpath
		} else {
			values["subpath"] = ""
		}

		// To ensure consistency, always sort the qualifiers by key
		qualifiersMap := map[string]string{}
		keys := []string{}
		for _, kv := range subject.Package.Qualifiers {
			qualifiersMap[kv.Key] = kv.Value
			keys = append(keys, kv.Key)
		}
		sort.Strings(keys)
		qualifiers := []string{}
		for _, k := range keys {
			qualifiers = append(qualifiers, k, qualifiersMap[k])
		}
		values["qualifier"] = qualifiers

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

		query := `LET firstPkg = FIRST(
			FOR pkg IN Pkg
		      FILTER pkg.root == "pkg" && pkg.type == @pkgType && pkg.namespace == @namespace
				  FOR pkgHasName IN OUTBOUND pkg PkgHasName
						  FILTER pkgHasName.name == @name
					FOR pkgHasVersion IN OUTBOUND pkgHasName PkgHasVersion
							  FILTER pkgHasVersion.version == @version && pkgHasVersion.subpath == @subpath && pkgHasVersion.qualifier_list == @qualifier
					  RETURN {
						"type": pkg.type,
						"namespace": pkg.namespace,
						"name": pkgHasName.name,
						"version": pkgHasVersion.version,
						"subpath": pkgHasVersion.subpath,
						"qualifier_list": pkgHasVersion.qualifier_list,
						"versionDoc": pkgHasVersion
					  }
		  )
		  
		  LET hasSBOM = FIRST(
			  UPSERT { uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, annotations:@annotations, collector:@collector, origin:@origin } 
				  INSERT { uri:@uri, algorithm:@algorithm, digest:@digest, downloadLocation:@downloadLocation, annotations:@annotations, collector:@collector, origin:@origin } 
				  UPDATE {} IN hasSBOMs
				  RETURN NEW
		  )
		  
		  LET edgeCollection = (FOR edgeData IN [
			  {from: firstPkg.versionDoc._id, to: hasSBOM._id, label: "hasSBOM"}]
		  
			UPSERT { _from: edgeData.from, _to: edgeData.to, label : edgeData.label }
			  INSERT { _from: edgeData.from, _to: edgeData.to, label : edgeData.label }
			  UPDATE {} IN hasSBOMEdges
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
					return nil, fmt.Errorf("failed to ingest artifact: %w", err)
				}
			} else {
				createdValues = append(createdValues, doc)
			}
		}
		if len(createdValues) == 1 {

			pkg := generateModelPackage(createdValues[0].FirstPkgType, createdValues[0].FirstPkgNamespace,
				createdValues[0].FirstPkgName, createdValues[0].FirstPkgVersion, createdValues[0].FirstPkgSubpath, createdValues[0].FirstPkgQualifierList)

			isOccurrence := &model.HasSbom{
				Subject:          pkg,
				URI:              createdValues[0].Uri,
				Algorithm:        createdValues[0].Algorithm,
				Digest:           createdValues[0].Digest,
				DownloadLocation: createdValues[0].DownloadLocation,
				Annotations:      getAnnotations(createdValues[0].Annotations),
				Origin:           createdValues[0].Collector,
				Collector:        createdValues[0].Origin,
			}

			return isOccurrence, nil
		} else {
			return nil, fmt.Errorf("number of hashEqual ingested is too great")
		}
	}
}

func getAnnotations(annotationList []interface{}) []*model.Annotation {
	annotations := []*model.Annotation{}
	for i := range annotationList {
		if i%2 == 0 {
			qualifier := &model.Annotation{
				Key:   annotationList[i].(string),
				Value: annotationList[i+1].(string),
			}
			annotations = append(annotations, qualifier)
		}
	}
	return annotations
}
