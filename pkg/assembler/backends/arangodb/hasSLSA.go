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
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	buildTypeStr     string = "buildType"
	slsaPredicateStr string = "slsaPredicate"
	slsaVersionStr   string = "slsaVersion"
	startedOnStr     string = "startedOn"
	finishedOnStr    string = "finishedOn"
	builtFromStr     string = "builtFrom"
)

func (c *arangoClient) HasSlsa(ctx context.Context, hasSLSASpec *model.HasSLSASpec) ([]*model.HasSlsa, error) {
	panic(fmt.Errorf("not implemented: HasSlsa - HasSlsa"))
}

func getSLSAValues(subject model.ArtifactInputSpec, builtFrom []*model.Artifact, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) map[string]any {
	values := map[string]any{}

	values["algorithm"] = strings.ToLower(subject.Algorithm)
	values["digest"] = strings.ToLower(subject.Digest)

	values["uri"] = strings.ToLower(builtBy.URI)
	// To ensure consistency, always sort the checks by key
	predicateMap := map[string]string{}
	var keys []string
	for _, kv := range slsa.SlsaPredicate {
		predicateMap[kv.Key] = kv.Value
		keys = append(keys, kv.Key)
	}
	sort.Strings(keys)
	var predicate []string
	for _, k := range keys {
		predicate = append(predicate, k, predicateMap[k])
	}
	values[slsaPredicateStr] = predicate

	var builtFromIDList []string
	var builtFromKeyList []string

	for _, bf := range builtFrom {
		builtFromIDList = append(builtFromIDList, bf.ID)
		splitID := strings.Split(bf.ID, "/")
		builtFromKeyList = append(builtFromKeyList, splitID[0])
	}

	values[builtFromStr] = builtFromIDList
	values["buildFromKeyList"] = builtFromKeyList
	values[buildTypeStr] = slsa.BuildType
	values[slsaVersionStr] = slsa.SlsaVersion
	values[startedOnStr] = slsa.StartedOn.UTC()
	values[finishedOnStr] = slsa.FinishedOn.UTC()
	values[origin] = slsa.Origin
	values[collector] = slsa.Collector

	return values
}

func (c *arangoClient) IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	// ingest materials (builtFrom artifacts)
	artifacts, err := c.IngestArtifacts(ctx, builtFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest built from artifact with error: %w", err)
	}

	query := `
	LET subject = FIRST(FOR art IN artifacts FILTER art.algorithm == @algorithm FILTER art.digest == @digest RETURN art)
	LET builtBy = FIRST(FOR builder IN builders FILTER builder.uri == @uri RETURN builder)
	LET hasSLSA = FIRST(
		UPSERT { subjectID:subject._id, builtByID:builtBy._id, builtFrom:@builtFrom, buildType:@buildType, slsaPredicate:@slsaPredicate, slsaVersion:@slsaVersion, startedOn:@startedOn, finishedOn:@finishedOn, collector:@collector, origin:@origin } 
		INSERT { subjectID:subject._id, builtByID:builtBy._id, builtFrom:@builtFrom, buildType:@buildType, slsaPredicate:@slsaPredicate, slsaVersion:@slsaVersion, startedOn:@startedOn, finishedOn:@finishedOn, collector:@collector, origin:@origin } 
		UPDATE {} IN hasSLSAs
		RETURN NEW
	)

	LET buildFromCollection = (FOR bfData IN @buildFromKeyList
		INSERT { _key: CONCAT("hasSLSAEdges", hasSLSA._key, bfData), _from: hasSLSA._id, _to: CONCAT("artifacts/", bfData), label: "builtFrom"} INTO hasSLSAEdges OPTIONS { overwriteMode: "ignore" }
	)
	  
	LET edgeCollection = (FOR edgeData IN [
		{fromKey: hasSLSA._key, toKey: builtBy._key, from: hasSLSA._id, to: builtBy._id, label: "builtBy"}, 
		{fromKey: subject._key, toKey: hasSLSA._key, from: subject._id, to: hasSLSA._id, label: "subject"}]
	  
		INSERT { _key: CONCAT("hasSLSAEdges", edgeData.fromKey, edgeData.toKey), _from: edgeData.from, _to: edgeData.to, label : edgeData.label } INTO hasSLSAEdges OPTIONS { overwriteMode: "ignore" }
	)

	RETURN {
		'subject': {
			'id': subject._id,
			'algorithm': subject.algorithm,
			'digest': subject.digest
		},
		'builtBy': {
			'id': builtBy._id,
			'uri': builtBy.uri
		},
		'hasSLSA_id': hasSLSA._id,
		'buildType': hasSLSA.buildType,
		'slsaPredicate': hasSLSA.slsaPredicate,
		'slsaVersion': hasSLSA.slsaVersion,
		'startedOn': hasSLSA.startedOn,
		'finishedOn': hasSLSA.finishedOn,
		'collector': hasSLSA.collector,
		'origin': hasSLSA.origin
	}`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getSLSAValues(subject, artifacts, builtBy, slsa), "IngestSLSA")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest hasSLSA: %w", err)
	}
	defer cursor.Close()

	hasSLSAList, err := getHasSLSA(ctx, cursor, artifacts)
	if err != nil {
		return nil, fmt.Errorf("failed to get hasSLSA from arango cursor: %w", err)
	}

	if len(hasSLSAList) == 1 {
		return hasSLSAList[0], nil
	} else {
		return nil, fmt.Errorf("number of hasSLSA ingested is greater than one")
	}
}

func getHasSLSA(ctx context.Context, cursor driver.Cursor, builtFrom []*model.Artifact) ([]*model.HasSlsa, error) {
	type collectedData struct {
		Subject       model.Artifact `json:"subject"`
		BuiltBy       model.Builder  `json:"builtBy"`
		HasSLSAId     string         `json:"hasSLSA_id"`
		BuildType     string         `json:"buildType"`
		SlsaPredicate []string       `json:"slsaPredicate"`
		SlsaVersion   string         `json:"slsaVersion"`
		StartedOn     time.Time      `json:"startedOn"`
		FinishedOn    time.Time      `json:"finishedOn"`
		Collector     string         `json:"collector"`
		Origin        string         `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get hasSLSA from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var hasSLSAList []*model.HasSlsa
	for _, createdValue := range createdValues {

		slsa := &model.Slsa{
			BuiltFrom:     builtFrom,
			BuiltBy:       &createdValue.BuiltBy,
			BuildType:     createdValue.BuildType,
			SlsaPredicate: getCollectedPredicates(createdValue.SlsaPredicate),
			SlsaVersion:   createdValue.SlsaVersion,
			StartedOn:     &createdValue.StartedOn,
			FinishedOn:    &createdValue.FinishedOn,
			Origin:        createdValue.Origin,
			Collector:     createdValue.Collector,
		}

		hasSLSA := &model.HasSlsa{
			ID:      createdValue.HasSLSAId,
			Subject: &createdValue.Subject,
			Slsa:    slsa,
		}
		hasSLSAList = append(hasSLSAList, hasSLSA)
	}
	return hasSLSAList, nil
}

func getCollectedPredicates(slsaPredicateList []string) []*model.SLSAPredicate {
	var predicates []*model.SLSAPredicate
	for i := range slsaPredicateList {
		if i%2 == 0 {
			key := slsaPredicateList[i]
			value := slsaPredicateList[i+1]
			slsaPredicate := &model.SLSAPredicate{
				Key:   key,
				Value: value,
			}
			predicates = append(predicates, slsaPredicate)
		}
	}
	return predicates
}
