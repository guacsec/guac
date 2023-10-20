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
	"github.com/guacsec/guac/internal/testing/ptrfrom"
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

	if hasSLSASpec != nil && hasSLSASpec.ID != nil {
		slsa, err := c.buildHasSlsaByID(ctx, *hasSLSASpec.ID, hasSLSASpec)
		if err != nil {
			return nil, fmt.Errorf("buildHasSlsaByID failed with an error: %w", err)
		}
		return []*model.HasSlsa{slsa}, nil
	}

	// TODO (pxp928): Optimize/add other queries based on input and starting node/edge for most efficient retrieval (like from builtBy/builtFrom if specified)
	values := map[string]any{}
	arangoQueryBuilder := setArtifactMatchValues(hasSLSASpec.Subject, values)
	arangoQueryBuilder.forOutBound(hasSLSASubjectArtEdgesStr, "hasSLSA", "art")
	setHasSLSAMatchValues(arangoQueryBuilder, hasSLSASpec, values)
	arangoQueryBuilder.forOutBound(hasSLSABuiltByEdgesStr, "build", "hasSLSA")
	if hasSLSASpec.BuiltBy != nil {
		if hasSLSASpec.BuiltBy.ID != nil {
			arangoQueryBuilder.filter("build", "_id", "==", "@id")
			values["id"] = *hasSLSASpec.BuiltBy.ID
		}
		if hasSLSASpec.BuiltBy.URI != nil {
			arangoQueryBuilder.filter("build", "uri", "==", "@uri")
			values["uri"] = *hasSLSASpec.BuiltBy.URI
		}
	}
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN {
		'subject': {
			'id': art._id,
			'algorithm': art.algorithm,
			'digest': art.digest
		},
		'builtBy': {
			'id': build._id,
			'uri': build.uri
		},
		'hasSLSA_id': hasSLSA._id,
		'buildType': hasSLSA.buildType,
		'builtFrom': hasSLSA.builtFrom,
		'slsaPredicate': hasSLSA.slsaPredicate,
		'slsaVersion': hasSLSA.slsaVersion,
		'startedOn': hasSLSA.startedOn,
		'finishedOn': hasSLSA.finishedOn,
		'collector': hasSLSA.collector,
		'origin': hasSLSA.origin
	}`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "HasSlsa")
	if err != nil {
		return nil, fmt.Errorf("failed to query for HasSlsa: %w", err)
	}
	defer cursor.Close()

	return getHasSLSAFromCursor(c, ctx, cursor, map[string][]*model.Artifact{}, hasSLSASpec.BuiltFrom)
}

func setHasSLSAMatchValues(arangoQueryBuilder *arangoQueryBuilder, hasSLSASpec *model.HasSLSASpec, queryValues map[string]any) {
	if hasSLSASpec.ID != nil {
		arangoQueryBuilder.filter("hasSLSA", "_id", "==", "@id")
		queryValues["id"] = *hasSLSASpec.ID
	}
	if hasSLSASpec.BuildType != nil {
		arangoQueryBuilder.filter("hasSLSA", buildTypeStr, "==", "@"+buildTypeStr)
		queryValues[buildTypeStr] = *hasSLSASpec.BuildType
	}
	if len(hasSLSASpec.Predicate) > 0 {
		predicateValues := getPredicateValuesFromFilter(hasSLSASpec.Predicate)
		arangoQueryBuilder.filter("hasSLSA", slsaPredicateStr, "==", "@"+slsaPredicateStr)
		queryValues[slsaPredicateStr] = predicateValues
	}
	if hasSLSASpec.SlsaVersion != nil {
		arangoQueryBuilder.filter("hasSLSA", slsaVersionStr, "==", "@"+slsaVersionStr)
		queryValues[slsaVersionStr] = *hasSLSASpec.SlsaVersion
	}
	if hasSLSASpec.StartedOn != nil {
		arangoQueryBuilder.filter("hasSLSA", startedOnStr, "==", "@"+startedOnStr)
		queryValues[startedOnStr] = hasSLSASpec.StartedOn.UTC()
	}
	if hasSLSASpec.FinishedOn != nil {
		arangoQueryBuilder.filter("hasSLSA", finishedOnStr, "==", "@"+finishedOnStr)
		queryValues[finishedOnStr] = hasSLSASpec.FinishedOn.UTC()
	}
	if hasSLSASpec.Origin != nil {
		arangoQueryBuilder.filter("hasSLSA", origin, "==", "@"+origin)
		queryValues[origin] = *hasSLSASpec.Origin
	}
	if hasSLSASpec.Collector != nil {
		arangoQueryBuilder.filter("hasSLSA", collector, "==", "@"+collector)
		queryValues[collector] = *hasSLSASpec.Collector
	}
}

func getPredicateValuesFromFilter(slsaPredicate []*model.SLSAPredicateSpec) []string {
	predicateMap := map[string]string{}
	keys := []string{}
	for _, kv := range slsaPredicate {
		key := removeInvalidCharFromProperty(kv.Key)
		predicateMap[key] = kv.Value
		keys = append(keys, key)
	}
	sort.Strings(keys)
	predicateValues := []string{}
	for _, k := range keys {
		predicateValues = append(predicateValues, k, predicateMap[k])
	}
	return predicateValues
}

func getSLSAValues(subject model.ArtifactInputSpec, builtFrom []*model.Artifact, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) map[string]any {
	values := map[string]any{}

	values["algorithm"] = strings.ToLower(subject.Algorithm)
	values["digest"] = strings.ToLower(subject.Digest)

	values["uri"] = builtBy.URI
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
		builtFromKeyList = append(builtFromKeyList, splitID[1])
	}

	values[builtFromStr] = builtFromIDList
	values["buildFromKeyList"] = builtFromKeyList
	values[buildTypeStr] = slsa.BuildType
	values[slsaVersionStr] = slsa.SlsaVersion
	if slsa.StartedOn != nil {
		values[startedOnStr] = slsa.StartedOn.UTC()
	} else {
		values[startedOnStr] = time.Unix(0, 0).UTC()
	}
	if slsa.FinishedOn != nil {
		values[finishedOnStr] = slsa.FinishedOn.UTC()
	} else {
		values[finishedOnStr] = time.Unix(0, 0).UTC()
	}
	values[origin] = slsa.Origin
	values[collector] = slsa.Collector

	return values
}

func (c *arangoClient) IngestSLSAs(ctx context.Context, subjects []*model.ArtifactInputSpec, builtFromList [][]*model.ArtifactInputSpec, builtByList []*model.BuilderInputSpec, slsaList []*model.SLSAInputSpec) ([]*model.HasSlsa, error) {
	builtFromMap := map[string][]*model.Artifact{}
	var listOfValues []map[string]any

	for i := range subjects {
		// get materials (builtFrom artifacts) as they should already be ingested
		materialList, err := c.getMaterials(ctx, builtFromList[i])
		if err != nil {
			return nil, fmt.Errorf("failed to get built from artifact with error: %w", err)
		}
		builtFromMap[artifactKey(subjects[i].Algorithm, subjects[i].Digest)] = materialList
		listOfValues = append(listOfValues, getSLSAValues(*subjects[i], materialList, *builtByList[i], *slsaList[i]))
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
	LET subject = FIRST(FOR art IN artifacts FILTER art.algorithm == doc.algorithm FILTER art.digest == doc.digest RETURN art)
	LET builtBy = FIRST(FOR builder IN builders FILTER builder.uri == doc.uri RETURN builder)
	LET hasSLSA = FIRST(
		UPSERT { subjectID:subject._id, builtByID:builtBy._id, builtFrom:doc.builtFrom, buildType:doc.buildType, slsaPredicate:doc.slsaPredicate, slsaVersion:doc.slsaVersion, startedOn:doc.startedOn, finishedOn:doc.finishedOn, collector:doc.collector, origin:doc.origin } 
		INSERT { subjectID:subject._id, builtByID:builtBy._id, builtFrom:doc.builtFrom, buildType:doc.buildType, slsaPredicate:doc.slsaPredicate, slsaVersion:doc.slsaVersion, startedOn:doc.startedOn, finishedOn:doc.finishedOn, collector:doc.collector, origin:doc.origin } 
		UPDATE {} IN hasSLSAs
		RETURN NEW
	)

	INSERT { _key: CONCAT("hasSLSASubjectArtEdges", subject._key, hasSLSA._key), _from: subject._id, _to: hasSLSA._id } INTO hasSLSASubjectArtEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("hasSLSABuiltByEdges", hasSLSA._key, builtBy._key), _from: hasSLSA._id, _to: builtBy._id } INTO hasSLSABuiltByEdges OPTIONS { overwriteMode: "ignore" }

	LET buildFromCollection = (FOR bfData IN doc.buildFromKeyList
		INSERT { _key: CONCAT("hasSLSABuiltFromEdges", hasSLSA._key, bfData), _from: hasSLSA._id, _to: CONCAT("artifacts/", bfData) } INTO hasSLSABuiltFromEdges OPTIONS { overwriteMode: "ignore" }
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
		'builtFrom': hasSLSA.builtFrom,
		'slsaPredicate': hasSLSA.slsaPredicate,
		'slsaVersion': hasSLSA.slsaVersion,
		'startedOn': hasSLSA.startedOn,
		'finishedOn': hasSLSA.finishedOn,
		'collector': hasSLSA.collector,
		'origin': hasSLSA.origin
	}`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestSLSAs")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest hasSLSA: %w", err)
	}
	defer cursor.Close()
	hasSLSAList, err := getHasSLSAFromCursor(c, ctx, cursor, builtFromMap, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get hasSLSA from arango cursor: %w", err)
	}

	return hasSLSAList, nil
}

func (c *arangoClient) IngestSLSA(ctx context.Context, subject model.ArtifactInputSpec, builtFrom []*model.ArtifactInputSpec, builtBy model.BuilderInputSpec, slsa model.SLSAInputSpec) (*model.HasSlsa, error) {
	// get materials (builtFrom artifacts) as they should already be ingested
	artifacts, err := c.getMaterials(ctx, builtFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to get built from artifact with error: %w", err)
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

	INSERT { _key: CONCAT("hasSLSASubjectArtEdges", subject._key, hasSLSA._key), _from: subject._id, _to: hasSLSA._id } INTO hasSLSASubjectArtEdges OPTIONS { overwriteMode: "ignore" }
	INSERT { _key: CONCAT("hasSLSABuiltByEdges", hasSLSA._key, builtBy._key), _from: hasSLSA._id, _to: builtBy._id } INTO hasSLSABuiltByEdges OPTIONS { overwriteMode: "ignore" }

	LET buildFromCollection = (FOR bfData IN @buildFromKeyList
		INSERT { _key: CONCAT("hasSLSABuiltFromEdges", hasSLSA._key, bfData), _from: hasSLSA._id, _to: CONCAT("artifacts/", bfData) } INTO hasSLSABuiltFromEdges OPTIONS { overwriteMode: "ignore" }
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
		'builtFrom': hasSLSA.builtFrom,
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

	hasSLSAList, err := getHasSLSAFromCursor(c, ctx, cursor, map[string][]*model.Artifact{artifactKey(subject.Algorithm, subject.Digest): artifacts}, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get hasSLSA from arango cursor: %w", err)
	}

	if len(hasSLSAList) == 1 {
		return hasSLSAList[0], nil
	} else {
		return nil, fmt.Errorf("number of hasSLSA ingested is greater than one")
	}
}

func artifactKey(alg, dig string) string {
	algorithm := strings.ToLower(alg)
	digest := strings.ToLower(dig)
	return strings.Join([]string{algorithm, digest}, ":")
}

func getHasSLSAFromCursor(c *arangoClient, ctx context.Context, cursor driver.Cursor, builtFromMap map[string][]*model.Artifact, filterBuiltFrom []*model.ArtifactSpec) ([]*model.HasSlsa, error) {
	type collectedData struct {
		Subject       *model.Artifact `json:"subject"`
		BuiltBy       *model.Builder  `json:"builtBy"`
		BuiltFrom     []string        `json:"builtFrom"`
		HasSLSAId     string          `json:"hasSLSA_id"`
		BuildType     string          `json:"buildType"`
		SlsaPredicate []string        `json:"slsaPredicate"`
		SlsaVersion   string          `json:"slsaVersion"`
		StartedOn     *time.Time      `json:"startedOn"`
		FinishedOn    *time.Time      `json:"finishedOn"`
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
				return nil, fmt.Errorf("failed to get hasSLSA from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var hasSLSAList []*model.HasSlsa
	for _, createdValue := range createdValues {
		if createdValue.BuiltBy == nil || createdValue.Subject == nil {
			return nil, fmt.Errorf("failed to get subject or builtBy from cursor for hasSLSA")
		}
		var builtFromArtifacts []*model.Artifact
		if val, ok := builtFromMap[artifactKey(createdValue.Subject.Algorithm, createdValue.Subject.Digest)]; ok {
			builtFromArtifacts = val
		} else {
			artifacts, err := c.getMaterialsByID(ctx, createdValue.BuiltFrom)
			if err != nil {
				return nil, fmt.Errorf("failed to get artifact by ID for hasSLSA builtFrom with error: %w", err)
			}
			matchingArtifacts := true
			if filterBuiltFrom != nil {
				matchingArtifacts = false
				for _, bfArtifact := range filterBuiltFrom {
					if containsMatchingArtifact(artifacts, bfArtifact.ID, bfArtifact.Algorithm, bfArtifact.Digest) {
						matchingArtifacts = true
						break
					}
				}
			}
			if matchingArtifacts {
				builtFromArtifacts = artifacts
			}
		}

		if len(builtFromArtifacts) > 0 {
			slsa := &model.Slsa{
				BuiltFrom:     builtFromArtifacts,
				BuiltBy:       createdValue.BuiltBy,
				BuildType:     createdValue.BuildType,
				SlsaPredicate: getCollectedPredicates(createdValue.SlsaPredicate),
				SlsaVersion:   createdValue.SlsaVersion,
				Origin:        createdValue.Origin,
				Collector:     createdValue.Collector,
			}

			if !createdValue.StartedOn.Equal(time.Unix(0, 0).UTC()) {
				slsa.StartedOn = createdValue.StartedOn
			}

			if !createdValue.FinishedOn.Equal(time.Unix(0, 0).UTC()) {
				slsa.FinishedOn = createdValue.FinishedOn
			}

			hasSLSA := &model.HasSlsa{
				ID:      createdValue.HasSLSAId,
				Subject: createdValue.Subject,
				Slsa:    slsa,
			}
			hasSLSAList = append(hasSLSAList, hasSLSA)
		}
	}
	return hasSLSAList, nil
}

func containsMatchingArtifact(artifacts []*model.Artifact, filterID *string, filterAlgo *string, filterDigest *string) bool {
	var id string = ""
	var algorithm string = ""
	var digest string = ""
	if filterID != nil {
		id = *filterID
	}
	if filterAlgo != nil {
		algorithm = strings.ToLower(*filterAlgo)
	}
	if filterDigest != nil {
		digest = strings.ToLower(*filterDigest)
	}

	for _, a := range artifacts {
		matchID := false
		if id == "" || id == a.ID {
			matchID = true
		}
		matchAlgorithm := false
		if algorithm == "" || algorithm == a.Algorithm {
			matchAlgorithm = true
		}

		matchDigest := false
		if digest == "" || digest == a.Digest {
			matchDigest = true
		}

		if matchID && matchDigest && matchAlgorithm {
			return true
		}
	}
	return false
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

func (c *arangoClient) buildHasSlsaByID(ctx context.Context, id string, filter *model.HasSLSASpec) (*model.HasSlsa, error) {
	if filter != nil && filter.ID != nil {
		if *filter.ID != id {
			return nil, fmt.Errorf("ID does not match filter")
		}
	}

	idSplit := strings.Split(id, "/")
	if len(idSplit) != 2 {
		return nil, fmt.Errorf("invalid ID: %s", id)
	}

	if idSplit[0] == hasSLSAsStr {
		if filter != nil {
			filter.ID = ptrfrom.String(id)
		} else {
			filter = &model.HasSLSASpec{
				ID: ptrfrom.String(id),
			}
		}
		return c.queryHasSlsaNodeByID(ctx, filter)
	} else {
		return nil, fmt.Errorf("id type does not match for hasSLSA query: %s", id)
	}
}

func (c *arangoClient) queryHasSlsaNodeByID(ctx context.Context, filter *model.HasSLSASpec) (*model.HasSlsa, error) {
	values := map[string]any{}
	arangoQueryBuilder := newForQuery(hasSLSAsStr, "hasSLSA")
	setHasSLSAMatchValues(arangoQueryBuilder, filter, values)
	arangoQueryBuilder.query.WriteString("\n")
	arangoQueryBuilder.query.WriteString(`RETURN hasSLSA`)

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "queryHasSlsaNodeByID")
	if err != nil {
		return nil, fmt.Errorf("failed to query for hasSLSA: %w, values: %v", err, values)
	}
	defer cursor.Close()

	type dbHasSLSA struct {
		HasSlsaID     string     `json:"_id"`
		ArtifactID    string     `json:"subjectID"`
		BuiltByID     string     `json:"builtByID"`
		BuiltFrom     []string   `json:"builtFrom"`
		HasSLSAId     string     `json:"hasSLSA_id"`
		BuildType     string     `json:"buildType"`
		SlsaPredicate []string   `json:"slsaPredicate"`
		SlsaVersion   string     `json:"slsaVersion"`
		StartedOn     *time.Time `json:"startedOn"`
		FinishedOn    *time.Time `json:"finishedOn"`
		Collector     string     `json:"collector"`
		Origin        string     `json:"origin"`
	}

	var collectedValues []dbHasSLSA
	for {
		var doc dbHasSLSA
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to hasSLSA from cursor: %w", err)
			}
		} else {
			collectedValues = append(collectedValues, doc)
		}
	}

	if len(collectedValues) != 1 {
		return nil, fmt.Errorf("number of hasSLSA nodes found for ID: %s is greater than one", *filter.ID)
	}

	slsa := &model.Slsa{
		BuildType:     collectedValues[0].BuildType,
		SlsaPredicate: getCollectedPredicates(collectedValues[0].SlsaPredicate),
		SlsaVersion:   collectedValues[0].SlsaVersion,
		Origin:        collectedValues[0].Origin,
		Collector:     collectedValues[0].Collector,
	}

	if !collectedValues[0].StartedOn.Equal(time.Unix(0, 0).UTC()) {
		slsa.StartedOn = collectedValues[0].StartedOn
	}

	if !collectedValues[0].FinishedOn.Equal(time.Unix(0, 0).UTC()) {
		slsa.FinishedOn = collectedValues[0].FinishedOn
	}

	builtPackage, err := c.buildBuilderResponseByID(ctx, collectedValues[0].BuiltByID, filter.BuiltBy)
	if err != nil {
		return nil, fmt.Errorf("failed to get builtBy from ID: %s, with error: %w", collectedValues[0].BuiltByID, err)
	}
	slsa.BuiltBy = builtPackage

	artifacts, err := c.getMaterialsByID(ctx, collectedValues[0].BuiltFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to get artifact by ID for hasSLSA builtFrom with error: %w", err)
	}

	matchingArtifacts := true
	if filter.BuiltFrom != nil {
		matchingArtifacts = false
		for _, bfArtifact := range filter.BuiltFrom {
			if containsMatchingArtifact(artifacts, bfArtifact.ID, bfArtifact.Algorithm, bfArtifact.Digest) {
				matchingArtifacts = true
				break
			}
		}
	}
	if matchingArtifacts {
		slsa.BuiltFrom = append(slsa.BuiltFrom, artifacts...)
	}

	subject, err := c.buildArtifactResponseByID(ctx, collectedValues[0].ArtifactID, filter.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to get artifact from ID: %s, with error: %w", collectedValues[0].ArtifactID, err)
	}

	return &model.HasSlsa{
		ID:      collectedValues[0].HasSlsaID,
		Subject: subject,
		Slsa:    slsa,
	}, nil
}

func (c *arangoClient) hasSlsaNeighbors(ctx context.Context, nodeID string, allowedEdges edgeMap) ([]string, error) {
	out := make([]string, 0, 1)
	if allowedEdges[model.EdgeHasSlsaSubject] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSLSAsStr, "hasSLSA")
		setHasSLSAMatchValues(arangoQueryBuilder, &model.HasSLSASpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSLSA.subjectID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasSlsaNeighbors - artifact")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeHasSlsaBuiltBy] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSLSAsStr, "hasSLSA")
		setHasSLSAMatchValues(arangoQueryBuilder, &model.HasSLSASpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { neighbor:  hasSLSA.builtByID }")

		foundIDs, err := c.getNeighborIDFromCursor(ctx, arangoQueryBuilder, values, "hasSlsaNeighbors - builder")
		if err != nil {
			return out, fmt.Errorf("failed to get neighbors for node ID: %s from arango cursor with error: %w", nodeID, err)
		}
		out = append(out, foundIDs...)
	}
	if allowedEdges[model.EdgeHasSlsaMaterials] {
		values := map[string]any{}
		arangoQueryBuilder := newForQuery(hasSLSAsStr, "hasSLSA")
		setHasSLSAMatchValues(arangoQueryBuilder, &model.HasSLSASpec{ID: &nodeID}, values)
		arangoQueryBuilder.query.WriteString("\nRETURN { builtFrom:  hasSLSA.builtFrom }")

		cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "getNeighborIDFromCursor - hasSlsaNeighbors")
		if err != nil {
			return nil, fmt.Errorf("failed to query for Neighbors for %s with error: %w", "hasSlsaNeighbors", err)
		}
		defer cursor.Close()

		type dbSlsaMaterialsNeighbor struct {
			BuiltFrom []string `json:"builtFrom"`
		}

		var foundSlsaMaterialNeighbors []dbSlsaMaterialsNeighbor
		for {
			var doc dbSlsaMaterialsNeighbor
			_, err := cursor.ReadDocument(ctx, &doc)
			if err != nil {
				if driver.IsNoMoreDocuments(err) {
					break
				} else {
					return nil, fmt.Errorf("failed to get neighbor id from cursor for %s with error: %w", "hasSlsaNeighbors", err)
				}
			} else {
				foundSlsaMaterialNeighbors = append(foundSlsaMaterialNeighbors, doc)
			}
		}

		var foundIDs []string
		for _, foundMaterial := range foundSlsaMaterialNeighbors {
			if foundMaterial.BuiltFrom != nil {
				foundIDs = append(foundIDs, foundMaterial.BuiltFrom...)
			}
		}

		out = append(out, foundIDs...)
	}

	return out, nil
}
