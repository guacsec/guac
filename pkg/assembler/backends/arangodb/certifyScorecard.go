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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arangodb/go-driver"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const (
	timeScannedStr      string = "timeScanned"
	aggregateScoreStr   string = "aggregateScore"
	checksStr           string = "checks"
	scorecardVersionStr string = "scorecardVersion"
	scorecardCommitStr  string = "scorecardCommit"
)

// Query Scorecards

func (c *arangoClient) Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	values := map[string]any{}
	var arangoQueryBuilder *arangoQueryBuilder

	if certifyScorecardSpec.Source != nil {
		arangoQueryBuilder = setSrcMatchValues(certifyScorecardSpec.Source, values)
		arangoQueryBuilder.forOutBound(scorecardSrcEdgesStr, "scorecard", "sName")
	} else {
		arangoQueryBuilder = newForQuery(scorecardStr, "scorecard")
	}

	setCertifyScorecardMatchValues(arangoQueryBuilder, certifyScorecardSpec, values)

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
		'scorecard_id': scorecard._id,
		'checks': scorecard.checks,
		'aggregateScore': scorecard.aggregateScore,
		'timeScanned': scorecard.timeScanned,
		'scorecardVersion': scorecard.scorecardVersion,
		'scorecardCommit': scorecard.scorecardCommit,
		'collector': scorecard.collector,
		'origin': scorecard.origin
	  }`)

	fmt.Println(arangoQueryBuilder.string())

	cursor, err := executeQueryWithRetry(ctx, c.db, arangoQueryBuilder.string(), values, "Scorecards")
	if err != nil {
		return nil, fmt.Errorf("failed to query for Scorecards: %w", err)
	}
	defer cursor.Close()

	return getCertifyScorecard(ctx, cursor)
}

func setCertifyScorecardMatchValues(arangoQueryBuilder *arangoQueryBuilder, certifyScorecardSpec *model.CertifyScorecardSpec, queryValues map[string]any) {
	if certifyScorecardSpec.TimeScanned != nil {
		arangoQueryBuilder.filter("scorecard", timeScannedStr, "==", "@"+timeScannedStr)
		queryValues[timeScannedStr] = certifyScorecardSpec.TimeScanned.UTC()
	}
	if certifyScorecardSpec.AggregateScore != nil {
		arangoQueryBuilder.filter("scorecard", aggregateScoreStr, "==", "@"+aggregateScoreStr)
		queryValues[aggregateScoreStr] = certifyScorecardSpec.AggregateScore
	}
	if len(certifyScorecardSpec.Checks) > 0 {
		checks := getChecks(certifyScorecardSpec.Checks)
		arangoQueryBuilder.filter("scorecard", checksStr, "==", "@"+checksStr)
		queryValues[checksStr] = checks
	}
	if certifyScorecardSpec.ScorecardVersion != nil {
		arangoQueryBuilder.filter("scorecard", scorecardVersionStr, "==", "@"+scorecardVersionStr)
		queryValues[scorecardVersionStr] = certifyScorecardSpec.ScorecardVersion
	}
	if certifyScorecardSpec.ScorecardCommit != nil {
		arangoQueryBuilder.filter("scorecard", scorecardCommitStr, "==", "@"+scorecardCommitStr)
		queryValues[scorecardCommitStr] = certifyScorecardSpec.ScorecardCommit
	}
	if certifyScorecardSpec.Origin != nil {
		arangoQueryBuilder.filter("scorecard", origin, "==", "@"+origin)
		queryValues["origin"] = certifyScorecardSpec.Origin
	}
	if certifyScorecardSpec.Collector != nil {
		arangoQueryBuilder.filter("scorecard", collector, "==", "@"+collector)
		queryValues["collector"] = certifyScorecardSpec.Collector
	}
	if certifyScorecardSpec.Source == nil {
		// get sources
		arangoQueryBuilder.forInBound(scorecardSrcEdgesStr, "sName", "scorecard")
		arangoQueryBuilder.forInBound(srcHasNameStr, "sNs", "sName")
		arangoQueryBuilder.forInBound(srcHasNamespaceStr, "sType", "sNs")
	}
}

func getChecks(qualifiersSpec []*model.ScorecardCheckSpec) []string {
	checksMap := map[string]int{}
	var keys []string
	for _, kv := range qualifiersSpec {
		checksMap[kv.Check] = kv.Score
		keys = append(keys, kv.Check)
	}
	sort.Strings(keys)
	var checks []string
	for _, k := range keys {
		checks = append(checks, k, strconv.Itoa(checksMap[k]))
	}
	return checks
}

func getScorecardValues(src *model.SourceInputSpec, scorecard *model.ScorecardInputSpec) map[string]any {
	values := map[string]any{}
	// add guac keys
	source := guacSrcId(*src)
	values["srcNameGuacKey"] = source.NameId

	// To ensure consistency, always sort the checks by key
	checksMap := map[string]int{}
	var keys []string
	for _, kv := range scorecard.Checks {
		checksMap[kv.Check] = kv.Score
		keys = append(keys, kv.Check)
	}
	sort.Strings(keys)
	var checks []string
	for _, k := range keys {
		checks = append(checks, k, strconv.Itoa(checksMap[k]))
	}
	values[checksStr] = checks
	values[aggregateScoreStr] = scorecard.AggregateScore
	values[timeScannedStr] = scorecard.TimeScanned.UTC()
	values[scorecardVersionStr] = scorecard.ScorecardVersion
	values[scorecardCommitStr] = scorecard.ScorecardCommit
	values[origin] = scorecard.Origin
	values[collector] = scorecard.Collector

	return values
}

// Ingest Scorecards

func (c *arangoClient) IngestScorecards(ctx context.Context, sources []*model.SourceInputSpec, scorecards []*model.ScorecardInputSpec) ([]*model.CertifyScorecard, error) {
	if len(sources) != len(scorecards) {
		return nil, fmt.Errorf("uneven source and scorecards for ingestion")
	}

	var listOfValues []map[string]any

	for i := range sources {
		listOfValues = append(listOfValues, getScorecardValues(sources[i], scorecards[i]))
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
	  	  
	LET scorecard = FIRST(
		UPSERT { sourceID:firstSrc.name_id, checks:doc.checks, aggregateScore:doc.aggregateScore, timeScanned:doc.timeScanned, scorecardVersion:doc.scorecardVersion, scorecardCommit:doc.scorecardCommit, collector:doc.collector, origin:doc.origin } 
			INSERT { sourceID:firstSrc.name_id, checks:doc.checks, aggregateScore:doc.aggregateScore, timeScanned:doc.timeScanned, scorecardVersion:doc.scorecardVersion, scorecardCommit:doc.scorecardCommit, collector:doc.collector, origin:doc.origin } 
			UPDATE {} IN scorecards
			RETURN NEW
	)
	
	LET edgeCollection = (
	  INSERT {  _key: CONCAT("scorecardSrcEdges", firstSrc.nameDoc._key, scorecard._key), _from: firstSrc.name_id, _to: scorecard._id } INTO scorecardSrcEdges OPTIONS { overwriteMode: "ignore" }
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
		'scorecard_id': scorecard._id,
		'checks': scorecard.checks,
		'aggregateScore': scorecard.aggregateScore,
		'timeScanned': scorecard.timeScanned,
		'scorecardVersion': scorecard.scorecardVersion,
		'scorecardCommit': scorecard.scorecardCommit,
		'collector': scorecard.collector,
		'origin': scorecard.origin
	  }`

	sb.WriteString(query)

	cursor, err := executeQueryWithRetry(ctx, c.db, sb.String(), nil, "IngestScorecards")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest scorecard: %w", err)
	}
	defer cursor.Close()
	scorecardList, err := getCertifyScorecard(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get scorecard from arango cursor: %w", err)
	}

	return scorecardList, nil

}

// Ingest Scorecard

func (c *arangoClient) IngestScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
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
	  	  
	LET scorecard = FIRST(
		UPSERT { sourceID:firstSrc.name_id, checks:@checks, aggregateScore:@aggregateScore, timeScanned:@timeScanned, scorecardVersion:@scorecardVersion, scorecardCommit:@scorecardCommit, collector:@collector, origin:@origin } 
			INSERT { sourceID:firstSrc.name_id, checks:@checks, aggregateScore:@aggregateScore, timeScanned:@timeScanned, scorecardVersion:@scorecardVersion, scorecardCommit:@scorecardCommit, collector:@collector, origin:@origin } 
			UPDATE {} IN scorecards
			RETURN NEW
	)
	
	LET edgeCollection = (
	  INSERT {  _key: CONCAT("scorecardSrcEdges", firstSrc.nameDoc._key, scorecard._key), _from: firstSrc.name_id, _to: scorecard._id } INTO scorecardSrcEdges OPTIONS { overwriteMode: "ignore" }
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
		'scorecard_id': scorecard._id,
		'checks': scorecard.checks,
		'aggregateScore': scorecard.aggregateScore,
		'timeScanned': scorecard.timeScanned,
		'scorecardVersion': scorecard.scorecardVersion,
		'scorecardCommit': scorecard.scorecardCommit,
		'collector': scorecard.collector,
		'origin': scorecard.origin
	  }`

	cursor, err := executeQueryWithRetry(ctx, c.db, query, getScorecardValues(&source, &scorecard), "IngestScorecard")
	if err != nil {
		return nil, fmt.Errorf("failed to ingest source occurrence: %w", err)
	}
	defer cursor.Close()

	scorecardList, err := getCertifyScorecard(ctx, cursor)
	if err != nil {
		return nil, fmt.Errorf("failed to get scorecard from arango cursor: %w", err)
	}

	if len(scorecardList) == 1 {
		return scorecardList[0], nil
	} else {
		return nil, fmt.Errorf("number of scorecard ingested is greater than one")
	}
}

func getCollectedScorecardChecks(checksList []string) ([]*model.ScorecardCheck, error) {
	var scorecardChecks []*model.ScorecardCheck
	for i := range checksList {
		if i%2 == 0 {
			check := checksList[i]
			score, err := strconv.Atoi(checksList[i+1])
			if err != nil {
				return nil, fmt.Errorf("failed to convert score into integer with error: %w", err)
			}
			scorecardCheck := &model.ScorecardCheck{
				Check: check,
				Score: score,
			}
			scorecardChecks = append(scorecardChecks, scorecardCheck)
		}
	}
	return scorecardChecks, nil
}

func getCertifyScorecard(ctx context.Context, cursor driver.Cursor) ([]*model.CertifyScorecard, error) {
	type collectedData struct {
		SrcName          *dbSrcName `json:"srcName"`
		ScorecardID      string     `json:"scorecard_id"`
		Checks           []string   `json:"checks"`
		AggregateScore   float64    `json:"aggregateScore"`
		TimeScanned      time.Time  `json:"timeScanned"`
		ScorecardVersion string     `json:"scorecardVersion"`
		ScorecardCommit  string     `json:"scorecardCommit"`
		Collector        string     `json:"collector"`
		Origin           string     `json:"origin"`
	}

	var createdValues []collectedData
	for {
		var doc collectedData
		_, err := cursor.ReadDocument(ctx, &doc)
		if err != nil {
			if driver.IsNoMoreDocuments(err) {
				break
			} else {
				return nil, fmt.Errorf("failed to get scorecard from cursor: %w", err)
			}
		} else {
			createdValues = append(createdValues, doc)
		}
	}

	var certifyScorecardList []*model.CertifyScorecard
	for _, createdValue := range createdValues {
		src := generateModelSource(createdValue.SrcName.TypeID, createdValue.SrcName.SrcType, createdValue.SrcName.NamespaceID, createdValue.SrcName.Namespace,
			createdValue.SrcName.NameID, createdValue.SrcName.Name, createdValue.SrcName.Commit, createdValue.SrcName.Tag)

		checks, err := getCollectedScorecardChecks(createdValue.Checks)
		if err != nil {
			return nil, fmt.Errorf("failed to get scorecard checks with error: %w", err)
		}
		scorecard := &model.Scorecard{
			Checks:           checks,
			AggregateScore:   createdValue.AggregateScore,
			TimeScanned:      createdValue.TimeScanned,
			ScorecardVersion: createdValue.ScorecardVersion,
			ScorecardCommit:  createdValue.ScorecardCommit,
			Origin:           createdValue.Origin,
			Collector:        createdValue.Collector,
		}

		certifyScorecard := &model.CertifyScorecard{
			ID:        createdValue.ScorecardID,
			Source:    src,
			Scorecard: scorecard,
		}
		certifyScorecardList = append(certifyScorecardList, certifyScorecard)
	}
	return certifyScorecardList, nil
}
