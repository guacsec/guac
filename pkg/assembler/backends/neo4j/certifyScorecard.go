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

package neo4jBackend

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j/dbtype"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	timeScanned      string = "timeScanned"
	aggregateScore   string = "aggregateScore"
	checkKeys        string = "checkKeys"
	checkValues      string = "checkValues"
	scorecardVersion string = "scorecardVersion"
	scorecardCommit  string = "scorecardCommit"
)

func (c *neo4jClient) Scorecards(ctx context.Context, certifyScorecardSpec *model.CertifyScorecardSpec) ([]*model.CertifyScorecard, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close()

	var sb strings.Builder
	var firstMatch bool = true
	queryValues := map[string]any{}

	query := "MATCH (root:Src)-[:SrcHasType]->(type:SrcType)-[:SrcHasNamespace]->(namespace:SrcNamespace)" +
		"-[:SrcHasName]->(name:SrcName)-[:subject]-(certifyScorecard:CertifyScorecard)"
	sb.WriteString(query)

	setSrcMatchValues(&sb, certifyScorecardSpec.Source, false, &firstMatch, queryValues)
	setCertifyScorecardValues(&sb, certifyScorecardSpec, &firstMatch, queryValues)
	sb.WriteString(" RETURN type.type, namespace.namespace, name.name, name.tag, name.commit, certifyScorecard")

	result, err := session.ReadTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			result, err := tx.Run(sb.String(), queryValues)
			if err != nil {
				return nil, err
			}

			collectedCertifyScorecard := []*model.CertifyScorecard{}

			for result.Next() {
				tag := result.Record().Values[4]
				commit := result.Record().Values[3]
				nameStr := result.Record().Values[2].(string)
				namespaceStr := result.Record().Values[1].(string)
				srcType := result.Record().Values[0].(string)

				src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

				certifyScorecardNode := dbtype.Node{}
				if result.Record().Values[5] != nil {
					certifyScorecardNode = result.Record().Values[5].(dbtype.Node)
				} else {
					return nil, gqlerror.Errorf("certifyScorecard Node not found in neo4j")
				}

				checks, err := getCollectedChecks(certifyScorecardNode.Props[checkKeys].([]interface{}), certifyScorecardNode.Props[checkValues].([]interface{}))
				if err != nil {
					return nil, err
				}

				scorecard := model.Scorecard{
					TimeScanned:      certifyScorecardNode.Props[timeScanned].(time.Time),
					AggregateScore:   certifyScorecardNode.Props[aggregateScore].(float64),
					Checks:           checks,
					ScorecardVersion: certifyScorecardNode.Props[scorecardVersion].(string),
					ScorecardCommit:  certifyScorecardNode.Props[scorecardCommit].(string),
					Origin:           certifyScorecardNode.Props[origin].(string),
					Collector:        certifyScorecardNode.Props[collector].(string),
				}

				certifyScorecard := &model.CertifyScorecard{
					Source:    src,
					Scorecard: &scorecard,
				}

				collectedCertifyScorecard = append(collectedCertifyScorecard, certifyScorecard)
			}
			if err = result.Err(); err != nil {
				return nil, err
			}

			return collectedCertifyScorecard, nil
		})
	if err != nil {
		return nil, err
	}

	return result.([]*model.CertifyScorecard), nil
}

func getCollectedChecks(keyList []interface{}, valueList []interface{}) ([]*model.ScorecardCheck, error) {
	if len(keyList) != len(valueList) {
		return nil, gqlerror.Errorf("length of scorecard checks do not match")
	}
	checks := []*model.ScorecardCheck{}
	for i := range keyList {
		check := &model.ScorecardCheck{
			Check: keyList[i].(string),
			// TODO(mihaimaruseac): This cast seems weird, investigate
			Score: int(valueList[i].(int64)),
		}
		checks = append(checks, check)
	}
	return checks, nil
}

func getScorecardChecks(checks []*model.ScorecardCheckSpec) ([]string, []int) {
	checksMap := map[string]int{}
	keys := []string{}
	for _, kv := range checks {
		key := removeInvalidCharFromProperty(kv.Check)
		checksMap[key] = kv.Score
		keys = append(keys, key)
	}
	sort.Strings(keys)
	collectedChecks := []int{}
	for _, k := range keys {
		collectedChecks = append(collectedChecks, checksMap[k])
	}
	return keys, collectedChecks
}

func setCertifyScorecardValues(sb *strings.Builder, certifyScorecardSpec *model.CertifyScorecardSpec, firstMatch *bool, queryValues map[string]any) {
	if certifyScorecardSpec.TimeScanned != nil {
		matchProperties(sb, *firstMatch, "certifyScorecard", timeScanned, "$"+timeScanned)
		*firstMatch = false
		queryValues[timeScanned] = certifyScorecardSpec.TimeScanned
	}
	if certifyScorecardSpec.AggregateScore != nil {
		matchProperties(sb, *firstMatch, "certifyScorecard", aggregateScore, "$"+aggregateScore)
		*firstMatch = false
		queryValues[aggregateScore] = certifyScorecardSpec.AggregateScore
	}
	if len(certifyScorecardSpec.Checks) > 0 {
		keys, values := getScorecardChecks(certifyScorecardSpec.Checks)
		matchProperties(sb, *firstMatch, "certifyScorecard", checkKeys, "$"+checkKeys)
		queryValues[checkKeys] = keys
		matchProperties(sb, *firstMatch, "certifyScorecard", checkValues, "$"+checkValues)
		queryValues[checkValues] = values
		*firstMatch = false
	}
	if certifyScorecardSpec.ScorecardVersion != nil {
		matchProperties(sb, *firstMatch, "certifyScorecard", scorecardVersion, "$"+scorecardVersion)
		*firstMatch = false
		queryValues[scorecardVersion] = certifyScorecardSpec.ScorecardVersion
	}
	if certifyScorecardSpec.ScorecardCommit != nil {
		matchProperties(sb, *firstMatch, "certifyScorecard", scorecardCommit, "$"+scorecardCommit)
		*firstMatch = false
		queryValues[scorecardCommit] = certifyScorecardSpec.ScorecardCommit
	}
	if certifyScorecardSpec.Origin != nil {
		matchProperties(sb, *firstMatch, "certifyScorecard", "origin", "$origin")
		*firstMatch = false
		queryValues["origin"] = certifyScorecardSpec.Origin
	}
	if certifyScorecardSpec.Collector != nil {
		matchProperties(sb, *firstMatch, "certifyScorecard", "collector", "$collector")
		*firstMatch = false
		queryValues["collector"] = certifyScorecardSpec.Collector
	}
}

func (c *neo4jClient) CertifyScorecard(ctx context.Context, source model.SourceInputSpec, scorecard model.ScorecardInputSpec) (*model.CertifyScorecard, error) {
	session := c.driver.NewSession(neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close()

	values := map[string]any{}
	values["sourceType"] = source.Type
	values["namespace"] = source.Namespace
	values["name"] = source.Name

	if source.Commit != nil && source.Tag != nil {
		if *source.Commit != "" && *source.Tag != "" {
			return nil, gqlerror.Errorf("Passing both commit and tag selectors is an error")
		}
	}

	if source.Commit != nil {
		values["commit"] = *source.Commit
	}

	if source.Tag != nil {
		values["tag"] = *source.Tag
	}

	values[timeScanned] = scorecard.TimeScanned
	values[aggregateScore] = scorecard.AggregateScore
	values[scorecardVersion] = scorecard.ScorecardVersion
	values[scorecardCommit] = scorecard.ScorecardCommit

	// Cannot use getScorecardChecks due to type mismatch
	// Generics would be really helpful here :)
	checksMap := map[string]int{}
	checkKeysList := []string{}
	checkValuesList := []int{}
	for _, check := range scorecard.Checks {
		key := removeInvalidCharFromProperty(check.Check)
		checksMap[key] = check.Score
		checkKeysList = append(checkKeysList, key)
	}
	sort.Strings(checkKeysList)
	for _, k := range checkKeysList {
		checkValuesList = append(checkValuesList, checksMap[k])
	}
	values[checkKeys] = checkKeysList
	values[checkValues] = checkValuesList

	// TODO(mihaimaruseac): Should we put origin/collector on the edge instead?
	values["origin"] = scorecard.Origin
	values["collector"] = scorecard.Collector

	result, err := session.WriteTransaction(
		func(tx neo4j.Transaction) (interface{}, error) {
			query := `
MATCH (root:Src) -[:SrcHasType]-> (type:SrcType) -[:SrcHasNamespace]-> (ns:SrcNamespace) -[:SrcHasName] -> (name:SrcName)
WHERE type.type = $sourceType AND ns.namespace = $namespace AND name.name = $name AND name.commit = $commit AND name.tag = $tag
MERGE (name) <-[:subject]- (certifyScorecard:CertifyScorecard{timeScanned:$timeScanned,aggregateScore:$aggregateScore,scorecardVersion:$scorecardVersion,scorecardCommit:$scorecardCommit,checkKeys:$checkKeys,checkValues:$checkValues,origin:$origin,collector:$collector})
RETURN type.type, ns.namespace, name.name, name.commit, name.tag, certifyScorecard`
			result, err := tx.Run(query, values)
			if err != nil {
				return nil, err
			}

			// query returns a single record
			record, err := result.Single()
			if err != nil {
				return nil, err
			}

			// TODO(mihaimaruseac): Profile to compare returning node vs returning list of properties
			certifyScorecardNode := record.Values[5].(dbtype.Node)
			checks, err := getCollectedChecks(
				certifyScorecardNode.Props[checkKeys].([]interface{}),
				certifyScorecardNode.Props[checkValues].([]interface{}))
			if err != nil {
				return nil, err
			}

			scorecard := model.Scorecard{
				TimeScanned:      certifyScorecardNode.Props[timeScanned].(time.Time),
				AggregateScore:   certifyScorecardNode.Props[aggregateScore].(float64),
				Checks:           checks,
				ScorecardVersion: certifyScorecardNode.Props[scorecardVersion].(string),
				ScorecardCommit:  certifyScorecardNode.Props[scorecardCommit].(string),
				Origin:           certifyScorecardNode.Props[origin].(string),
				Collector:        certifyScorecardNode.Props[collector].(string),
			}

			tag := record.Values[4]
			commit := record.Values[3]
			nameStr := record.Values[2].(string)
			namespaceStr := record.Values[1].(string)
			srcType := record.Values[0].(string)

			src := generateModelSource(srcType, namespaceStr, nameStr, commit, tag)

			certification := model.CertifyScorecard{
				Source:    src,
				Scorecard: &scorecard,
			}

			return &certification, nil
		})
	if err != nil {
		return nil, err
	}

	return result.(*model.CertifyScorecard), nil
}
