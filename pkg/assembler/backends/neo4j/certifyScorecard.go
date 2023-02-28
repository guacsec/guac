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
				commitString := ""
				if result.Record().Values[4] != nil {
					commitString = result.Record().Values[4].(string)
				}

				tagString := ""
				if result.Record().Values[3] != nil {
					tagString = result.Record().Values[3].(string)
				}

				nameString := result.Record().Values[2].(string)
				namespaceString := result.Record().Values[1].(string)
				typeString := result.Record().Values[0].(string)

				srcName := &model.SourceName{
					Name:   nameString,
					Tag:    &tagString,
					Commit: &commitString,
				}

				srcNamespace := &model.SourceNamespace{
					Namespace: namespaceString,
					Names:     []*model.SourceName{srcName},
				}

				src := model.Source{
					Type:       typeString,
					Namespaces: []*model.SourceNamespace{srcNamespace},
				}

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
					TimeScanned:      certifyScorecardNode.Props[timeScanned].(string),
					AggregateScore:   certifyScorecardNode.Props[aggregateScore].(float64),
					Checks:           checks,
					ScorecardVersion: certifyScorecardNode.Props[scorecardVersion].(string),
					ScorecardCommit:  certifyScorecardNode.Props[scorecardCommit].(string),
					Origin:           certifyScorecardNode.Props[origin].(string),
					Collector:        certifyScorecardNode.Props[collector].(string),
				}

				certifyScorecard := &model.CertifyScorecard{
					Source:    &src,
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
			Score: valueList[i].(int),
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
