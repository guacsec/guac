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

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/logging"
)

func ingestData(port int) {
	ctx := logging.WithLogger(context.Background())
	logger := logging.FromContext(ctx)

	// ensure server is up
	time.Sleep(1 * time.Second)

	// Create a http client to send the mutation through
	url := fmt.Sprintf("http://localhost:%d/query", port)
	httpClient := http.Client{}
	gqlclient := graphql.NewClient(url, &httpClient)

	logger.Infof("Ingesting test data into backend server")
	ingestScorecards(ctx, gqlclient)
	logger.Infof("Finished ingesting test data into backend server")
}

func ingestScorecards(ctx Context, client graphql.Client) {
	logger := logging.FromContext(ctx)

	source := model.SourceInputSpec{
		Type:      "git",
		Namespace: "github",
		Name:      "github.com/tensorflow/tensorflow",
		Tag:       "v2.12.0",
	}
	checks := []model.ScorecardCheckInputSpec{
		{Check: "Binary_Artifacts", Score: 4},
		{Check: "Branch_Protection", Score: 3},
		{Check: "Code_Review", Score: 2},
		{Check: "Contributors", Score: 1},
	}
	scorecard := model.ScorecardInputSpec{
		Checks:           checks,
		AggregateScore:   2.9,
		TimeScanned:      time.Now(),
		ScorecardVersion: "v4.10.2",
		ScorecardCommit:  "5e6a521",
		Origin:           "Demo ingestion",
		Collector:        "Demo ingestion",
	}
	resp, err := model.Scorecard(context.Background(), client, source, scorecard)
	if err != nil {
		// TODO(mihaimaruseac): Panic or just error and continue?
		logger.Errorf("Error in ingesting: %v\n", err)
	}
	fmt.Printf("Response is |%v|\n", resp)
}
