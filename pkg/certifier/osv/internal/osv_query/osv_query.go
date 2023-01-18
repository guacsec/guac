//
// Copyright 2022 The GUAC Authors.
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

// This package is currently copied from
// https://github.com/google/osv-scanner/blob/main/internal/osv/osv.go.
// Currently, this is not exposed by the upstream project. Once it is
// exposed, this will be removed.

package osv_query

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/vuln/osv"
)

const (
	// QueryEndpoint is the URL for posting queries to OSV.
	QueryEndpoint = "https://api.osv.dev/v1/querybatch"
	// GetEndpoint is the URL for getting vulenrabilities from OSV.
	GetEndpoint = "https://api.osv.dev/v1/vulns"
	// MaxQueriesPerRequest splits up querybatch into multiple requests if
	// number of queries exceed this number
	MaxQueriesPerRequest = 1000
)

// Package represents a package identifier for OSV.
type Package struct {
	PURL      string   `json:"purl,omitempty"`
	Name      string   `json:"name,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Digest    []string `json:"omitempty"`
}

// Query represents a query to OSV.
type Query struct {
	Commit  string  `json:"commit,omitempty"`
	Package Package `json:"package,omitempty"`
	Version string  `json:"version,omitempty"`
}

// BatchedQuery represents a batched query to OSV.
type BatchedQuery struct {
	Queries []*Query `json:"queries"`
}

// MinimalVulnerability represents an unhydrated vulnerability entry from OSV.
type MinimalVulnerability struct {
	ID string `json:"id"`
}

// Response represents a full response from OSV.
type Response struct {
	Vulns []osv.Entry `json:"vulns"`
}

// BatchedResponse represents an unhydrated batched response from OSV.
type BatchedResponse struct {
	Results []Response `json:"results"`
}

// MakePURLRequest makes a PURL request.
func MakePURLRequest(purl string) *Query {
	return &Query{
		Package: Package{
			PURL: purl,
		},
	}
}

// From: https://stackoverflow.com/a/72408490
func chunkBy[T any](items []T, chunkSize int) [][]T {
	var _chunks = make([][]T, 0, (len(items)/chunkSize)+1)
	for chunkSize < len(items) {
		items, _chunks = items[chunkSize:], append(_chunks, items[0:chunkSize:chunkSize])
	}
	return append(_chunks, items)
}

// checkResponseError checks if the response has an error.
func checkResponseError(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBuf, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read error response from server.")
	}

	return fmt.Errorf("server response error: %s", string(respBuf))
}

func MakeRequest(request BatchedQuery) (*BatchedResponse, error) {
	// API has a limit of 1000 bulk query per request
	queryChunks := chunkBy(request.Queries, MaxQueriesPerRequest)
	var totalOsvResp BatchedResponse

	for _, queries := range queryChunks {
		requestBytes, err := json.Marshal(BatchedQuery{Queries: queries})
		if err != nil {
			return nil, err
		}
		requestBuf := bytes.NewBuffer(requestBytes)

		resp, err := http.Post(QueryEndpoint, "application/json", requestBuf)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if err := checkResponseError(resp); err != nil {
			return nil, err
		}

		var osvResp BatchedResponse
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&osvResp)
		if err != nil {
			return nil, err
		}

		totalOsvResp.Results = append(totalOsvResp.Results, osvResp.Results...)
	}

	return &totalOsvResp, nil
}
