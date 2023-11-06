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

//go:build e2e

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestBadHandler(t *testing.T) {
	type args struct {
		gqlAddr     string
		searchDepth string
	}
	tests := []struct {
		name           string
		args           args
		wantStatusCode int
		wantBody       string
	}{
		{
			name: "default",
			args: args{
				gqlAddr:     "http://localhost:8080/query",
				searchDepth: "1",
			},
			wantStatusCode: 200,
		},
		{
			name: "invalid search depth",
			args: args{
				gqlAddr:     "http://localhost:8080/query",
				searchDepth: "invalid",
			},
			wantStatusCode: 400,
		},
	}

	r := gin.Default()
	ctx := context.Background()

	r.GET("/bad", badHandler(ctx))

	ts := httptest.NewServer(r)
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/bad?gql_addr="+tt.args.gqlAddr+"&search_depth="+tt.args.searchDepth, nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			resp, err := http.Get(ts.URL + "/bad?gql_addr=" + tt.args.gqlAddr + "&search_depth=" + tt.args.searchDepth)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			tt.wantBody = string(body)

			if diff := cmp.Diff(tt.wantStatusCode, w.Code); diff != "" {
				t.Errorf("code mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantBody, w.Body.String(), cmpopts.SortSlices(func(x, y string) bool { return x < y })); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
