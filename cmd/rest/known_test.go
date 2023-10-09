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

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/go-cmp/cmp"
)

func TestGetPackage(t *testing.T) {
	type args struct {
		url  string
		hash string
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
				url:  "/known/package/pkg:golang/github.com/prometheus/client_golang@v1.11.1",
				hash: "pkg:golang/github.com/prometheus/client_golang@v1.11.1",
			},
			wantStatusCode: 200,
		},
		{
			name: "invalid hash",
			args: args{
				url:  "/known/package/invalid",
				hash: "invalid",
			},
			wantStatusCode: 400,
		},
		{
			name: "non-existent package",
			args: args{
				url:  "/known/package/pkg:golang/github.com/nonexistent/package@v1.0.0",
				hash: "pkg:golang/github.com/nonexistent/package@v1.0.0",
			},
			wantStatusCode: 404,
		},
	}

	r := gin.Default()
	ctx := context.Background()

	r.GET("/known/package/*hash", packageHandlerForHash(ctx))

	ts := httptest.NewServer(r)
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.args.url, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			resp, err := http.Get(ts.URL + tt.args.url)
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
			if diff := cmp.Diff(tt.wantBody, w.Body.String()); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetSource(t *testing.T) {
	type args struct {
		url string
		vcs string
	}
	tests := []struct {
		name           string
		args           args
		wantStatusCode int
	}{
		{
			name: "Valid VCS",
			args: args{
				url: "/known/source/git+https://github.com/prometheus/client_golang",
				vcs: "git+https://github.com/prometheus/client_golang",
			},
			wantStatusCode: 200,
		},
		{
			name: "Invalid VCS",
			args: args{
				url: "/known/source/invalid",
				vcs: "invalid",
			},
			wantStatusCode: 400,
		},
		{
			name: "Non-existent VCS",
			args: args{
				url: "/known/source/git+https://github.com/nonexistent/vcs",
				vcs: "git+https://github.com/nonexistent/vcs",
			},
			wantStatusCode: 404,
		},
	}

	r := gin.Default()
	ctx := context.Background()

	r.GET("/known/source/*vcs", sourceHandlerForVCS(ctx))

	ts := httptest.NewServer(r)
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.args.url, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			resp, err := http.Get(ts.URL + tt.args.url)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if diff := cmp.Diff(tt.wantStatusCode, w.Code); diff != "" {
				t.Errorf("code mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetArtifact(t *testing.T) {
	type args struct {
		url      string
		artifact string
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
				url:      "/known/artifact/sha256:625fe537a4c1657bd613be44f7882a8883c13c3b72919cfdbd02d2eb4dbf677b",
				artifact: "sha256:625fe537a4c1657bd613be44f7882a8883c13c3b72919cfdbd02d2eb4dbf677b",
			},
			wantStatusCode: 200,
			wantBody:       "ok",
		},
	}

	r := gin.Default()
	ctx := context.Background()

	r.GET("/known/artifact/*artifact", artifactHandlerForArtifact(ctx))

	ts := httptest.NewServer(r)
	defer ts.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.args.url, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			resp, err := http.Get(ts.URL + tt.args.url)
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
			if diff := cmp.Diff(tt.wantBody, w.Body.String()); diff != "" {
				t.Errorf("body mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
