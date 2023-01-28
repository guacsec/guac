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

package metrics

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestNewPrometheus(t *testing.T) {
	test := struct {
		name string
		want Metrics
	}{
		name: "default",
		want: &prom{
			counters: make(map[string]prometheus.Counter),
			summary:  make(map[string]prometheus.Summary),
		},
	}
	t.Run(test.name, func(t *testing.T) {
		if got := NewPrometheus(); !reflect.DeepEqual(got, test.want) {
			t.Errorf("NewPrometheus() = %v, want %v", got, test.want)
		}
	})

}

func Test_prom_NewCounter(t *testing.T) {
	type fields struct {
		counters map[string]prometheus.Counter
		summary  map[string]prometheus.Summary
	}
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "default",
			fields: fields{
				counters: make(map[string]prometheus.Counter),
				summary:  make(map[string]prometheus.Summary),
			},
			args:    args{name: "test"},
			wantErr: false,
		},
		{
			name: "default",
			fields: fields{
				counters: make(map[string]prometheus.Counter),
				summary:  make(map[string]prometheus.Summary),
			},
			args:    args{name: "test"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stop := make(chan struct{})
			p := &prom{
				counters: tt.fields.counters,
				summary:  tt.fields.summary,
			}
			// this is a hack to make the test pass when the counter already exists
			if tt.wantErr {
				p.counters[tt.args.name] = prometheus.NewCounter(prometheus.CounterOpts{})
			}
			if err := p.NewCounter(tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("NewCounter() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// start a server to get the metrics
			http.Handle(
				"/summary",
				promhttp.Handler(),
			)
			go func() {
				err := http.ListenAndServe(":2113", nil)
				if err != nil {
					fmt.Println(err)
				}
				close(stop)
			}()
			//increment the counter
			p.IncrementCounter(tt.args.name)
			// wait for the server to start
			time.Sleep(1 * time.Second)
			// get the metrics
			resp, err := http.Get("http://localhost:2113/summary")
			if err != nil {
				t.Errorf("error getting metrics: %v", err)
			}
			body, err := httputil.DumpResponse(resp, true)
			if err != nil {
				t.Errorf("error reading response: %v", err)
			}
			found := false
			for _, line := range strings.Split(string(body), "\n") {
				if strings.Contains(line, fmt.Sprintf("%s_total", tt.args.name)) {
					found = true
				}
			}
			if !found {
				t.Errorf("counter not found: %v", tt.args.name)
			}
		})
	}
}

func Test_prom_NewSummary(t *testing.T) {
	type fields struct {
		counters map[string]prometheus.Counter
		summary  map[string]prometheus.Summary
	}
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "default",
			fields: fields{
				counters: make(map[string]prometheus.Counter),
				summary:  make(map[string]prometheus.Summary),
			},
			args:    args{name: "test"},
			wantErr: false,
		},
		{
			name: "default",
			fields: fields{
				counters: make(map[string]prometheus.Counter),
				summary:  make(map[string]prometheus.Summary),
			},
			args:    args{name: "test"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		stop := make(chan struct{})
		t.Run(tt.name, func(t *testing.T) {
			p := &prom{
				counters: tt.fields.counters,
				summary:  tt.fields.summary,
			}
			// this is a hack to make the test pass when the summary already exists
			if tt.wantErr {
				p.summary[tt.args.name] = prometheus.NewSummary(prometheus.SummaryOpts{})
			}
			if err := p.NewSummary(tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("NewSummary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// start a server to get the metrics
			http.Handle(
				"/metrics",
				promhttp.Handler(),
			)
			go func() {
				err := http.ListenAndServe(":2112", nil)
				if err != nil {
					fmt.Println(err)
				}
				close(stop)
			}()
			//increment the summary
			p.ObserveSummary(tt.args.name, 1)
			// wait for the server to start
			time.Sleep(1 * time.Second)
			// get the metrics
			resp, err := http.Get("http://localhost:2112/metrics")
			if err != nil {
				t.Errorf("error getting metrics: %v", err)
			}
			body, err := httputil.DumpResponse(resp, true)
			if err != nil {
				t.Errorf("error reading response: %v", err)
			}
			found := false
			for _, line := range strings.Split(string(body), "\n") {
				if strings.Contains(line, fmt.Sprintf("%s_sum", tt.args.name)) {
					found = true
				}
			}
			if !found {
				t.Errorf("summary not found: %v", tt.args.name)
			}
			close(stop)
		})
	}
}
