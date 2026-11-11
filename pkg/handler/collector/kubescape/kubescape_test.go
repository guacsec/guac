//
// Copyright 2025 The GUAC Authors.
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

package kubescape

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/sbom"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/metrics"
	scv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestListSBOMs(t *testing.T) {
	restInClusterConfig = func() (*rest.Config, error) {
		return nil, nil
	}
	ksscNewForConfig = func(c *rest.Config) (*kssc.Clientset, error) {
		return nil, nil
	}
	var listCalled int
	list = func(ctx context.Context, sc *kssc.Clientset, ns string) (*scv1beta1.SBOMSPDXv2p3List, error) {
		listCalled++
		return &scv1beta1.SBOMSPDXv2p3List{
			Items: []scv1beta1.SBOMSPDXv2p3{{ObjectMeta: metav1.ObjectMeta{Name: "sbom1"}}},
		}, nil
	}
	var getCalled int
	var getCalledName string
	get = func(ctx context.Context, sc *kssc.Clientset, ns, name string) (*scv1beta1.SBOMSPDXv2p3, error) {
		getCalled++
		getCalledName = name
		return &scv1beta1.SBOMSPDXv2p3{
			ObjectMeta: metav1.ObjectMeta{Name: "sbom1"},
			Spec: scv1beta1.SBOMSPDXv2p3Spec{
				SPDX: scv1beta1.Document{},
			},
		}, nil
	}
	formatDecode = func(reader io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
		return &sbom.SBOM{}, "", "", nil
	}
	formatEncode = func(s sbom.SBOM, f sbom.FormatEncoder) ([]byte, error) {
		return nil, nil
	}

	c := New(Config{
		Watch: false,
	})
	dc := make(chan *processor.Document, 100)
	err := c.RetrieveArtifacts(context.Background(), dc)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	var docs []*processor.Document
	for d := range dc {
		docs = append(docs, d)
	}

	if len(docs) != 1 {
		t.Errorf("Did not get expected docs. Exp: 1 Got: %d", len(docs))
	}
	if listCalled != 1 {
		t.Errorf("Expected list to be called 1 time, Got: %d", listCalled)
	}
	if getCalled != 1 {
		t.Errorf("Expected get to be called 1 time, Got: %d", getCalled)
	}
	if getCalledName != "sbom1" {
		t.Errorf("Expected get to be called with sbom name 'sbom1', Got: %q", getCalledName)
	}
}

func TestWatch_RecordsSBOMErrorMetric(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"ADDED","object":{"apiVersion":"spdx.softwarecomposition.kubescape.io/v1beta1","kind":"SBOMSPDXv2p3","metadata":{"name":"sbom1"}}}` + "\n"))
	}))
	defer server.Close()

	sc, err := kssc.NewForConfig(&rest.Config{Host: server.URL})
	if err != nil {
		t.Fatalf("failed to create clientset: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	get = func(ctx context.Context, sc *kssc.Clientset, ns, name string) (*scv1beta1.SBOMSPDXv2p3, error) {
		cancel()
		return nil, errors.New("get failed")
	}

	ctx = metrics.WithMetrics(ctx, "kubescape_test")
	mc := metrics.FromContext(ctx, "kubescape_test")
	counter, err := mc.RegisterCounter(ctx, SBOMErrorsCounter)
	if err != nil {
		t.Fatalf("failed to register counter: %v", err)
	}

	c := New(Config{Watch: true, Namespace: "ns"}, WithMetrics(mc))
	dc := make(chan *processor.Document, 1)
	if err := c.watch(ctx, dc, sc); err != nil {
		t.Fatalf("watch() error = %v", err)
	}

	counterVec, ok := counter.(prometheus.Collector)
	if !ok {
		t.Fatal("counter should implement prometheus.Collector")
	}
	if err := testutil.CollectAndCompare(counterVec, strings.NewReader(`
		# HELP guac_kubescape_test_kubescape_sbom_errors Counter for kubescape_test_kubescape_sbom_errors
		# TYPE guac_kubescape_test_kubescape_sbom_errors counter
		guac_kubescape_test_kubescape_sbom_errors 1
	`)); err != nil {
		t.Errorf("unexpected metric state: %v", err)
	}
}
