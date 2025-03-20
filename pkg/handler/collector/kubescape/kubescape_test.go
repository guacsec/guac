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
	"io"
	"testing"

	"github.com/anchore/syft/syft/sbom"
	"github.com/guacsec/guac/pkg/handler/processor"
	scv1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	kssc "github.com/kubescape/storage/pkg/generated/clientset/versioned"
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
	list = func(ctx context.Context, sc *kssc.Clientset, ns string) (*scv1beta1.SBOMSyftList, error) {
		listCalled++
		return &scv1beta1.SBOMSyftList{
			Items: []scv1beta1.SBOMSyft{{ObjectMeta: metav1.ObjectMeta{Name: "sbom1"}}},
		}, nil
	}
	var getCalled int
	var getCalledName string
	get = func(ctx context.Context, sc *kssc.Clientset, ns, name string) (*scv1beta1.SBOMSyft, error) {
		getCalled++
		getCalledName = name
		return &scv1beta1.SBOMSyft{
			ObjectMeta: metav1.ObjectMeta{Name: "sbom1"},
			Spec: scv1beta1.SBOMSyftSpec{
				Syft: scv1beta1.SyftDocument{},
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
