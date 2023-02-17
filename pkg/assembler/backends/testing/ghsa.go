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

package testing

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

func registerAllGHSA(client *demoClient) {
	client.registerGhsa("GHSA-h45f-rjvw-2rv2")
	client.registerGhsa("GHSA-xrw3-wqph-3fxg")
	client.registerGhsa("GHSA-8v4j-7jgf-5rg9")
	client.registerGhsa("GHSA-h45f-rjvw-2rv2")
	client.registerGhsa("GHSA-h45f-rjvw-2rv2")
}

// Ingest GHSA

func (c *demoClient) registerGhsa(id string) {
	for i, g := range c.ghsa {
		c.ghsa[i] = registerGhsaID(g, id)
		return
	}

	newGhsa := &model.Ghsa{}
	newGhsa = registerGhsaID(newGhsa, id)
	c.ghsa = append(c.ghsa, newGhsa)
}

func registerGhsaID(g *model.Ghsa, id string) *model.Ghsa {
	for _, cveID := range g.GhsaID {
		if cveID.ID == id {
			return g
		}
	}

	g.GhsaID = append(g.GhsaID, &model.GHSAId{ID: id})
	return g
}

// Query GHSA

func (c *demoClient) Ghsa(ctx context.Context, ghsaSpec *model.GHSASpec) ([]*model.Ghsa, error) {
	var ghsa []*model.Ghsa
	for _, g := range c.ghsa {
		newGHSA, err := filterGHSAID(g, ghsaSpec)
		if err != nil {
			return nil, err
		}
		if newGHSA != nil {
			ghsa = append(ghsa, newGHSA)
		}
	}
	return ghsa, nil
}

func filterGHSAID(ghsa *model.Ghsa, ghsaSpec *model.GHSASpec) (*model.Ghsa, error) {
	var ghsaID []*model.GHSAId
	for _, id := range ghsa.GhsaID {
		if ghsaSpec.GhsaID == nil || id.ID == *ghsaSpec.GhsaID {
			ghsaID = append(ghsaID, id)
		}
	}
	if len(ghsaID) == 0 {
		return nil, nil
	}
	return &model.Ghsa{
		GhsaID: ghsaID,
	}, nil
}
