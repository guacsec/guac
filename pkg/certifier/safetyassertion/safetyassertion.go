//
// Copyright 2026 The GUAC Authors.
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

// Package safetyassertion reconciles externally authored safety assertions with
// existing package versions through GUAC's GraphQL API.
package safetyassertion

import (
	"context"
	"fmt"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/certifier"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type Reconciler struct {
	client   graphql.Client
	pageSize int
}

var _ certifier.Certifier = (*Reconciler)(nil)
var _ certifier.QueryComponents = (*Reconciler)(nil)

func New(client graphql.Client, pageSize int) (*Reconciler, error) {
	if client == nil || pageSize <= 0 {
		return nil, fmt.Errorf("a GraphQL client and positive page size are required")
	}
	return &Reconciler{client: client, pageSize: pageSize}, nil
}

// pages visits every assertion, including previous matches, so expiry, added
// candidates, and newly observed digest conflicts are eventually re-evaluated.
// The query deliberately does not filter by the state being changed by the run.
func (r *Reconciler) pages(ctx context.Context, visit func([]string) error) error {
	var after *string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		response, err := generated.SafetyAssertionCandidates(ctx, r.client, after, &r.pageSize)
		if err != nil {
			return fmt.Errorf("query safety assertion candidates: %w", err)
		}
		connection := response.SafetyAssertionList
		if connection == nil {
			return fmt.Errorf("safety assertion candidate connection is missing")
		}
		ids := make([]string, 0, len(connection.Edges))
		for _, edge := range connection.Edges {
			ids = append(ids, edge.Node.Id)
		}
		if err := visit(ids); err != nil {
			return err
		}
		if !connection.PageInfo.HasNextPage {
			return nil
		}
		next := connection.PageInfo.EndCursor
		if next == nil || *next == "" || (after != nil && *next == *after) {
			return fmt.Errorf("safety assertion pagination did not advance")
		}
		after = next
	}
}

func (r *Reconciler) GetComponents(ctx context.Context, out chan<- interface{}) error {
	if out == nil {
		return fmt.Errorf("component channel is required")
	}
	return r.pages(ctx, func(ids []string) error {
		if len(ids) == 0 {
			return nil
		}
		select {
		case out <- ids:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

// CertifyComponent updates only correlation data. It emits no new externally
// authored safety document and never changes an assertion's decision state.
func (r *Reconciler) CertifyComponent(ctx context.Context, components interface{}, _ chan<- *processor.Document) error {
	ids, ok := components.([]string)
	if !ok {
		return fmt.Errorf("expected safety assertion IDs")
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := generated.ReconcileSafetyAssertion(ctx, r.client, id); err != nil {
			return fmt.Errorf("reconcile safety assertion %s: %w", id, err)
		}
	}
	return nil
}

func (r *Reconciler) RunOnce(ctx context.Context) error {
	return r.pages(ctx, func(ids []string) error { return r.CertifyComponent(ctx, ids, nil) })
}

// Run supports one-shot use after ingestion or periodic reconciliation. Every
// query/mutation failure is propagated; cancellation interrupts in-flight work.
func (r *Reconciler) Run(ctx context.Context, poll bool, interval time.Duration) error {
	if poll && interval <= 0 {
		return fmt.Errorf("polling requires a positive interval")
	}
	if err := r.RunOnce(ctx); err != nil {
		return err
	}
	if !poll {
		return nil
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil {
				return err
			}
		}
	}
}
