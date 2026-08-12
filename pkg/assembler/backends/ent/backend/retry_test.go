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

package backend

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestIsPGForeignKeyViolation(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "plain error",
			err:  errors.New("some other failure"),
			want: false,
		},
		{
			name: "pq foreign_key_violation by value",
			err:  &pq.Error{Code: "23503"},
			want: true,
		},
		{
			name: "pq unique_violation is not retryable here",
			err:  &pq.Error{Code: "23505"},
			want: false,
		},
		{
			name: "pq check_violation is not retryable here",
			err:  &pq.Error{Code: "23514"},
			want: false,
		},
		{
			name: "wrapped pq foreign_key_violation",
			err:  fmt.Errorf("bulk upsert pkgVersion node: %w", &pq.Error{Code: "23503"}),
			want: true,
		},
		{
			name: "doubly-wrapped pq foreign_key_violation",
			err:  fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", &pq.Error{Code: "23503"})),
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPGForeignKeyViolation(tc.err); got != tc.want {
				t.Fatalf("isPGForeignKeyViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetryOnFKViolation_SuccessFirstAttempt(t *testing.T) {
	calls := 0
	err := retryOnFKViolation(context.Background(), func() error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("want nil err, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("want 1 call, got %d", calls)
	}
}

func TestRetryOnFKViolation_NonRetryableErrorPropagates(t *testing.T) {
	calls := 0
	sentinel := errors.New("not a pq error")
	err := retryOnFKViolation(context.Background(), func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel err, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("want 1 call (no retry on non-FK), got %d", calls)
	}
}

func TestRetryOnFKViolation_UniqueViolationNotRetried(t *testing.T) {
	calls := 0
	err := retryOnFKViolation(context.Background(), func() error {
		calls++
		return &pq.Error{Code: "23505"}
	})
	if err == nil {
		t.Fatalf("want err, got nil")
	}
	if calls != 1 {
		t.Fatalf("want 1 call (unique violation not retried), got %d", calls)
	}
}

func TestRetryOnFKViolation_RecoversAfterTransientFK(t *testing.T) {
	calls := 0
	err := retryOnFKViolation(context.Background(), func() error {
		calls++
		if calls < 2 {
			return &pq.Error{Code: "23503"}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("want nil err after recovery, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("want 2 calls (one retry), got %d", calls)
	}
}

func TestRetryOnFKViolation_GivesUpAfterMaxAttempts(t *testing.T) {
	calls := 0
	err := retryOnFKViolation(context.Background(), func() error {
		calls++
		return &pq.Error{Code: "23503"}
	})
	if err == nil {
		t.Fatalf("want err after exhausting retries")
	}
	if !isPGForeignKeyViolation(err) {
		t.Fatalf("want final err to be FK violation, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("want 3 calls (initial + 2 retries), got %d", calls)
	}
}

func TestRetryOnFKViolation_HonorsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	calls := 0
	start := time.Now()
	err := retryOnFKViolation(ctx, func() error {
		calls++
		return &pq.Error{Code: "23503"}
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("want err from cancelled context")
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("cancellation should abort fast, elapsed=%v", elapsed)
	}
	if calls < 1 {
		t.Fatalf("want at least one attempt, got %d", calls)
	}
}
