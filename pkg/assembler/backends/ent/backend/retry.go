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
	"time"

	"github.com/lib/pq"
)

// pgForeignKeyViolationCode is PostgreSQL SQLSTATE 23503 (foreign_key_violation).
// See https://www.postgresql.org/docs/current/errcodes-appendix.html.
const pgForeignKeyViolationCode = "23503"

// isPGForeignKeyViolation reports whether err (possibly wrapped) is a PostgreSQL
// foreign-key-violation error. It intentionally does not match other constraint
// classes (unique, check, not-null) because those are not expected to become
// valid on retry.
func isPGForeignKeyViolation(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	return string(pqErr.Code) == pgForeignKeyViolationCode
}

// fkRetryBackoffs controls sleep duration before each retry. Length determines
// max retries. Chosen to cover the ~1–2 s window in which rows committed by a
// sibling transaction typically become visible under production load.
var fkRetryBackoffs = []time.Duration{
	500 * time.Millisecond,
	1 * time.Second,
}

// retryOnFKViolation invokes fn and, on a PostgreSQL foreign-key violation,
// retries with bounded backoff. Non-FK errors propagate immediately.
// Honors ctx cancellation between attempts.
func retryOnFKViolation(ctx context.Context, fn func() error) error {
	err := fn()
	if !isPGForeignKeyViolation(err) {
		return err
	}
	for _, backoff := range fkRetryBackoffs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		err = fn()
		if !isPGForeignKeyViolation(err) {
			return err
		}
	}
	return err
}
