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

package ent

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
)

func (c *Client) Ping(ctx context.Context) error {
	driver, ok := c.driver.(*sql.Driver)
	if ok {
		return driver.DB().PingContext(ctx)
	}

	return fmt.Errorf("connection does not support Ping")
}
