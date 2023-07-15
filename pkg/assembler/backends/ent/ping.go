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
