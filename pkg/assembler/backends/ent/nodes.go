package ent

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/sync/semaphore"
)

type Noder interface {
	IsNode()
}

type tables struct {
	once  sync.Once
	sem   *semaphore.Weighted
	value atomic.Value
}

var errNodeInvalidID = &NotFoundError{"node"}

type nodeOptions struct {
	nodeType func(context.Context, int) (string, error)
}

// NodeOption allows configuring the Noder execution using functional options.
type NodeOption func(*nodeOptions)

// Noder returns a Node by its id. If the NodeType was not provided, it will
// be derived from the id value according to the universal-id configuration.
//
//	c.Noder(ctx, id)
//	c.Noder(ctx, id, ent.WithNodeType(typeResolver))
func (c *Client) Noder(ctx context.Context, id int, opts ...NodeOption) (_ Noder, err error) {
	defer func() {
		if IsNotFound(err) {
			err = multierror.Append(err, entgql.ErrNodeNotFound(id))
		}
	}()
	table, err := c.newNodeOpts(opts).nodeType(ctx, id)
	if err != nil {
		return nil, err
	}
	return c.noder(ctx, table, id)
}

func (c *Client) newNodeOpts(opts []NodeOption) *nodeOptions {
	nopts := &nodeOptions{}
	for _, opt := range opts {
		opt(nopts)
	}
	if nopts.nodeType == nil {
		nopts.nodeType = func(ctx context.Context, id int) (string, error) {
			return c.tables.nodeType(ctx, c.driver, id)
		}
	}
	return nopts
}

func (t *tables) nodeType(ctx context.Context, drv dialect.Driver, id int) (string, error) {
	tables, err := t.Load(ctx, drv)
	if err != nil {
		return "", err
	}
	idx := int64(int64(id) / (1<<32 - 1))
	if idx < 0 || idx >= int64(len(tables)) {
		return "", fmt.Errorf("cannot resolve table from id %v: %w", id, errNodeInvalidID)
	}
	return tables[idx], nil
}

func (t *tables) Load(ctx context.Context, drv dialect.Driver) ([]string, error) {
	if tables := t.value.Load(); tables != nil {
		return tables.([]string), nil
	}
	t.once.Do(func() { t.sem = semaphore.NewWeighted(1) })
	if err := t.sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer t.sem.Release(1)
	if tables := t.value.Load(); tables != nil {
		return tables.([]string), nil
	}
	tables, err := t.load(ctx, drv)
	if err == nil {
		t.value.Store(tables)
	}
	return tables, err
}

func (*tables) load(ctx context.Context, drv dialect.Driver) ([]string, error) {
	rows := &sql.Rows{}
	query, args := sql.Dialect(drv.Dialect()).
		Select("type").
		From(sql.Table(schema.TypeTable)).
		OrderBy(sql.Asc("id")).
		Query()
	if err := drv.Query(ctx, query, args, rows); err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	return tables, sql.ScanSlice(rows, &tables)
}
