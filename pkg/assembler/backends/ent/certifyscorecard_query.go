// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/certifyscorecard"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
)

// CertifyScorecardQuery is the builder for querying CertifyScorecard entities.
type CertifyScorecardQuery struct {
	config
	ctx        *QueryContext
	order      []certifyscorecard.OrderOption
	inters     []Interceptor
	predicates []predicate.CertifyScorecard
	withSource *SourceNameQuery
	modifiers  []func(*sql.Selector)
	loadTotal  []func(context.Context, []*CertifyScorecard) error
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the CertifyScorecardQuery builder.
func (csq *CertifyScorecardQuery) Where(ps ...predicate.CertifyScorecard) *CertifyScorecardQuery {
	csq.predicates = append(csq.predicates, ps...)
	return csq
}

// Limit the number of records to be returned by this query.
func (csq *CertifyScorecardQuery) Limit(limit int) *CertifyScorecardQuery {
	csq.ctx.Limit = &limit
	return csq
}

// Offset to start from.
func (csq *CertifyScorecardQuery) Offset(offset int) *CertifyScorecardQuery {
	csq.ctx.Offset = &offset
	return csq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (csq *CertifyScorecardQuery) Unique(unique bool) *CertifyScorecardQuery {
	csq.ctx.Unique = &unique
	return csq
}

// Order specifies how the records should be ordered.
func (csq *CertifyScorecardQuery) Order(o ...certifyscorecard.OrderOption) *CertifyScorecardQuery {
	csq.order = append(csq.order, o...)
	return csq
}

// QuerySource chains the current query on the "source" edge.
func (csq *CertifyScorecardQuery) QuerySource() *SourceNameQuery {
	query := (&SourceNameClient{config: csq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := csq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := csq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(certifyscorecard.Table, certifyscorecard.FieldID, selector),
			sqlgraph.To(sourcename.Table, sourcename.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, false, certifyscorecard.SourceTable, certifyscorecard.SourceColumn),
		)
		fromU = sqlgraph.SetNeighbors(csq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first CertifyScorecard entity from the query.
// Returns a *NotFoundError when no CertifyScorecard was found.
func (csq *CertifyScorecardQuery) First(ctx context.Context) (*CertifyScorecard, error) {
	nodes, err := csq.Limit(1).All(setContextOp(ctx, csq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{certifyscorecard.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (csq *CertifyScorecardQuery) FirstX(ctx context.Context) *CertifyScorecard {
	node, err := csq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first CertifyScorecard ID from the query.
// Returns a *NotFoundError when no CertifyScorecard ID was found.
func (csq *CertifyScorecardQuery) FirstID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = csq.Limit(1).IDs(setContextOp(ctx, csq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{certifyscorecard.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (csq *CertifyScorecardQuery) FirstIDX(ctx context.Context) uuid.UUID {
	id, err := csq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single CertifyScorecard entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one CertifyScorecard entity is found.
// Returns a *NotFoundError when no CertifyScorecard entities are found.
func (csq *CertifyScorecardQuery) Only(ctx context.Context) (*CertifyScorecard, error) {
	nodes, err := csq.Limit(2).All(setContextOp(ctx, csq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{certifyscorecard.Label}
	default:
		return nil, &NotSingularError{certifyscorecard.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (csq *CertifyScorecardQuery) OnlyX(ctx context.Context) *CertifyScorecard {
	node, err := csq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only CertifyScorecard ID in the query.
// Returns a *NotSingularError when more than one CertifyScorecard ID is found.
// Returns a *NotFoundError when no entities are found.
func (csq *CertifyScorecardQuery) OnlyID(ctx context.Context) (id uuid.UUID, err error) {
	var ids []uuid.UUID
	if ids, err = csq.Limit(2).IDs(setContextOp(ctx, csq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{certifyscorecard.Label}
	default:
		err = &NotSingularError{certifyscorecard.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (csq *CertifyScorecardQuery) OnlyIDX(ctx context.Context) uuid.UUID {
	id, err := csq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of CertifyScorecards.
func (csq *CertifyScorecardQuery) All(ctx context.Context) ([]*CertifyScorecard, error) {
	ctx = setContextOp(ctx, csq.ctx, "All")
	if err := csq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*CertifyScorecard, *CertifyScorecardQuery]()
	return withInterceptors[[]*CertifyScorecard](ctx, csq, qr, csq.inters)
}

// AllX is like All, but panics if an error occurs.
func (csq *CertifyScorecardQuery) AllX(ctx context.Context) []*CertifyScorecard {
	nodes, err := csq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of CertifyScorecard IDs.
func (csq *CertifyScorecardQuery) IDs(ctx context.Context) (ids []uuid.UUID, err error) {
	if csq.ctx.Unique == nil && csq.path != nil {
		csq.Unique(true)
	}
	ctx = setContextOp(ctx, csq.ctx, "IDs")
	if err = csq.Select(certifyscorecard.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (csq *CertifyScorecardQuery) IDsX(ctx context.Context) []uuid.UUID {
	ids, err := csq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (csq *CertifyScorecardQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, csq.ctx, "Count")
	if err := csq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, csq, querierCount[*CertifyScorecardQuery](), csq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (csq *CertifyScorecardQuery) CountX(ctx context.Context) int {
	count, err := csq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (csq *CertifyScorecardQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, csq.ctx, "Exist")
	switch _, err := csq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (csq *CertifyScorecardQuery) ExistX(ctx context.Context) bool {
	exist, err := csq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the CertifyScorecardQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (csq *CertifyScorecardQuery) Clone() *CertifyScorecardQuery {
	if csq == nil {
		return nil
	}
	return &CertifyScorecardQuery{
		config:     csq.config,
		ctx:        csq.ctx.Clone(),
		order:      append([]certifyscorecard.OrderOption{}, csq.order...),
		inters:     append([]Interceptor{}, csq.inters...),
		predicates: append([]predicate.CertifyScorecard{}, csq.predicates...),
		withSource: csq.withSource.Clone(),
		// clone intermediate query.
		sql:  csq.sql.Clone(),
		path: csq.path,
	}
}

// WithSource tells the query-builder to eager-load the nodes that are connected to
// the "source" edge. The optional arguments are used to configure the query builder of the edge.
func (csq *CertifyScorecardQuery) WithSource(opts ...func(*SourceNameQuery)) *CertifyScorecardQuery {
	query := (&SourceNameClient{config: csq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	csq.withSource = query
	return csq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		SourceID uuid.UUID `json:"source_id,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.CertifyScorecard.Query().
//		GroupBy(certifyscorecard.FieldSourceID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (csq *CertifyScorecardQuery) GroupBy(field string, fields ...string) *CertifyScorecardGroupBy {
	csq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &CertifyScorecardGroupBy{build: csq}
	grbuild.flds = &csq.ctx.Fields
	grbuild.label = certifyscorecard.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		SourceID uuid.UUID `json:"source_id,omitempty"`
//	}
//
//	client.CertifyScorecard.Query().
//		Select(certifyscorecard.FieldSourceID).
//		Scan(ctx, &v)
func (csq *CertifyScorecardQuery) Select(fields ...string) *CertifyScorecardSelect {
	csq.ctx.Fields = append(csq.ctx.Fields, fields...)
	sbuild := &CertifyScorecardSelect{CertifyScorecardQuery: csq}
	sbuild.label = certifyscorecard.Label
	sbuild.flds, sbuild.scan = &csq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a CertifyScorecardSelect configured with the given aggregations.
func (csq *CertifyScorecardQuery) Aggregate(fns ...AggregateFunc) *CertifyScorecardSelect {
	return csq.Select().Aggregate(fns...)
}

func (csq *CertifyScorecardQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range csq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, csq); err != nil {
				return err
			}
		}
	}
	for _, f := range csq.ctx.Fields {
		if !certifyscorecard.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if csq.path != nil {
		prev, err := csq.path(ctx)
		if err != nil {
			return err
		}
		csq.sql = prev
	}
	return nil
}

func (csq *CertifyScorecardQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*CertifyScorecard, error) {
	var (
		nodes       = []*CertifyScorecard{}
		_spec       = csq.querySpec()
		loadedTypes = [1]bool{
			csq.withSource != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*CertifyScorecard).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &CertifyScorecard{config: csq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(csq.modifiers) > 0 {
		_spec.Modifiers = csq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, csq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := csq.withSource; query != nil {
		if err := csq.loadSource(ctx, query, nodes, nil,
			func(n *CertifyScorecard, e *SourceName) { n.Edges.Source = e }); err != nil {
			return nil, err
		}
	}
	for i := range csq.loadTotal {
		if err := csq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (csq *CertifyScorecardQuery) loadSource(ctx context.Context, query *SourceNameQuery, nodes []*CertifyScorecard, init func(*CertifyScorecard), assign func(*CertifyScorecard, *SourceName)) error {
	ids := make([]uuid.UUID, 0, len(nodes))
	nodeids := make(map[uuid.UUID][]*CertifyScorecard)
	for i := range nodes {
		fk := nodes[i].SourceID
		if _, ok := nodeids[fk]; !ok {
			ids = append(ids, fk)
		}
		nodeids[fk] = append(nodeids[fk], nodes[i])
	}
	if len(ids) == 0 {
		return nil
	}
	query.Where(sourcename.IDIn(ids...))
	neighbors, err := query.All(ctx)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nodeids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected foreign-key "source_id" returned %v`, n.ID)
		}
		for i := range nodes {
			assign(nodes[i], n)
		}
	}
	return nil
}

func (csq *CertifyScorecardQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := csq.querySpec()
	if len(csq.modifiers) > 0 {
		_spec.Modifiers = csq.modifiers
	}
	_spec.Node.Columns = csq.ctx.Fields
	if len(csq.ctx.Fields) > 0 {
		_spec.Unique = csq.ctx.Unique != nil && *csq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, csq.driver, _spec)
}

func (csq *CertifyScorecardQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(certifyscorecard.Table, certifyscorecard.Columns, sqlgraph.NewFieldSpec(certifyscorecard.FieldID, field.TypeUUID))
	_spec.From = csq.sql
	if unique := csq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if csq.path != nil {
		_spec.Unique = true
	}
	if fields := csq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, certifyscorecard.FieldID)
		for i := range fields {
			if fields[i] != certifyscorecard.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
		if csq.withSource != nil {
			_spec.Node.AddColumnOnce(certifyscorecard.FieldSourceID)
		}
	}
	if ps := csq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := csq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := csq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := csq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (csq *CertifyScorecardQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(csq.driver.Dialect())
	t1 := builder.Table(certifyscorecard.Table)
	columns := csq.ctx.Fields
	if len(columns) == 0 {
		columns = certifyscorecard.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if csq.sql != nil {
		selector = csq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if csq.ctx.Unique != nil && *csq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range csq.predicates {
		p(selector)
	}
	for _, p := range csq.order {
		p(selector)
	}
	if offset := csq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := csq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// CertifyScorecardGroupBy is the group-by builder for CertifyScorecard entities.
type CertifyScorecardGroupBy struct {
	selector
	build *CertifyScorecardQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (csgb *CertifyScorecardGroupBy) Aggregate(fns ...AggregateFunc) *CertifyScorecardGroupBy {
	csgb.fns = append(csgb.fns, fns...)
	return csgb
}

// Scan applies the selector query and scans the result into the given value.
func (csgb *CertifyScorecardGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, csgb.build.ctx, "GroupBy")
	if err := csgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*CertifyScorecardQuery, *CertifyScorecardGroupBy](ctx, csgb.build, csgb, csgb.build.inters, v)
}

func (csgb *CertifyScorecardGroupBy) sqlScan(ctx context.Context, root *CertifyScorecardQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(csgb.fns))
	for _, fn := range csgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*csgb.flds)+len(csgb.fns))
		for _, f := range *csgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*csgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := csgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// CertifyScorecardSelect is the builder for selecting fields of CertifyScorecard entities.
type CertifyScorecardSelect struct {
	*CertifyScorecardQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (css *CertifyScorecardSelect) Aggregate(fns ...AggregateFunc) *CertifyScorecardSelect {
	css.fns = append(css.fns, fns...)
	return css
}

// Scan applies the selector query and scans the result into the given value.
func (css *CertifyScorecardSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, css.ctx, "Select")
	if err := css.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*CertifyScorecardQuery, *CertifyScorecardSelect](ctx, css.CertifyScorecardQuery, css, css.inters, v)
}

func (css *CertifyScorecardSelect) sqlScan(ctx context.Context, root *CertifyScorecardQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(css.fns))
	for _, fn := range css.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*css.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := css.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
