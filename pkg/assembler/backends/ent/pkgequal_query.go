// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"database/sql/driver"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/pkgequal"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/predicate"
)

// PkgEqualQuery is the builder for querying PkgEqual entities.
type PkgEqualQuery struct {
	config
	ctx               *QueryContext
	order             []pkgequal.OrderOption
	inters            []Interceptor
	predicates        []predicate.PkgEqual
	withPackages      *PackageVersionQuery
	modifiers         []func(*sql.Selector)
	loadTotal         []func(context.Context, []*PkgEqual) error
	withNamedPackages map[string]*PackageVersionQuery
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the PkgEqualQuery builder.
func (peq *PkgEqualQuery) Where(ps ...predicate.PkgEqual) *PkgEqualQuery {
	peq.predicates = append(peq.predicates, ps...)
	return peq
}

// Limit the number of records to be returned by this query.
func (peq *PkgEqualQuery) Limit(limit int) *PkgEqualQuery {
	peq.ctx.Limit = &limit
	return peq
}

// Offset to start from.
func (peq *PkgEqualQuery) Offset(offset int) *PkgEqualQuery {
	peq.ctx.Offset = &offset
	return peq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (peq *PkgEqualQuery) Unique(unique bool) *PkgEqualQuery {
	peq.ctx.Unique = &unique
	return peq
}

// Order specifies how the records should be ordered.
func (peq *PkgEqualQuery) Order(o ...pkgequal.OrderOption) *PkgEqualQuery {
	peq.order = append(peq.order, o...)
	return peq
}

// QueryPackages chains the current query on the "packages" edge.
func (peq *PkgEqualQuery) QueryPackages() *PackageVersionQuery {
	query := (&PackageVersionClient{config: peq.config}).Query()
	query.path = func(ctx context.Context) (fromU *sql.Selector, err error) {
		if err := peq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		selector := peq.sqlQuery(ctx)
		if err := selector.Err(); err != nil {
			return nil, err
		}
		step := sqlgraph.NewStep(
			sqlgraph.From(pkgequal.Table, pkgequal.FieldID, selector),
			sqlgraph.To(packageversion.Table, packageversion.FieldID),
			sqlgraph.Edge(sqlgraph.M2M, false, pkgequal.PackagesTable, pkgequal.PackagesPrimaryKey...),
		)
		fromU = sqlgraph.SetNeighbors(peq.driver.Dialect(), step)
		return fromU, nil
	}
	return query
}

// First returns the first PkgEqual entity from the query.
// Returns a *NotFoundError when no PkgEqual was found.
func (peq *PkgEqualQuery) First(ctx context.Context) (*PkgEqual, error) {
	nodes, err := peq.Limit(1).All(setContextOp(ctx, peq.ctx, "First"))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{pkgequal.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (peq *PkgEqualQuery) FirstX(ctx context.Context) *PkgEqual {
	node, err := peq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first PkgEqual ID from the query.
// Returns a *NotFoundError when no PkgEqual ID was found.
func (peq *PkgEqualQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = peq.Limit(1).IDs(setContextOp(ctx, peq.ctx, "FirstID")); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{pkgequal.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (peq *PkgEqualQuery) FirstIDX(ctx context.Context) int {
	id, err := peq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single PkgEqual entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one PkgEqual entity is found.
// Returns a *NotFoundError when no PkgEqual entities are found.
func (peq *PkgEqualQuery) Only(ctx context.Context) (*PkgEqual, error) {
	nodes, err := peq.Limit(2).All(setContextOp(ctx, peq.ctx, "Only"))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{pkgequal.Label}
	default:
		return nil, &NotSingularError{pkgequal.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (peq *PkgEqualQuery) OnlyX(ctx context.Context) *PkgEqual {
	node, err := peq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only PkgEqual ID in the query.
// Returns a *NotSingularError when more than one PkgEqual ID is found.
// Returns a *NotFoundError when no entities are found.
func (peq *PkgEqualQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = peq.Limit(2).IDs(setContextOp(ctx, peq.ctx, "OnlyID")); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{pkgequal.Label}
	default:
		err = &NotSingularError{pkgequal.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (peq *PkgEqualQuery) OnlyIDX(ctx context.Context) int {
	id, err := peq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of PkgEquals.
func (peq *PkgEqualQuery) All(ctx context.Context) ([]*PkgEqual, error) {
	ctx = setContextOp(ctx, peq.ctx, "All")
	if err := peq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*PkgEqual, *PkgEqualQuery]()
	return withInterceptors[[]*PkgEqual](ctx, peq, qr, peq.inters)
}

// AllX is like All, but panics if an error occurs.
func (peq *PkgEqualQuery) AllX(ctx context.Context) []*PkgEqual {
	nodes, err := peq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of PkgEqual IDs.
func (peq *PkgEqualQuery) IDs(ctx context.Context) (ids []int, err error) {
	if peq.ctx.Unique == nil && peq.path != nil {
		peq.Unique(true)
	}
	ctx = setContextOp(ctx, peq.ctx, "IDs")
	if err = peq.Select(pkgequal.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (peq *PkgEqualQuery) IDsX(ctx context.Context) []int {
	ids, err := peq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (peq *PkgEqualQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, peq.ctx, "Count")
	if err := peq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, peq, querierCount[*PkgEqualQuery](), peq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (peq *PkgEqualQuery) CountX(ctx context.Context) int {
	count, err := peq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (peq *PkgEqualQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, peq.ctx, "Exist")
	switch _, err := peq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (peq *PkgEqualQuery) ExistX(ctx context.Context) bool {
	exist, err := peq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the PkgEqualQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (peq *PkgEqualQuery) Clone() *PkgEqualQuery {
	if peq == nil {
		return nil
	}
	return &PkgEqualQuery{
		config:       peq.config,
		ctx:          peq.ctx.Clone(),
		order:        append([]pkgequal.OrderOption{}, peq.order...),
		inters:       append([]Interceptor{}, peq.inters...),
		predicates:   append([]predicate.PkgEqual{}, peq.predicates...),
		withPackages: peq.withPackages.Clone(),
		// clone intermediate query.
		sql:  peq.sql.Clone(),
		path: peq.path,
	}
}

// WithPackages tells the query-builder to eager-load the nodes that are connected to
// the "packages" edge. The optional arguments are used to configure the query builder of the edge.
func (peq *PkgEqualQuery) WithPackages(opts ...func(*PackageVersionQuery)) *PkgEqualQuery {
	query := (&PackageVersionClient{config: peq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	peq.withPackages = query
	return peq
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Origin string `json:"origin,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.PkgEqual.Query().
//		GroupBy(pkgequal.FieldOrigin).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (peq *PkgEqualQuery) GroupBy(field string, fields ...string) *PkgEqualGroupBy {
	peq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &PkgEqualGroupBy{build: peq}
	grbuild.flds = &peq.ctx.Fields
	grbuild.label = pkgequal.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Origin string `json:"origin,omitempty"`
//	}
//
//	client.PkgEqual.Query().
//		Select(pkgequal.FieldOrigin).
//		Scan(ctx, &v)
func (peq *PkgEqualQuery) Select(fields ...string) *PkgEqualSelect {
	peq.ctx.Fields = append(peq.ctx.Fields, fields...)
	sbuild := &PkgEqualSelect{PkgEqualQuery: peq}
	sbuild.label = pkgequal.Label
	sbuild.flds, sbuild.scan = &peq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a PkgEqualSelect configured with the given aggregations.
func (peq *PkgEqualQuery) Aggregate(fns ...AggregateFunc) *PkgEqualSelect {
	return peq.Select().Aggregate(fns...)
}

func (peq *PkgEqualQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range peq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, peq); err != nil {
				return err
			}
		}
	}
	for _, f := range peq.ctx.Fields {
		if !pkgequal.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if peq.path != nil {
		prev, err := peq.path(ctx)
		if err != nil {
			return err
		}
		peq.sql = prev
	}
	return nil
}

func (peq *PkgEqualQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*PkgEqual, error) {
	var (
		nodes       = []*PkgEqual{}
		_spec       = peq.querySpec()
		loadedTypes = [1]bool{
			peq.withPackages != nil,
		}
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*PkgEqual).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &PkgEqual{config: peq.config}
		nodes = append(nodes, node)
		node.Edges.loadedTypes = loadedTypes
		return node.assignValues(columns, values)
	}
	if len(peq.modifiers) > 0 {
		_spec.Modifiers = peq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, peq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	if query := peq.withPackages; query != nil {
		if err := peq.loadPackages(ctx, query, nodes,
			func(n *PkgEqual) { n.Edges.Packages = []*PackageVersion{} },
			func(n *PkgEqual, e *PackageVersion) { n.Edges.Packages = append(n.Edges.Packages, e) }); err != nil {
			return nil, err
		}
	}
	for name, query := range peq.withNamedPackages {
		if err := peq.loadPackages(ctx, query, nodes,
			func(n *PkgEqual) { n.appendNamedPackages(name) },
			func(n *PkgEqual, e *PackageVersion) { n.appendNamedPackages(name, e) }); err != nil {
			return nil, err
		}
	}
	for i := range peq.loadTotal {
		if err := peq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (peq *PkgEqualQuery) loadPackages(ctx context.Context, query *PackageVersionQuery, nodes []*PkgEqual, init func(*PkgEqual), assign func(*PkgEqual, *PackageVersion)) error {
	edgeIDs := make([]driver.Value, len(nodes))
	byID := make(map[int]*PkgEqual)
	nids := make(map[int]map[*PkgEqual]struct{})
	for i, node := range nodes {
		edgeIDs[i] = node.ID
		byID[node.ID] = node
		if init != nil {
			init(node)
		}
	}
	query.Where(func(s *sql.Selector) {
		joinT := sql.Table(pkgequal.PackagesTable)
		s.Join(joinT).On(s.C(packageversion.FieldID), joinT.C(pkgequal.PackagesPrimaryKey[1]))
		s.Where(sql.InValues(joinT.C(pkgequal.PackagesPrimaryKey[0]), edgeIDs...))
		columns := s.SelectedColumns()
		s.Select(joinT.C(pkgequal.PackagesPrimaryKey[0]))
		s.AppendSelect(columns...)
		s.SetDistinct(false)
	})
	if err := query.prepareQuery(ctx); err != nil {
		return err
	}
	qr := QuerierFunc(func(ctx context.Context, q Query) (Value, error) {
		return query.sqlAll(ctx, func(_ context.Context, spec *sqlgraph.QuerySpec) {
			assign := spec.Assign
			values := spec.ScanValues
			spec.ScanValues = func(columns []string) ([]any, error) {
				values, err := values(columns[1:])
				if err != nil {
					return nil, err
				}
				return append([]any{new(sql.NullInt64)}, values...), nil
			}
			spec.Assign = func(columns []string, values []any) error {
				outValue := int(values[0].(*sql.NullInt64).Int64)
				inValue := int(values[1].(*sql.NullInt64).Int64)
				if nids[inValue] == nil {
					nids[inValue] = map[*PkgEqual]struct{}{byID[outValue]: {}}
					return assign(columns[1:], values[1:])
				}
				nids[inValue][byID[outValue]] = struct{}{}
				return nil
			}
		})
	})
	neighbors, err := withInterceptors[[]*PackageVersion](ctx, query, qr, query.inters)
	if err != nil {
		return err
	}
	for _, n := range neighbors {
		nodes, ok := nids[n.ID]
		if !ok {
			return fmt.Errorf(`unexpected "packages" node returned %v`, n.ID)
		}
		for kn := range nodes {
			assign(kn, n)
		}
	}
	return nil
}

func (peq *PkgEqualQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := peq.querySpec()
	if len(peq.modifiers) > 0 {
		_spec.Modifiers = peq.modifiers
	}
	_spec.Node.Columns = peq.ctx.Fields
	if len(peq.ctx.Fields) > 0 {
		_spec.Unique = peq.ctx.Unique != nil && *peq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, peq.driver, _spec)
}

func (peq *PkgEqualQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(pkgequal.Table, pkgequal.Columns, sqlgraph.NewFieldSpec(pkgequal.FieldID, field.TypeInt))
	_spec.From = peq.sql
	if unique := peq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if peq.path != nil {
		_spec.Unique = true
	}
	if fields := peq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, pkgequal.FieldID)
		for i := range fields {
			if fields[i] != pkgequal.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := peq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := peq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := peq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := peq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (peq *PkgEqualQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(peq.driver.Dialect())
	t1 := builder.Table(pkgequal.Table)
	columns := peq.ctx.Fields
	if len(columns) == 0 {
		columns = pkgequal.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if peq.sql != nil {
		selector = peq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if peq.ctx.Unique != nil && *peq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range peq.predicates {
		p(selector)
	}
	for _, p := range peq.order {
		p(selector)
	}
	if offset := peq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := peq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// WithNamedPackages tells the query-builder to eager-load the nodes that are connected to the "packages"
// edge with the given name. The optional arguments are used to configure the query builder of the edge.
func (peq *PkgEqualQuery) WithNamedPackages(name string, opts ...func(*PackageVersionQuery)) *PkgEqualQuery {
	query := (&PackageVersionClient{config: peq.config}).Query()
	for _, opt := range opts {
		opt(query)
	}
	if peq.withNamedPackages == nil {
		peq.withNamedPackages = make(map[string]*PackageVersionQuery)
	}
	peq.withNamedPackages[name] = query
	return peq
}

// PkgEqualGroupBy is the group-by builder for PkgEqual entities.
type PkgEqualGroupBy struct {
	selector
	build *PkgEqualQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (pegb *PkgEqualGroupBy) Aggregate(fns ...AggregateFunc) *PkgEqualGroupBy {
	pegb.fns = append(pegb.fns, fns...)
	return pegb
}

// Scan applies the selector query and scans the result into the given value.
func (pegb *PkgEqualGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, pegb.build.ctx, "GroupBy")
	if err := pegb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*PkgEqualQuery, *PkgEqualGroupBy](ctx, pegb.build, pegb, pegb.build.inters, v)
}

func (pegb *PkgEqualGroupBy) sqlScan(ctx context.Context, root *PkgEqualQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(pegb.fns))
	for _, fn := range pegb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*pegb.flds)+len(pegb.fns))
		for _, f := range *pegb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*pegb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := pegb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// PkgEqualSelect is the builder for selecting fields of PkgEqual entities.
type PkgEqualSelect struct {
	*PkgEqualQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (pes *PkgEqualSelect) Aggregate(fns ...AggregateFunc) *PkgEqualSelect {
	pes.fns = append(pes.fns, fns...)
	return pes
}

// Scan applies the selector query and scans the result into the given value.
func (pes *PkgEqualSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, pes.ctx, "Select")
	if err := pes.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*PkgEqualQuery, *PkgEqualSelect](ctx, pes.PkgEqualQuery, pes, pes.inters, v)
}

func (pes *PkgEqualSelect) sqlScan(ctx context.Context, root *PkgEqualQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(pes.fns))
	for _, fn := range pes.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*pes.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := pes.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
