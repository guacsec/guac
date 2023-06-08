package ent

import (
	"entgo.io/ent/dialect/sql"
	entsql "entgo.io/ent/dialect/sql"
)

func IDEQ(id *string) func(*sql.Selector) {
	if id == nil {
		return NoOpSelector()
	}

	return sql.FieldEQ("id", *id)
}

func NoOpSelector() func(*sql.Selector) {
	return func(s *sql.Selector) {}
}

type Predicate interface {
	~func(*entsql.Selector)
}

func optionalPredicate[P Predicate](value *string, fn func(s string) P) P {
	if value == nil {
		return func(*entsql.Selector) {}
	}

	return fn(*value)
}
