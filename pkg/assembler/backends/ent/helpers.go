package ent

import "entgo.io/ent/dialect/sql"

func IDEQ(id *string) func(*sql.Selector) {
	if id == nil {
		return NoOpSelector()
	}

	return sql.FieldEQ("id", *id)
}

func NoOpSelector() func(*sql.Selector) {
	return func(s *sql.Selector) {}
}
