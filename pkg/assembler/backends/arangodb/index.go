package arangodb

type index struct {
	name   string
	fields []string
	unique bool
}

func initIndex(name string, fields []string, unique bool) *index {
	return &index{
		name: name,
		fields: fields,
		unique: unique,
	}
}