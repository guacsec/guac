// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package generated

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/99designs/gqlgen/graphql"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/ast"
)

// region    ************************** generated!.gotpl **************************

// endregion ************************** generated!.gotpl **************************

// region    ***************************** args.gotpl *****************************

// endregion ***************************** args.gotpl *****************************

// region    ************************** directives.gotpl **************************

// endregion ************************** directives.gotpl **************************

// region    **************************** field.gotpl *****************************

func (ec *executionContext) _HashEqual_id(ctx context.Context, field graphql.CollectedField, obj *model.HashEqual) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HashEqual_id(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.ID, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNID2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HashEqual_id(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HashEqual",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type ID does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HashEqual_artifacts(ctx context.Context, field graphql.CollectedField, obj *model.HashEqual) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HashEqual_artifacts(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Artifacts, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.([]*model.Artifact)
	fc.Result = res
	return ec.marshalNArtifact2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐArtifactᚄ(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HashEqual_artifacts(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HashEqual",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "id":
				return ec.fieldContext_Artifact_id(ctx, field)
			case "algorithm":
				return ec.fieldContext_Artifact_algorithm(ctx, field)
			case "digest":
				return ec.fieldContext_Artifact_digest(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type Artifact", field.Name)
		},
	}
	return fc, nil
}

func (ec *executionContext) _HashEqual_justification(ctx context.Context, field graphql.CollectedField, obj *model.HashEqual) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HashEqual_justification(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Justification, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HashEqual_justification(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HashEqual",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HashEqual_origin(ctx context.Context, field graphql.CollectedField, obj *model.HashEqual) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HashEqual_origin(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Origin, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HashEqual_origin(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HashEqual",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HashEqual_collector(ctx context.Context, field graphql.CollectedField, obj *model.HashEqual) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HashEqual_collector(ctx, field)
	if err != nil {
		return graphql.Null
	}
	ctx = graphql.WithFieldContext(ctx, fc)
	defer func() {
		if r := recover(); r != nil {
			ec.Error(ctx, ec.Recover(ctx, r))
			ret = graphql.Null
		}
	}()
	resTmp, err := ec.ResolverMiddleware(ctx, func(rctx context.Context) (interface{}, error) {
		ctx = rctx // use context from middleware stack in children
		return obj.Collector, nil
	})
	if err != nil {
		ec.Error(ctx, err)
		return graphql.Null
	}
	if resTmp == nil {
		if !graphql.HasFieldError(ctx, fc) {
			ec.Errorf(ctx, "must not be null")
		}
		return graphql.Null
	}
	res := resTmp.(string)
	fc.Result = res
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HashEqual_collector(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HashEqual",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

// endregion **************************** field.gotpl *****************************

// region    **************************** input.gotpl *****************************

func (ec *executionContext) unmarshalInputHashEqualInputSpec(ctx context.Context, obj interface{}) (model.HashEqualInputSpec, error) {
	var it model.HashEqualInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"justification", "origin", "collector"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "justification":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("justification"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Justification = data
		case "origin":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("origin"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Origin = data
		case "collector":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("collector"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Collector = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputHashEqualSpec(ctx context.Context, obj interface{}) (model.HashEqualSpec, error) {
	var it model.HashEqualSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"id", "artifacts", "justification", "origin", "collector"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "id":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("id"))
			data, err := ec.unmarshalOID2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.ID = data
		case "artifacts":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("artifacts"))
			data, err := ec.unmarshalOArtifactSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐArtifactSpec(ctx, v)
			if err != nil {
				return it, err
			}
			it.Artifacts = data
		case "justification":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("justification"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Justification = data
		case "origin":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("origin"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Origin = data
		case "collector":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("collector"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Collector = data
		}
	}

	return it, nil
}

// endregion **************************** input.gotpl *****************************

// region    ************************** interface.gotpl ***************************

// endregion ************************** interface.gotpl ***************************

// region    **************************** object.gotpl ****************************

var hashEqualImplementors = []string{"HashEqual", "Node"}

func (ec *executionContext) _HashEqual(ctx context.Context, sel ast.SelectionSet, obj *model.HashEqual) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, hashEqualImplementors)
	out := graphql.NewFieldSet(fields)
	var invalids uint32
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("HashEqual")
		case "id":

			out.Values[i] = ec._HashEqual_id(ctx, field, obj)

			if out.Values[i] == graphql.Null {
				invalids++
			}
		case "artifacts":

			out.Values[i] = ec._HashEqual_artifacts(ctx, field, obj)

			if out.Values[i] == graphql.Null {
				invalids++
			}
		case "justification":

			out.Values[i] = ec._HashEqual_justification(ctx, field, obj)

			if out.Values[i] == graphql.Null {
				invalids++
			}
		case "origin":

			out.Values[i] = ec._HashEqual_origin(ctx, field, obj)

			if out.Values[i] == graphql.Null {
				invalids++
			}
		case "collector":

			out.Values[i] = ec._HashEqual_collector(ctx, field, obj)

			if out.Values[i] == graphql.Null {
				invalids++
			}
		default:
			panic("unknown field " + strconv.Quote(field.Name))
		}
	}
	out.Dispatch()
	if invalids > 0 {
		return graphql.Null
	}
	return out
}

// endregion **************************** object.gotpl ****************************

// region    ***************************** type.gotpl *****************************

func (ec *executionContext) marshalNHashEqual2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHashEqual(ctx context.Context, sel ast.SelectionSet, v model.HashEqual) graphql.Marshaler {
	return ec._HashEqual(ctx, sel, &v)
}

func (ec *executionContext) marshalNHashEqual2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHashEqualᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.HashEqual) graphql.Marshaler {
	ret := make(graphql.Array, len(v))
	var wg sync.WaitGroup
	isLen1 := len(v) == 1
	if !isLen1 {
		wg.Add(len(v))
	}
	for i := range v {
		i := i
		fc := &graphql.FieldContext{
			Index:  &i,
			Result: &v[i],
		}
		ctx := graphql.WithFieldContext(ctx, fc)
		f := func(i int) {
			defer func() {
				if r := recover(); r != nil {
					ec.Error(ctx, ec.Recover(ctx, r))
					ret = nil
				}
			}()
			if !isLen1 {
				defer wg.Done()
			}
			ret[i] = ec.marshalNHashEqual2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHashEqual(ctx, sel, v[i])
		}
		if isLen1 {
			f(i)
		} else {
			go f(i)
		}

	}
	wg.Wait()

	for _, e := range ret {
		if e == graphql.Null {
			return graphql.Null
		}
	}

	return ret
}

func (ec *executionContext) marshalNHashEqual2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHashEqual(ctx context.Context, sel ast.SelectionSet, v *model.HashEqual) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._HashEqual(ctx, sel, v)
}

func (ec *executionContext) unmarshalNHashEqualInputSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHashEqualInputSpec(ctx context.Context, v interface{}) (model.HashEqualInputSpec, error) {
	res, err := ec.unmarshalInputHashEqualInputSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalOHashEqualSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHashEqualSpec(ctx context.Context, v interface{}) (*model.HashEqualSpec, error) {
	if v == nil {
		return nil, nil
	}
	res, err := ec.unmarshalInputHashEqualSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

// endregion ***************************** type.gotpl *****************************
