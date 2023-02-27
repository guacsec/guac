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

func (ec *executionContext) _GHSA_ghsaId(ctx context.Context, field graphql.CollectedField, obj *model.Ghsa) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_GHSA_ghsaId(ctx, field)
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
		return obj.GhsaID, nil
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
	res := resTmp.([]*model.GHSAId)
	fc.Result = res
	return ec.marshalNGHSAId2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGHSAIdᚄ(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_GHSA_ghsaId(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "GHSA",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "id":
				return ec.fieldContext_GHSAId_id(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type GHSAId", field.Name)
		},
	}
	return fc, nil
}

func (ec *executionContext) _GHSAId_id(ctx context.Context, field graphql.CollectedField, obj *model.GHSAId) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_GHSAId_id(ctx, field)
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
	return ec.marshalNString2string(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_GHSAId_id(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "GHSAId",
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

func (ec *executionContext) unmarshalInputGHSAInputSpec(ctx context.Context, obj interface{}) (model.GHSAInputSpec, error) {
	var it model.GHSAInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"ghsaId"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "ghsaId":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("ghsaId"))
			it.GhsaID, err = ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputGHSASpec(ctx context.Context, obj interface{}) (model.GHSASpec, error) {
	var it model.GHSASpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"ghsaId"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "ghsaId":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("ghsaId"))
			it.GhsaID, err = ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
		}
	}

	return it, nil
}

// endregion **************************** input.gotpl *****************************

// region    ************************** interface.gotpl ***************************

// endregion ************************** interface.gotpl ***************************

// region    **************************** object.gotpl ****************************

var gHSAImplementors = []string{"GHSA", "OsvCveGhsaObject", "CveGhsaObject"}

func (ec *executionContext) _GHSA(ctx context.Context, sel ast.SelectionSet, obj *model.Ghsa) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, gHSAImplementors)
	out := graphql.NewFieldSet(fields)
	var invalids uint32
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("GHSA")
		case "ghsaId":

			out.Values[i] = ec._GHSA_ghsaId(ctx, field, obj)

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

var gHSAIdImplementors = []string{"GHSAId"}

func (ec *executionContext) _GHSAId(ctx context.Context, sel ast.SelectionSet, obj *model.GHSAId) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, gHSAIdImplementors)
	out := graphql.NewFieldSet(fields)
	var invalids uint32
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("GHSAId")
		case "id":

			out.Values[i] = ec._GHSAId_id(ctx, field, obj)

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

func (ec *executionContext) marshalNGHSA2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGhsa(ctx context.Context, sel ast.SelectionSet, v model.Ghsa) graphql.Marshaler {
	return ec._GHSA(ctx, sel, &v)
}

func (ec *executionContext) marshalNGHSA2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGhsaᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.Ghsa) graphql.Marshaler {
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
			ret[i] = ec.marshalNGHSA2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGhsa(ctx, sel, v[i])
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

func (ec *executionContext) marshalNGHSA2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGhsa(ctx context.Context, sel ast.SelectionSet, v *model.Ghsa) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._GHSA(ctx, sel, v)
}

func (ec *executionContext) marshalNGHSAId2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGHSAIdᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.GHSAId) graphql.Marshaler {
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
			ret[i] = ec.marshalNGHSAId2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGHSAId(ctx, sel, v[i])
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

func (ec *executionContext) marshalNGHSAId2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGHSAId(ctx context.Context, sel ast.SelectionSet, v *model.GHSAId) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._GHSAId(ctx, sel, v)
}

func (ec *executionContext) unmarshalOGHSAInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGHSAInputSpec(ctx context.Context, v interface{}) (*model.GHSAInputSpec, error) {
	if v == nil {
		return nil, nil
	}
	res, err := ec.unmarshalInputGHSAInputSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalOGHSASpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐGHSASpec(ctx context.Context, v interface{}) (*model.GHSASpec, error) {
	if v == nil {
		return nil, nil
	}
	res, err := ec.unmarshalInputGHSASpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

// endregion ***************************** type.gotpl *****************************
