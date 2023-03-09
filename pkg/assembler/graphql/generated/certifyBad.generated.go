// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package generated

import (
	"context"
	"errors"
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

func (ec *executionContext) _CertifyBad_subject(ctx context.Context, field graphql.CollectedField, obj *model.CertifyBad) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_CertifyBad_subject(ctx, field)
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
		return obj.Subject, nil
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
	res := resTmp.(model.PackageSourceOrArtifact)
	fc.Result = res
	return ec.marshalNPackageSourceOrArtifact2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPackageSourceOrArtifact(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_CertifyBad_subject(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "CertifyBad",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type PackageSourceOrArtifact does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _CertifyBad_justification(ctx context.Context, field graphql.CollectedField, obj *model.CertifyBad) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_CertifyBad_justification(ctx, field)
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

func (ec *executionContext) fieldContext_CertifyBad_justification(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "CertifyBad",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _CertifyBad_origin(ctx context.Context, field graphql.CollectedField, obj *model.CertifyBad) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_CertifyBad_origin(ctx, field)
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

func (ec *executionContext) fieldContext_CertifyBad_origin(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "CertifyBad",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _CertifyBad_collector(ctx context.Context, field graphql.CollectedField, obj *model.CertifyBad) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_CertifyBad_collector(ctx, field)
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

func (ec *executionContext) fieldContext_CertifyBad_collector(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "CertifyBad",
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

func (ec *executionContext) unmarshalInputCertifyBadInputSpec(ctx context.Context, obj interface{}) (model.CertifyBadInputSpec, error) {
	var it model.CertifyBadInputSpec
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
			it.Justification, err = ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
		case "origin":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("origin"))
			it.Origin, err = ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
		case "collector":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("collector"))
			it.Collector, err = ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputCertifyBadSpec(ctx context.Context, obj interface{}) (model.CertifyBadSpec, error) {
	var it model.CertifyBadSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"subject", "justification", "origin", "collector"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "subject":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("subject"))
			it.Subject, err = ec.unmarshalOPackageSourceOrArtifactSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPackageSourceOrArtifactSpec(ctx, v)
			if err != nil {
				return it, err
			}
		case "justification":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("justification"))
			it.Justification, err = ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
		case "origin":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("origin"))
			it.Origin, err = ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
		case "collector":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("collector"))
			it.Collector, err = ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputMatchFlags(ctx context.Context, obj interface{}) (model.MatchFlags, error) {
	var it model.MatchFlags
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"pkg"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "pkg":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("pkg"))
			it.Pkg, err = ec.unmarshalNPkgMatchType2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPkgMatchType(ctx, v)
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

var certifyBadImplementors = []string{"CertifyBad"}

func (ec *executionContext) _CertifyBad(ctx context.Context, sel ast.SelectionSet, obj *model.CertifyBad) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, certifyBadImplementors)
	out := graphql.NewFieldSet(fields)
	var invalids uint32
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("CertifyBad")
		case "subject":

			out.Values[i] = ec._CertifyBad_subject(ctx, field, obj)

			if out.Values[i] == graphql.Null {
				invalids++
			}
		case "justification":

			out.Values[i] = ec._CertifyBad_justification(ctx, field, obj)

			if out.Values[i] == graphql.Null {
				invalids++
			}
		case "origin":

			out.Values[i] = ec._CertifyBad_origin(ctx, field, obj)

			if out.Values[i] == graphql.Null {
				invalids++
			}
		case "collector":

			out.Values[i] = ec._CertifyBad_collector(ctx, field, obj)

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

func (ec *executionContext) marshalNCertifyBad2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyBad(ctx context.Context, sel ast.SelectionSet, v model.CertifyBad) graphql.Marshaler {
	return ec._CertifyBad(ctx, sel, &v)
}

func (ec *executionContext) marshalNCertifyBad2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyBadᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.CertifyBad) graphql.Marshaler {
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
			ret[i] = ec.marshalNCertifyBad2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyBad(ctx, sel, v[i])
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

func (ec *executionContext) marshalNCertifyBad2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyBad(ctx context.Context, sel ast.SelectionSet, v *model.CertifyBad) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._CertifyBad(ctx, sel, v)
}

func (ec *executionContext) unmarshalNCertifyBadInputSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyBadInputSpec(ctx context.Context, v interface{}) (model.CertifyBadInputSpec, error) {
	res, err := ec.unmarshalInputCertifyBadInputSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNPkgMatchType2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPkgMatchType(ctx context.Context, v interface{}) (model.PkgMatchType, error) {
	var res model.PkgMatchType
	err := res.UnmarshalGQL(v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) marshalNPkgMatchType2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPkgMatchType(ctx context.Context, sel ast.SelectionSet, v model.PkgMatchType) graphql.Marshaler {
	return v
}

func (ec *executionContext) unmarshalOCertifyBadSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐCertifyBadSpec(ctx context.Context, v interface{}) (*model.CertifyBadSpec, error) {
	if v == nil {
		return nil, nil
	}
	res, err := ec.unmarshalInputCertifyBadSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalOMatchFlags2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐMatchFlags(ctx context.Context, v interface{}) (*model.MatchFlags, error) {
	if v == nil {
		return nil, nil
	}
	res, err := ec.unmarshalInputMatchFlags(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

// endregion ***************************** type.gotpl *****************************
