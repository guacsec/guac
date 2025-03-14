// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package generated

import (
	"context"
	"errors"

	"github.com/99designs/gqlgen/graphql"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/ast"
)

// region    ************************** generated!.gotpl **************************

// endregion ************************** generated!.gotpl **************************

// region    ***************************** args.gotpl *****************************

func (ec *executionContext) dir_filter_args(ctx context.Context, rawArgs map[string]any) (map[string]any, error) {
	var err error
	args := map[string]any{}
	arg0, err := ec.dir_filter_argsKeyName(ctx, rawArgs)
	if err != nil {
		return nil, err
	}
	args["keyName"] = arg0
	arg1, err := ec.dir_filter_argsOperation(ctx, rawArgs)
	if err != nil {
		return nil, err
	}
	args["operation"] = arg1
	arg2, err := ec.dir_filter_argsValue(ctx, rawArgs)
	if err != nil {
		return nil, err
	}
	args["value"] = arg2
	return args, nil
}
func (ec *executionContext) dir_filter_argsKeyName(
	ctx context.Context,
	rawArgs map[string]any,
) (*string, error) {
	if _, ok := rawArgs["keyName"]; !ok {
		var zeroVal *string
		return zeroVal, nil
	}

	ctx = graphql.WithPathContext(ctx, graphql.NewPathWithField("keyName"))
	if tmp, ok := rawArgs["keyName"]; ok {
		return ec.unmarshalOString2ᚖstring(ctx, tmp)
	}

	var zeroVal *string
	return zeroVal, nil
}

func (ec *executionContext) dir_filter_argsOperation(
	ctx context.Context,
	rawArgs map[string]any,
) (*model.FilterOperation, error) {
	if _, ok := rawArgs["operation"]; !ok {
		var zeroVal *model.FilterOperation
		return zeroVal, nil
	}

	ctx = graphql.WithPathContext(ctx, graphql.NewPathWithField("operation"))
	if tmp, ok := rawArgs["operation"]; ok {
		return ec.unmarshalOFilterOperation2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐFilterOperation(ctx, tmp)
	}

	var zeroVal *model.FilterOperation
	return zeroVal, nil
}

func (ec *executionContext) dir_filter_argsValue(
	ctx context.Context,
	rawArgs map[string]any,
) (*string, error) {
	if _, ok := rawArgs["value"]; !ok {
		var zeroVal *string
		return zeroVal, nil
	}

	ctx = graphql.WithPathContext(ctx, graphql.NewPathWithField("value"))
	if tmp, ok := rawArgs["value"]; ok {
		return ec.unmarshalOString2ᚖstring(ctx, tmp)
	}

	var zeroVal *string
	return zeroVal, nil
}

// endregion ***************************** args.gotpl *****************************

// region    ************************** directives.gotpl **************************

func (ec *executionContext) _fieldMiddleware(ctx context.Context, obj any, next graphql.Resolver) any {
	fc := graphql.GetFieldContext(ctx)
	for _, d := range fc.Field.Directives {
		switch d.Name {
		case "filter":
			rawArgs := d.ArgumentMap(ec.Variables)
			args, err := ec.dir_filter_args(ctx, rawArgs)
			if err != nil {
				ec.Error(ctx, err)
				return nil
			}
			n := next
			next = func(ctx context.Context) (any, error) {
				if ec.directives.Filter == nil {
					return nil, errors.New("directive filter is not implemented")
				}
				return ec.directives.Filter(ctx, obj, n, args["keyName"].(*string), args["operation"].(*model.FilterOperation), args["value"].(*string))
			}
		}
	}
	res, err := ec.ResolverMiddleware(ctx, next)
	if err != nil {
		ec.Error(ctx, err)
		return nil
	}
	return res
}

// endregion ************************** directives.gotpl **************************

// region    **************************** field.gotpl *****************************

// endregion **************************** field.gotpl *****************************

// region    **************************** input.gotpl *****************************

// endregion **************************** input.gotpl *****************************

// region    ************************** interface.gotpl ***************************

// endregion ************************** interface.gotpl ***************************

// region    **************************** object.gotpl ****************************

// endregion **************************** object.gotpl ****************************

// region    ***************************** type.gotpl *****************************

func (ec *executionContext) unmarshalOFilterOperation2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐFilterOperation(ctx context.Context, v any) (*model.FilterOperation, error) {
	if v == nil {
		return nil, nil
	}
	var res = new(model.FilterOperation)
	err := res.UnmarshalGQL(v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) marshalOFilterOperation2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐFilterOperation(ctx context.Context, sel ast.SelectionSet, v *model.FilterOperation) graphql.Marshaler {
	if v == nil {
		return graphql.Null
	}
	return v
}

// endregion ***************************** type.gotpl *****************************
