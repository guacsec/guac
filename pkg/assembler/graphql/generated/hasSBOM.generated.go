// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package generated

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

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

func (ec *executionContext) _Annotation_key(ctx context.Context, field graphql.CollectedField, obj *model.Annotation) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Annotation_key(ctx, field)
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
		return obj.Key, nil
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

func (ec *executionContext) fieldContext_Annotation_key(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Annotation",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _Annotation_value(ctx context.Context, field graphql.CollectedField, obj *model.Annotation) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_Annotation_value(ctx, field)
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
		return obj.Value, nil
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

func (ec *executionContext) fieldContext_Annotation_value(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "Annotation",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_id(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_id(ctx, field)
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

func (ec *executionContext) fieldContext_HasSBOM_id(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type ID does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_subject(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_subject(ctx, field)
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
	res := resTmp.(model.PackageOrArtifact)
	fc.Result = res
	return ec.marshalNPackageOrArtifact2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPackageOrArtifact(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HasSBOM_subject(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type PackageOrArtifact does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_uri(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_uri(ctx, field)
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
		return obj.URI, nil
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

func (ec *executionContext) fieldContext_HasSBOM_uri(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_algorithm(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_algorithm(ctx, field)
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
		return obj.Algorithm, nil
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

func (ec *executionContext) fieldContext_HasSBOM_algorithm(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_digest(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_digest(ctx, field)
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
		return obj.Digest, nil
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

func (ec *executionContext) fieldContext_HasSBOM_digest(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_downloadLocation(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_downloadLocation(ctx, field)
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
		return obj.DownloadLocation, nil
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

func (ec *executionContext) fieldContext_HasSBOM_downloadLocation(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_annotations(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_annotations(ctx, field)
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
		return obj.Annotations, nil
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
	res := resTmp.([]*model.Annotation)
	fc.Result = res
	return ec.marshalNAnnotation2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationᚄ(ctx, field.Selections, res)
}

func (ec *executionContext) fieldContext_HasSBOM_annotations(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			switch field.Name {
			case "key":
				return ec.fieldContext_Annotation_key(ctx, field)
			case "value":
				return ec.fieldContext_Annotation_value(ctx, field)
			}
			return nil, fmt.Errorf("no field named %q was found under type Annotation", field.Name)
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_origin(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_origin(ctx, field)
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

func (ec *executionContext) fieldContext_HasSBOM_origin(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
		Field:      field,
		IsMethod:   false,
		IsResolver: false,
		Child: func(ctx context.Context, field graphql.CollectedField) (*graphql.FieldContext, error) {
			return nil, errors.New("field of type String does not have child fields")
		},
	}
	return fc, nil
}

func (ec *executionContext) _HasSBOM_collector(ctx context.Context, field graphql.CollectedField, obj *model.HasSbom) (ret graphql.Marshaler) {
	fc, err := ec.fieldContext_HasSBOM_collector(ctx, field)
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

func (ec *executionContext) fieldContext_HasSBOM_collector(ctx context.Context, field graphql.CollectedField) (fc *graphql.FieldContext, err error) {
	fc = &graphql.FieldContext{
		Object:     "HasSBOM",
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

func (ec *executionContext) unmarshalInputAnnotationInputSpec(ctx context.Context, obj interface{}) (model.AnnotationInputSpec, error) {
	var it model.AnnotationInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"key", "value"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "key":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("key"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Key = data
		case "value":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("value"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Value = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputAnnotationSpec(ctx context.Context, obj interface{}) (model.AnnotationSpec, error) {
	var it model.AnnotationSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"key", "value"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "key":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("key"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Key = data
		case "value":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("value"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Value = data
		}
	}

	return it, nil
}

func (ec *executionContext) unmarshalInputHasSBOMInputSpec(ctx context.Context, obj interface{}) (model.HasSBOMInputSpec, error) {
	var it model.HasSBOMInputSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	fieldsInOrder := [...]string{"uri", "algorithm", "digest", "downloadLocation", "annotations", "origin", "collector"}
	for _, k := range fieldsInOrder {
		v, ok := asMap[k]
		if !ok {
			continue
		}
		switch k {
		case "uri":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("uri"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.URI = data
		case "algorithm":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("algorithm"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Algorithm = data
		case "digest":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("digest"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.Digest = data
		case "downloadLocation":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("downloadLocation"))
			data, err := ec.unmarshalNString2string(ctx, v)
			if err != nil {
				return it, err
			}
			it.DownloadLocation = data
		case "annotations":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("annotations"))
			data, err := ec.unmarshalNAnnotationInputSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationInputSpecᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.Annotations = data
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

func (ec *executionContext) unmarshalInputHasSBOMSpec(ctx context.Context, obj interface{}) (model.HasSBOMSpec, error) {
	var it model.HasSBOMSpec
	asMap := map[string]interface{}{}
	for k, v := range obj.(map[string]interface{}) {
		asMap[k] = v
	}

	if _, present := asMap["annotations"]; !present {
		asMap["annotations"] = []interface{}{}
	}

	fieldsInOrder := [...]string{"id", "subject", "uri", "algorithm", "digest", "downloadLocation", "annotations", "origin", "collector"}
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
		case "subject":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("subject"))
			data, err := ec.unmarshalOPackageOrArtifactSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐPackageOrArtifactSpec(ctx, v)
			if err != nil {
				return it, err
			}
			it.Subject = data
		case "uri":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("uri"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.URI = data
		case "algorithm":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("algorithm"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Algorithm = data
		case "digest":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("digest"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.Digest = data
		case "downloadLocation":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("downloadLocation"))
			data, err := ec.unmarshalOString2ᚖstring(ctx, v)
			if err != nil {
				return it, err
			}
			it.DownloadLocation = data
		case "annotations":
			var err error

			ctx := graphql.WithPathContext(ctx, graphql.NewPathWithField("annotations"))
			data, err := ec.unmarshalOAnnotationSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationSpecᚄ(ctx, v)
			if err != nil {
				return it, err
			}
			it.Annotations = data
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

var annotationImplementors = []string{"Annotation"}

func (ec *executionContext) _Annotation(ctx context.Context, sel ast.SelectionSet, obj *model.Annotation) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, annotationImplementors)

	out := graphql.NewFieldSet(fields)
	deferred := make(map[string]*graphql.FieldSet)
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("Annotation")
		case "key":
			out.Values[i] = ec._Annotation_key(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "value":
			out.Values[i] = ec._Annotation_value(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		default:
			panic("unknown field " + strconv.Quote(field.Name))
		}
	}
	out.Dispatch(ctx)
	if out.Invalids > 0 {
		return graphql.Null
	}

	atomic.AddInt32(&ec.deferred, int32(len(deferred)))

	for label, dfs := range deferred {
		ec.processDeferredGroup(graphql.DeferredGroup{
			Label:    label,
			Path:     graphql.GetPath(ctx),
			FieldSet: dfs,
			Context:  ctx,
		})
	}

	return out
}

var hasSBOMImplementors = []string{"HasSBOM", "Node"}

func (ec *executionContext) _HasSBOM(ctx context.Context, sel ast.SelectionSet, obj *model.HasSbom) graphql.Marshaler {
	fields := graphql.CollectFields(ec.OperationContext, sel, hasSBOMImplementors)

	out := graphql.NewFieldSet(fields)
	deferred := make(map[string]*graphql.FieldSet)
	for i, field := range fields {
		switch field.Name {
		case "__typename":
			out.Values[i] = graphql.MarshalString("HasSBOM")
		case "id":
			out.Values[i] = ec._HasSBOM_id(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "subject":
			out.Values[i] = ec._HasSBOM_subject(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "uri":
			out.Values[i] = ec._HasSBOM_uri(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "algorithm":
			out.Values[i] = ec._HasSBOM_algorithm(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "digest":
			out.Values[i] = ec._HasSBOM_digest(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "downloadLocation":
			out.Values[i] = ec._HasSBOM_downloadLocation(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "annotations":
			out.Values[i] = ec._HasSBOM_annotations(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "origin":
			out.Values[i] = ec._HasSBOM_origin(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		case "collector":
			out.Values[i] = ec._HasSBOM_collector(ctx, field, obj)
			if out.Values[i] == graphql.Null {
				out.Invalids++
			}
		default:
			panic("unknown field " + strconv.Quote(field.Name))
		}
	}
	out.Dispatch(ctx)
	if out.Invalids > 0 {
		return graphql.Null
	}

	atomic.AddInt32(&ec.deferred, int32(len(deferred)))

	for label, dfs := range deferred {
		ec.processDeferredGroup(graphql.DeferredGroup{
			Label:    label,
			Path:     graphql.GetPath(ctx),
			FieldSet: dfs,
			Context:  ctx,
		})
	}

	return out
}

// endregion **************************** object.gotpl ****************************

// region    ***************************** type.gotpl *****************************

func (ec *executionContext) marshalNAnnotation2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.Annotation) graphql.Marshaler {
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
			ret[i] = ec.marshalNAnnotation2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotation(ctx, sel, v[i])
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

func (ec *executionContext) marshalNAnnotation2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotation(ctx context.Context, sel ast.SelectionSet, v *model.Annotation) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._Annotation(ctx, sel, v)
}

func (ec *executionContext) unmarshalNAnnotationInputSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationInputSpecᚄ(ctx context.Context, v interface{}) ([]*model.AnnotationInputSpec, error) {
	var vSlice []interface{}
	if v != nil {
		vSlice = graphql.CoerceList(v)
	}
	var err error
	res := make([]*model.AnnotationInputSpec, len(vSlice))
	for i := range vSlice {
		ctx := graphql.WithPathContext(ctx, graphql.NewPathWithIndex(i))
		res[i], err = ec.unmarshalNAnnotationInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationInputSpec(ctx, vSlice[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ec *executionContext) unmarshalNAnnotationInputSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationInputSpec(ctx context.Context, v interface{}) (*model.AnnotationInputSpec, error) {
	res, err := ec.unmarshalInputAnnotationInputSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalNAnnotationSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationSpec(ctx context.Context, v interface{}) (*model.AnnotationSpec, error) {
	res, err := ec.unmarshalInputAnnotationSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) marshalNHasSBOM2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSbom(ctx context.Context, sel ast.SelectionSet, v model.HasSbom) graphql.Marshaler {
	return ec._HasSBOM(ctx, sel, &v)
}

func (ec *executionContext) marshalNHasSBOM2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSbomᚄ(ctx context.Context, sel ast.SelectionSet, v []*model.HasSbom) graphql.Marshaler {
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
			ret[i] = ec.marshalNHasSBOM2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSbom(ctx, sel, v[i])
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

func (ec *executionContext) marshalNHasSBOM2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSbom(ctx context.Context, sel ast.SelectionSet, v *model.HasSbom) graphql.Marshaler {
	if v == nil {
		if !graphql.HasFieldError(ctx, graphql.GetFieldContext(ctx)) {
			ec.Errorf(ctx, "the requested element is null which the schema does not allow")
		}
		return graphql.Null
	}
	return ec._HasSBOM(ctx, sel, v)
}

func (ec *executionContext) unmarshalNHasSBOMInputSpec2githubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMInputSpec(ctx context.Context, v interface{}) (model.HasSBOMInputSpec, error) {
	res, err := ec.unmarshalInputHasSBOMInputSpec(ctx, v)
	return res, graphql.ErrorOnPath(ctx, err)
}

func (ec *executionContext) unmarshalOAnnotationSpec2ᚕᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationSpecᚄ(ctx context.Context, v interface{}) ([]*model.AnnotationSpec, error) {
	if v == nil {
		return nil, nil
	}
	var vSlice []interface{}
	if v != nil {
		vSlice = graphql.CoerceList(v)
	}
	var err error
	res := make([]*model.AnnotationSpec, len(vSlice))
	for i := range vSlice {
		ctx := graphql.WithPathContext(ctx, graphql.NewPathWithIndex(i))
		res[i], err = ec.unmarshalNAnnotationSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐAnnotationSpec(ctx, vSlice[i])
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (ec *executionContext) unmarshalOHasSBOMSpec2ᚖgithubᚗcomᚋguacsecᚋguacᚋpkgᚋassemblerᚋgraphqlᚋmodelᚐHasSBOMSpec(ctx context.Context, v interface{}) (*model.HasSBOMSpec, error) {
	if v == nil {
		return nil, nil
	}
	res, err := ec.unmarshalInputHasSBOMSpec(ctx, v)
	return &res, graphql.ErrorOnPath(ctx, err)
}

// endregion ***************************** type.gotpl *****************************
