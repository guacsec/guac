package resolvers

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/99designs/gqlgen/graphql"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

const numWorkers = 5
const channelBufferSize = 1000

func collectResults(resultChan <-chan reflect.Value, modelType reflect.Type) reflect.Value {
	matchingItemsInterface := reflect.MakeSlice(reflect.SliceOf(reflect.PtrTo(modelType)), 0, 0)

	for item := range resultChan {
		matchingItemsInterface = reflect.Append(matchingItemsInterface, item.Addr())
	}

	return matchingItemsInterface
}

func worker(ctx context.Context, input reflect.Value, start, end int, keyName, value string, operation model.FilterOperation, resultChan chan<- reflect.Value, modelType reflect.Type) {
	for i := start; i < end; i++ {
		item := input.Index(i)
		item, isStruct := isStructOrPointerToStruct(item)
		found := fieldMatchesRecursive(item, keyName, value, operation)

		if isStruct && found {
			resultChan <- item
		}
	}

}

func fieldMatchesRecursive(item reflect.Value, keyName, value string, operation model.FilterOperation) bool {
	var found bool
	keys := strings.Split(keyName, ".")

	for i := 0; i < item.NumField(); i++ {
		field := item.Field(i)
		fieldName := item.Type().Field(i).Name

		if isStructPtrField(field) && strings.EqualFold(fieldName, keys[0]) {
			found = handleStructPtrField(field, keys, value, operation)

		} else if isSliceField(field) && isMatchingSliceField(fieldName, keys) {
			modifiedSlice := handleSliceField(field, keys, value, operation)
			if modifiedSlice.Len() > 0 {
				found = true
				item.Field(i).Set(modifiedSlice)
			} else {
				found = false
			}

		} else if isMatchingField(fieldName, keys) {
			found = handleMatchingField(field, keys, value, operation)
		}
	}

	return found
}

func handleSliceField(field reflect.Value, keys []string, value string, operation model.FilterOperation) reflect.Value {
	var matchingSliceItems []reflect.Value

	for j := 0; j < field.Len(); j++ {
		sliceItem := field.Index(j)
		if sliceItem.Kind() == reflect.Ptr {
			sliceItem = sliceItem.Elem()
		}
		newItem := reflect.New(sliceItem.Type()).Elem()
		newItem.Set(sliceItem)

		found := fieldMatchesRecursive(newItem, strings.Join(keys[1:], "."), value, operation)
		if found {
			matchingSliceItems = append(matchingSliceItems, newItem.Addr())
		}
	}

	modifiedSlice := reflect.MakeSlice(field.Type(), len(matchingSliceItems), len(matchingSliceItems))
	for k, matchingSliceItem := range matchingSliceItems {
		modifiedSlice.Index(k).Set(matchingSliceItem)
	}
	return modifiedSlice
}

func handleStructPtrField(field reflect.Value, keys []string, value string, operation model.FilterOperation) bool {
	found := fieldMatchesRecursive(field.Elem(), strings.Join(keys[1:], "."), value, operation)
	return found
}

func handleMatchingField(field reflect.Value, keys []string, value string, operation model.FilterOperation) bool {
	if len(keys) == 1 {

		lowercaseInputValue := strings.ToLower(value)
		lowercaseFieldValue := strings.ToLower(fmt.Sprintf("%v", field.Interface()))

		switch operation {
		case model.FilterOperationContains:
			if strings.Contains(lowercaseFieldValue, lowercaseInputValue) {
				return true
			}
		case model.FilterOperationStartswith:
			if strings.HasPrefix(lowercaseFieldValue, lowercaseInputValue) {
				return true
			}
		}
	}

	return false
}

func isStructOrPointerToStruct(v reflect.Value) (reflect.Value, bool) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	return v, v.Kind() == reflect.Struct
}

func isStructPtrField(field reflect.Value) bool {
	return field.Kind() == reflect.Ptr && !field.IsNil() && field.Elem().Kind() == reflect.Struct
}

func isSliceField(field reflect.Value) bool {
	return field.Kind() == reflect.Slice
}

func isMatchingSliceField(fieldName string, keys []string) bool {
	return strings.HasSuffix(keys[0], "[]") && strings.EqualFold(fieldName, keys[0][:len(keys[0])-2])
}

func isMatchingField(fieldName string, keys []string) bool {
	return strings.EqualFold(fieldName, keys[0])
}

func Filter(ctx context.Context, obj interface{}, next graphql.Resolver, keyName *string, operation *model.FilterOperation, value *string) (res interface{}, err error) {
	result, err := next(ctx)
	if err != nil {
		return nil, err
	}

	v := reflect.ValueOf(result)
	if v.Kind() == reflect.Slice && v.Len() > 0 {
		modelType := v.Index(0).Type().Elem()
		partSize := v.Len() / numWorkers
		resultChan := make(chan reflect.Value, channelBufferSize)
		var wg sync.WaitGroup

		for i := 0; i < numWorkers; i++ {
			start := i * partSize
			end := start + partSize
			if i == numWorkers-1 {
				end = v.Len()
			}
			wg.Add(1)

			go func(start, end int) {
				defer wg.Done()

				worker(ctx, v, start, end, *keyName, *value, *operation, resultChan, modelType)
			}(start, end)
		}

		go func() {
			wg.Wait()
			close(resultChan)
		}()

		totalMatchingItems := collectResults(resultChan, modelType)
		return totalMatchingItems.Interface(), nil
	} else {
		return result, nil
	}
}
