package tls

import (
	"reflect"
	"unsafe"
)

// clone returns a deep copy of the ClientHelloSpec and its extension state.
// Function values are reused as-is.
func (chs *ClientHelloSpec) clone() *ClientHelloSpec {
	if chs == nil {
		return nil
	}

	cloned := deepCloneValue(reflect.ValueOf(chs), make(map[deepCloneVisit]reflect.Value))
	return cloned.Interface().(*ClientHelloSpec)
}

type deepCloneVisit struct {
	ptr uintptr
	typ reflect.Type
}

func deepCloneValue(v reflect.Value, seen map[deepCloneVisit]reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}
	v = addressableValue(v)

	if cloned, ok := seenValue(v, seen); ok {
		return cloned
	}

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}

		cloned := reflect.New(v.Type().Elem())
		recordClone(v, cloned, seen)
		cloned.Elem().Set(deepCloneValue(v.Elem(), seen))
		return cloned
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}

		clonedValue := deepCloneValue(v.Elem(), seen)
		cloned := reflect.New(v.Type()).Elem()
		cloned.Set(clonedValue)
		return cloned
	case reflect.Struct:
		cloned := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			addressableValue(cloned.Field(i)).Set(deepCloneValue(v.Field(i), seen))
		}
		return cloned
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}

		cloned := reflect.MakeSlice(v.Type(), v.Len(), v.Cap())
		recordClone(v, cloned, seen)
		for i := 0; i < v.Len(); i++ {
			cloned.Index(i).Set(deepCloneValue(v.Index(i), seen))
		}
		return cloned
	case reflect.Array:
		cloned := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			addressableValue(cloned.Index(i)).Set(deepCloneValue(v.Index(i), seen))
		}
		return cloned
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(v.Type())
		}

		cloned := reflect.MakeMapWithSize(v.Type(), v.Len())
		recordClone(v, cloned, seen)
		iter := v.MapRange()
		for iter.Next() {
			cloned.SetMapIndex(deepCloneValue(iter.Key(), seen), deepCloneValue(iter.Value(), seen))
		}
		return cloned
	default:
		return v
	}
}

func seenValue(v reflect.Value, seen map[deepCloneVisit]reflect.Value) (reflect.Value, bool) {
	visit, ok := deepCloneVisitFor(v)
	if !ok {
		return reflect.Value{}, false
	}

	cloned, ok := seen[visit]
	return cloned, ok
}

func recordClone(v reflect.Value, cloned reflect.Value, seen map[deepCloneVisit]reflect.Value) {
	visit, ok := deepCloneVisitFor(v)
	if !ok {
		return
	}
	seen[visit] = cloned
}

func deepCloneVisitFor(v reflect.Value) (deepCloneVisit, bool) {
	if !v.IsValid() {
		return deepCloneVisit{}, false
	}

	switch v.Kind() {
	case reflect.Pointer, reflect.Map:
		if v.IsNil() {
			return deepCloneVisit{}, false
		}
		return deepCloneVisit{ptr: v.Pointer(), typ: v.Type()}, true
	case reflect.Slice:
		if v.IsNil() || v.Pointer() == 0 {
			return deepCloneVisit{}, false
		}
		return deepCloneVisit{ptr: v.Pointer(), typ: v.Type()}, true
	default:
		return deepCloneVisit{}, false
	}
}

func addressableValue(v reflect.Value) reflect.Value {
	if !v.IsValid() || v.CanSet() || !v.CanAddr() {
		return v
	}
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}
