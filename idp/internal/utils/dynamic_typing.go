package utils

import (
	"fmt"
	"reflect"
	"strconv"
)

// ConvertType attempts to convert a value to the specified type.
func ConvertType(value interface{}, targetType reflect.Type) (interface{}, error) {
	if value == nil {
		return nil, fmt.Errorf("cannot convert nil value")
	}

	valueType := reflect.TypeOf(value)
	if valueType == targetType {
		return value, nil // No conversion needed
	}

	valueValue := reflect.ValueOf(value)

	switch targetType.Kind() {
	case reflect.String:
		return convertToString(valueValue)
	case reflect.Int:
		return convertToInt(valueValue)
	case reflect.Float64:
		return convertToFloat64(valueValue)
	case reflect.Bool:
		return convertToBool(valueValue)
	default:
		return nil, fmt.Errorf("unsupported target type: %s", targetType.String())
	}
}

func convertToString(value reflect.Value) (interface{}, error) {
	switch value.Kind() {
	case reflect.String:
		return value.String(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(value.Int(), 10), nil
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(value.Float(), 'f', -1, 64), nil
	case reflect.Bool:
		return strconv.FormatBool(value.Bool()), nil
	default:
		return nil, fmt.Errorf("cannot convert %s to string", value.Type().String())
	}
}

func convertToInt(value reflect.Value) (interface{}, error) {
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(value.Int()), nil
	case reflect.Float32, reflect.Float64:
		return int(value.Float()), nil
	case reflect.String:
		return strconv.Atoi(value.String())
	default:
		return nil, fmt.Errorf("cannot convert %s to int", value.Type().String())
	}
}

func convertToFloat64(value reflect.Value) (interface{}, error) {
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(value.Int()), nil
	case reflect.Float32, reflect.Float64:
		return value.Float(), nil
	case reflect.String:
		return strconv.ParseFloat(value.String(), 64)
	default:
		return nil, fmt.Errorf("cannot convert %s to float64", value.Type().String())
	}
}

func convertToBool(value reflect.Value) (interface{}, error) {
	switch value.Kind() {
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.String:
		return strconv.ParseBool(value.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int() != 0, nil
	case reflect.Float32, reflect.Float64:
		return value.Float() != 0, nil
	default:
		return nil, fmt.Errorf("cannot convert %s to bool", value.Type().String())
	}
}

func IsEmptyTypeInterface(v interface{}) bool {
	if v == nil {
		return true
	}

	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		return val.IsNil()
	}

	return reflect.DeepEqual(v, reflect.Zero(val.Type()).Interface())
}
