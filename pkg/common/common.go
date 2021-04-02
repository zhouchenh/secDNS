package common

import "reflect"

func TypeString(i interface{}) string {
	if t := reflect.TypeOf(i); t != nil {
		return t.String()
	}
	return "<nil>"
}
