package typed

import "github.com/zhouchenh/go-descriptor"

type Value struct {
	Type  string
	Value interface{}
}

var ValueDescriptor = descriptor.Descriptor{
	Type: descriptor.TypeOfNew(new(Value)),
	Filler: descriptor.Fillers{
		descriptor.ObjectFiller{
			ObjectPath: descriptor.Path{"Type"},
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath:     descriptor.Path{"type"},
				AssignableKind: descriptor.KindString,
			},
		},
		descriptor.ObjectFiller{
			ObjectPath: descriptor.Path{"Value"},
			ValueSource: descriptor.ValueSources{
				descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"config"},
					AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
						return i, true
					}),
				},
				descriptor.DefaultValue{Value: nil},
			},
		},
	},
}
