package authz_test

import (
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

type kind = descriptorpb.FieldDescriptorProto_Type

const (
	stringKind  = descriptorpb.FieldDescriptorProto_TYPE_STRING
	int32Kind   = descriptorpb.FieldDescriptorProto_TYPE_INT32
	messageKind = descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
)

func field(name string, number int32, kind kind) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:   proto.String(name),
		Number: proto.Int32(number),
		Type:   kind.Enum(),
		Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
	}
}

func messageField(name string, number int32, typeName string) *descriptorpb.FieldDescriptorProto {
	f := field(name, number, messageKind)
	f.TypeName = proto.String(typeName)
	return f
}

func repeated(f *descriptorpb.FieldDescriptorProto) *descriptorpb.FieldDescriptorProto {
	f.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	return f
}

// library describes the requests of a books service, as AIP shapes them, so the
// specs have messages to name resources with and no generated code.
var library = func() protoreflect.FileDescriptor {
	file, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("test/library.proto"),
		Package: proto.String("test.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Book"), Field: []*descriptorpb.FieldDescriptorProto{
				field("name", 1, stringKind),
				field("title", 2, stringKind),
			}},
			{Name: proto.String("GetBookRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				field("name", 1, stringKind),
			}},
			{Name: proto.String("ListBooksRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				field("parent", 1, stringKind),
				field("page_size", 2, int32Kind),
			}},
			{Name: proto.String("UpdateBookRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				messageField("book", 1, ".test.v1.Book"),
			}},
			{
				Name: proto.String("BatchGetBooksRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					repeated(messageField("books", 1, ".test.v1.Book")),
					repeated(messageField("by_name", 2, ".test.v1.BatchGetBooksRequest.ByNameEntry")),
				},
				NestedType: []*descriptorpb.DescriptorProto{{
					Name:    proto.String("ByNameEntry"),
					Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
					Field: []*descriptorpb.FieldDescriptorProto{
						field("key", 1, stringKind),
						messageField("value", 2, ".test.v1.Book"),
					},
				}},
			},
			{Name: proto.String("CountRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				field("count", 1, int32Kind),
			}},
			{Name: proto.String("NumberedRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				field("name", 1, int32Kind),
			}},
		},
	}, nil)
	if err != nil {
		panic(err)
	}
	return file
}()

// message returns the message of the library that is named, from its text format.
func message(name, text string) proto.Message {
	message := dynamicpb.NewMessage(library.Messages().ByName(protoreflect.Name(name)))
	if err := prototext.Unmarshal([]byte(text), message); err != nil {
		panic(err)
	}
	return message
}

// empty returns the message of the library that is named, with nothing set.
func empty(name string) proto.Message {
	return dynamicpb.NewMessage(library.Messages().ByName(protoreflect.Name(name)))
}
