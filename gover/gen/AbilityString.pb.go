// Sorapointa - A server software re-implementation for a certain anime game, and avoid sorapointa.
// Copyright (C) 2022  Sorapointa Team
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.11.3
// source: AbilityString.proto

package gen

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AbilityString struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Type:
	//
	//	*AbilityString_Str
	//	*AbilityString_Hash
	Type isAbilityString_Type `protobuf_oneof:"type"`
}

func (x *AbilityString) Reset() {
	*x = AbilityString{}
	if protoimpl.UnsafeEnabled {
		mi := &file_AbilityString_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AbilityString) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AbilityString) ProtoMessage() {}

func (x *AbilityString) ProtoReflect() protoreflect.Message {
	mi := &file_AbilityString_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AbilityString.ProtoReflect.Descriptor instead.
func (*AbilityString) Descriptor() ([]byte, []int) {
	return file_AbilityString_proto_rawDescGZIP(), []int{0}
}

func (m *AbilityString) GetType() isAbilityString_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (x *AbilityString) GetStr() string {
	if x, ok := x.GetType().(*AbilityString_Str); ok {
		return x.Str
	}
	return ""
}

func (x *AbilityString) GetHash() uint32 {
	if x, ok := x.GetType().(*AbilityString_Hash); ok {
		return x.Hash
	}
	return 0
}

type isAbilityString_Type interface {
	isAbilityString_Type()
}

type AbilityString_Str struct {
	Str string `protobuf:"bytes,1,opt,name=str,proto3,oneof"`
}

type AbilityString_Hash struct {
	Hash uint32 `protobuf:"varint,2,opt,name=hash,proto3,oneof"`
}

func (*AbilityString_Str) isAbilityString_Type() {}

func (*AbilityString_Hash) isAbilityString_Type() {}

var File_AbilityString_proto protoreflect.FileDescriptor

var file_AbilityString_proto_rawDesc = []byte{
	0x0a, 0x13, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x41, 0x0a, 0x0d, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79,
	0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x12, 0x12, 0x0a, 0x03, 0x73, 0x74, 0x72, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x03, 0x73, 0x74, 0x72, 0x12, 0x14, 0x0a, 0x04, 0x68, 0x61,
	0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x48, 0x00, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68,
	0x42, 0x06, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_AbilityString_proto_rawDescOnce sync.Once
	file_AbilityString_proto_rawDescData = file_AbilityString_proto_rawDesc
)

func file_AbilityString_proto_rawDescGZIP() []byte {
	file_AbilityString_proto_rawDescOnce.Do(func() {
		file_AbilityString_proto_rawDescData = protoimpl.X.CompressGZIP(file_AbilityString_proto_rawDescData)
	})
	return file_AbilityString_proto_rawDescData
}

var file_AbilityString_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_AbilityString_proto_goTypes = []interface{}{
	(*AbilityString)(nil), // 0: AbilityString
}
var file_AbilityString_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_AbilityString_proto_init() }
func file_AbilityString_proto_init() {
	if File_AbilityString_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_AbilityString_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AbilityString); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_AbilityString_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*AbilityString_Str)(nil),
		(*AbilityString_Hash)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_AbilityString_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_AbilityString_proto_goTypes,
		DependencyIndexes: file_AbilityString_proto_depIdxs,
		MessageInfos:      file_AbilityString_proto_msgTypes,
	}.Build()
	File_AbilityString_proto = out.File
	file_AbilityString_proto_rawDesc = nil
	file_AbilityString_proto_goTypes = nil
	file_AbilityString_proto_depIdxs = nil
}
