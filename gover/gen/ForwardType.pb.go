// https://github.com/SlushinPS/beach-simulator
// Copyright (C) 2023 Slushy Team
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
// 	protoc        v4.24.1
// source: ForwardType.proto

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

// Obf: CLILGMMMGCK
type ForwardType int32

const (
	ForwardType_FORWARD_TYPE_LOCAL                   ForwardType = 0
	ForwardType_FORWARD_TYPE_TO_ALL                  ForwardType = 1
	ForwardType_FORWARD_TYPE_TO_ALL_EXCEPT_CUR       ForwardType = 2
	ForwardType_FORWARD_TYPE_TO_HOST                 ForwardType = 3
	ForwardType_FORWARD_TYPE_TO_ALL_GUEST            ForwardType = 4
	ForwardType_FORWARD_TYPE_TO_PEER                 ForwardType = 5
	ForwardType_FORWARD_TYPE_TO_PEERS                ForwardType = 6
	ForwardType_FORWARD_TYPE_ONLY_SERVER             ForwardType = 7
	ForwardType_FORWARD_TYPE_TO_ALL_EXIST_EXCEPT_CUR ForwardType = 8
)

// Enum value maps for ForwardType.
var (
	ForwardType_name = map[int32]string{
		0: "FORWARD_TYPE_LOCAL",
		1: "FORWARD_TYPE_TO_ALL",
		2: "FORWARD_TYPE_TO_ALL_EXCEPT_CUR",
		3: "FORWARD_TYPE_TO_HOST",
		4: "FORWARD_TYPE_TO_ALL_GUEST",
		5: "FORWARD_TYPE_TO_PEER",
		6: "FORWARD_TYPE_TO_PEERS",
		7: "FORWARD_TYPE_ONLY_SERVER",
		8: "FORWARD_TYPE_TO_ALL_EXIST_EXCEPT_CUR",
	}
	ForwardType_value = map[string]int32{
		"FORWARD_TYPE_LOCAL":                   0,
		"FORWARD_TYPE_TO_ALL":                  1,
		"FORWARD_TYPE_TO_ALL_EXCEPT_CUR":       2,
		"FORWARD_TYPE_TO_HOST":                 3,
		"FORWARD_TYPE_TO_ALL_GUEST":            4,
		"FORWARD_TYPE_TO_PEER":                 5,
		"FORWARD_TYPE_TO_PEERS":                6,
		"FORWARD_TYPE_ONLY_SERVER":             7,
		"FORWARD_TYPE_TO_ALL_EXIST_EXCEPT_CUR": 8,
	}
)

func (x ForwardType) Enum() *ForwardType {
	p := new(ForwardType)
	*p = x
	return p
}

func (x ForwardType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ForwardType) Descriptor() protoreflect.EnumDescriptor {
	return file_ForwardType_proto_enumTypes[0].Descriptor()
}

func (ForwardType) Type() protoreflect.EnumType {
	return &file_ForwardType_proto_enumTypes[0]
}

func (x ForwardType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ForwardType.Descriptor instead.
func (ForwardType) EnumDescriptor() ([]byte, []int) {
	return file_ForwardType_proto_rawDescGZIP(), []int{0}
}

var File_ForwardType_proto protoreflect.FileDescriptor

var file_ForwardType_proto_rawDesc = []byte{
	0x0a, 0x11, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0x98, 0x02, 0x0a, 0x0b, 0x46, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x12, 0x46, 0x4f, 0x52, 0x57, 0x41, 0x52, 0x44, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x4c, 0x4f, 0x43, 0x41, 0x4c, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x46,
	0x4f, 0x52, 0x57, 0x41, 0x52, 0x44, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x54, 0x4f, 0x5f, 0x41,
	0x4c, 0x4c, 0x10, 0x01, 0x12, 0x22, 0x0a, 0x1e, 0x46, 0x4f, 0x52, 0x57, 0x41, 0x52, 0x44, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x54, 0x4f, 0x5f, 0x41, 0x4c, 0x4c, 0x5f, 0x45, 0x58, 0x43, 0x45,
	0x50, 0x54, 0x5f, 0x43, 0x55, 0x52, 0x10, 0x02, 0x12, 0x18, 0x0a, 0x14, 0x46, 0x4f, 0x52, 0x57,
	0x41, 0x52, 0x44, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x54, 0x4f, 0x5f, 0x48, 0x4f, 0x53, 0x54,
	0x10, 0x03, 0x12, 0x1d, 0x0a, 0x19, 0x46, 0x4f, 0x52, 0x57, 0x41, 0x52, 0x44, 0x5f, 0x54, 0x59,
	0x50, 0x45, 0x5f, 0x54, 0x4f, 0x5f, 0x41, 0x4c, 0x4c, 0x5f, 0x47, 0x55, 0x45, 0x53, 0x54, 0x10,
	0x04, 0x12, 0x18, 0x0a, 0x14, 0x46, 0x4f, 0x52, 0x57, 0x41, 0x52, 0x44, 0x5f, 0x54, 0x59, 0x50,
	0x45, 0x5f, 0x54, 0x4f, 0x5f, 0x50, 0x45, 0x45, 0x52, 0x10, 0x05, 0x12, 0x19, 0x0a, 0x15, 0x46,
	0x4f, 0x52, 0x57, 0x41, 0x52, 0x44, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x54, 0x4f, 0x5f, 0x50,
	0x45, 0x45, 0x52, 0x53, 0x10, 0x06, 0x12, 0x1c, 0x0a, 0x18, 0x46, 0x4f, 0x52, 0x57, 0x41, 0x52,
	0x44, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x4f, 0x4e, 0x4c, 0x59, 0x5f, 0x53, 0x45, 0x52, 0x56,
	0x45, 0x52, 0x10, 0x07, 0x12, 0x28, 0x0a, 0x24, 0x46, 0x4f, 0x52, 0x57, 0x41, 0x52, 0x44, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x54, 0x4f, 0x5f, 0x41, 0x4c, 0x4c, 0x5f, 0x45, 0x58, 0x49, 0x53,
	0x54, 0x5f, 0x45, 0x58, 0x43, 0x45, 0x50, 0x54, 0x5f, 0x43, 0x55, 0x52, 0x10, 0x08, 0x42, 0x06,
	0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ForwardType_proto_rawDescOnce sync.Once
	file_ForwardType_proto_rawDescData = file_ForwardType_proto_rawDesc
)

func file_ForwardType_proto_rawDescGZIP() []byte {
	file_ForwardType_proto_rawDescOnce.Do(func() {
		file_ForwardType_proto_rawDescData = protoimpl.X.CompressGZIP(file_ForwardType_proto_rawDescData)
	})
	return file_ForwardType_proto_rawDescData
}

var file_ForwardType_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ForwardType_proto_goTypes = []interface{}{
	(ForwardType)(0), // 0: ForwardType
}
var file_ForwardType_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ForwardType_proto_init() }
func file_ForwardType_proto_init() {
	if File_ForwardType_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ForwardType_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ForwardType_proto_goTypes,
		DependencyIndexes: file_ForwardType_proto_depIdxs,
		EnumInfos:         file_ForwardType_proto_enumTypes,
	}.Build()
	File_ForwardType_proto = out.File
	file_ForwardType_proto_rawDesc = nil
	file_ForwardType_proto_goTypes = nil
	file_ForwardType_proto_depIdxs = nil
}
