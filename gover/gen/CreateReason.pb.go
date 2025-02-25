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
// source: CreateReason.proto

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

// Obf: DDPMPGDLDEN
type CreateReason int32

const (
	CreateReason_CREATE_NONE   CreateReason = 0
	CreateReason_CREATE_QUEST  CreateReason = 1
	CreateReason_CREATE_ENERGY CreateReason = 2
)

// Enum value maps for CreateReason.
var (
	CreateReason_name = map[int32]string{
		0: "CREATE_NONE",
		1: "CREATE_QUEST",
		2: "CREATE_ENERGY",
	}
	CreateReason_value = map[string]int32{
		"CREATE_NONE":   0,
		"CREATE_QUEST":  1,
		"CREATE_ENERGY": 2,
	}
)

func (x CreateReason) Enum() *CreateReason {
	p := new(CreateReason)
	*p = x
	return p
}

func (x CreateReason) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (CreateReason) Descriptor() protoreflect.EnumDescriptor {
	return file_CreateReason_proto_enumTypes[0].Descriptor()
}

func (CreateReason) Type() protoreflect.EnumType {
	return &file_CreateReason_proto_enumTypes[0]
}

func (x CreateReason) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use CreateReason.Descriptor instead.
func (CreateReason) EnumDescriptor() ([]byte, []int) {
	return file_CreateReason_proto_rawDescGZIP(), []int{0}
}

var File_CreateReason_proto protoreflect.FileDescriptor

var file_CreateReason_proto_rawDesc = []byte{
	0x0a, 0x12, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x44, 0x0a, 0x0c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x61, 0x73, 0x6f, 0x6e, 0x12, 0x0f, 0x0a, 0x0b, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x5f, 0x4e,
	0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x10, 0x0a, 0x0c, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x5f,
	0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0x01, 0x12, 0x11, 0x0a, 0x0d, 0x43, 0x52, 0x45, 0x41, 0x54,
	0x45, 0x5f, 0x45, 0x4e, 0x45, 0x52, 0x47, 0x59, 0x10, 0x02, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_CreateReason_proto_rawDescOnce sync.Once
	file_CreateReason_proto_rawDescData = file_CreateReason_proto_rawDesc
)

func file_CreateReason_proto_rawDescGZIP() []byte {
	file_CreateReason_proto_rawDescOnce.Do(func() {
		file_CreateReason_proto_rawDescData = protoimpl.X.CompressGZIP(file_CreateReason_proto_rawDescData)
	})
	return file_CreateReason_proto_rawDescData
}

var file_CreateReason_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_CreateReason_proto_goTypes = []interface{}{
	(CreateReason)(0), // 0: CreateReason
}
var file_CreateReason_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_CreateReason_proto_init() }
func file_CreateReason_proto_init() {
	if File_CreateReason_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_CreateReason_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_CreateReason_proto_goTypes,
		DependencyIndexes: file_CreateReason_proto_depIdxs,
		EnumInfos:         file_CreateReason_proto_enumTypes,
	}.Build()
	File_CreateReason_proto = out.File
	file_CreateReason_proto_rawDesc = nil
	file_CreateReason_proto_goTypes = nil
	file_CreateReason_proto_depIdxs = nil
}
