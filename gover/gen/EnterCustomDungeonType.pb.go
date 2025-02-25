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
// source: EnterCustomDungeonType.proto

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

// Obf: PCCMGHKHKNL
type EnterCustomDungeonType int32

const (
	EnterCustomDungeonType_ENTER_CUSTOM_DUNGEON_NONE     EnterCustomDungeonType = 0
	EnterCustomDungeonType_ENTER_CUSTOM_DUNGEON_EDIT     EnterCustomDungeonType = 1
	EnterCustomDungeonType_ENTER_CUSTOM_DUNGEON_PLAY     EnterCustomDungeonType = 2
	EnterCustomDungeonType_ENTER_CUSTOM_DUNGEON_OFFICIAL EnterCustomDungeonType = 3
)

// Enum value maps for EnterCustomDungeonType.
var (
	EnterCustomDungeonType_name = map[int32]string{
		0: "ENTER_CUSTOM_DUNGEON_NONE",
		1: "ENTER_CUSTOM_DUNGEON_EDIT",
		2: "ENTER_CUSTOM_DUNGEON_PLAY",
		3: "ENTER_CUSTOM_DUNGEON_OFFICIAL",
	}
	EnterCustomDungeonType_value = map[string]int32{
		"ENTER_CUSTOM_DUNGEON_NONE":     0,
		"ENTER_CUSTOM_DUNGEON_EDIT":     1,
		"ENTER_CUSTOM_DUNGEON_PLAY":     2,
		"ENTER_CUSTOM_DUNGEON_OFFICIAL": 3,
	}
)

func (x EnterCustomDungeonType) Enum() *EnterCustomDungeonType {
	p := new(EnterCustomDungeonType)
	*p = x
	return p
}

func (x EnterCustomDungeonType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EnterCustomDungeonType) Descriptor() protoreflect.EnumDescriptor {
	return file_EnterCustomDungeonType_proto_enumTypes[0].Descriptor()
}

func (EnterCustomDungeonType) Type() protoreflect.EnumType {
	return &file_EnterCustomDungeonType_proto_enumTypes[0]
}

func (x EnterCustomDungeonType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EnterCustomDungeonType.Descriptor instead.
func (EnterCustomDungeonType) EnumDescriptor() ([]byte, []int) {
	return file_EnterCustomDungeonType_proto_rawDescGZIP(), []int{0}
}

var File_EnterCustomDungeonType_proto protoreflect.FileDescriptor

var file_EnterCustomDungeonType_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e,
	0x67, 0x65, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x98,
	0x01, 0x0a, 0x16, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75,
	0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1d, 0x0a, 0x19, 0x45, 0x4e, 0x54,
	0x45, 0x52, 0x5f, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x5f, 0x44, 0x55, 0x4e, 0x47, 0x45, 0x4f,
	0x4e, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x1d, 0x0a, 0x19, 0x45, 0x4e, 0x54, 0x45,
	0x52, 0x5f, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x5f, 0x44, 0x55, 0x4e, 0x47, 0x45, 0x4f, 0x4e,
	0x5f, 0x45, 0x44, 0x49, 0x54, 0x10, 0x01, 0x12, 0x1d, 0x0a, 0x19, 0x45, 0x4e, 0x54, 0x45, 0x52,
	0x5f, 0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x5f, 0x44, 0x55, 0x4e, 0x47, 0x45, 0x4f, 0x4e, 0x5f,
	0x50, 0x4c, 0x41, 0x59, 0x10, 0x02, 0x12, 0x21, 0x0a, 0x1d, 0x45, 0x4e, 0x54, 0x45, 0x52, 0x5f,
	0x43, 0x55, 0x53, 0x54, 0x4f, 0x4d, 0x5f, 0x44, 0x55, 0x4e, 0x47, 0x45, 0x4f, 0x4e, 0x5f, 0x4f,
	0x46, 0x46, 0x49, 0x43, 0x49, 0x41, 0x4c, 0x10, 0x03, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_EnterCustomDungeonType_proto_rawDescOnce sync.Once
	file_EnterCustomDungeonType_proto_rawDescData = file_EnterCustomDungeonType_proto_rawDesc
)

func file_EnterCustomDungeonType_proto_rawDescGZIP() []byte {
	file_EnterCustomDungeonType_proto_rawDescOnce.Do(func() {
		file_EnterCustomDungeonType_proto_rawDescData = protoimpl.X.CompressGZIP(file_EnterCustomDungeonType_proto_rawDescData)
	})
	return file_EnterCustomDungeonType_proto_rawDescData
}

var file_EnterCustomDungeonType_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_EnterCustomDungeonType_proto_goTypes = []interface{}{
	(EnterCustomDungeonType)(0), // 0: EnterCustomDungeonType
}
var file_EnterCustomDungeonType_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_EnterCustomDungeonType_proto_init() }
func file_EnterCustomDungeonType_proto_init() {
	if File_EnterCustomDungeonType_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_EnterCustomDungeonType_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_EnterCustomDungeonType_proto_goTypes,
		DependencyIndexes: file_EnterCustomDungeonType_proto_depIdxs,
		EnumInfos:         file_EnterCustomDungeonType_proto_enumTypes,
	}.Build()
	File_EnterCustomDungeonType_proto = out.File
	file_EnterCustomDungeonType_proto_rawDesc = nil
	file_EnterCustomDungeonType_proto_goTypes = nil
	file_EnterCustomDungeonType_proto_depIdxs = nil
}
