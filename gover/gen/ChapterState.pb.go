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
// source: ChapterState.proto

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

// Obf: IGBMFOLFJLJ
type ChapterState int32

const (
	ChapterState_CHAPTER_STATE_INVALID         ChapterState = 0
	ChapterState_CHAPTER_STATE_UNABLE_TO_BEGIN ChapterState = 1
	ChapterState_CHAPTER_STATE_BEGIN           ChapterState = 2
	ChapterState_CHAPTER_STATE_END             ChapterState = 3
)

// Enum value maps for ChapterState.
var (
	ChapterState_name = map[int32]string{
		0: "CHAPTER_STATE_INVALID",
		1: "CHAPTER_STATE_UNABLE_TO_BEGIN",
		2: "CHAPTER_STATE_BEGIN",
		3: "CHAPTER_STATE_END",
	}
	ChapterState_value = map[string]int32{
		"CHAPTER_STATE_INVALID":         0,
		"CHAPTER_STATE_UNABLE_TO_BEGIN": 1,
		"CHAPTER_STATE_BEGIN":           2,
		"CHAPTER_STATE_END":             3,
	}
)

func (x ChapterState) Enum() *ChapterState {
	p := new(ChapterState)
	*p = x
	return p
}

func (x ChapterState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ChapterState) Descriptor() protoreflect.EnumDescriptor {
	return file_ChapterState_proto_enumTypes[0].Descriptor()
}

func (ChapterState) Type() protoreflect.EnumType {
	return &file_ChapterState_proto_enumTypes[0]
}

func (x ChapterState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ChapterState.Descriptor instead.
func (ChapterState) EnumDescriptor() ([]byte, []int) {
	return file_ChapterState_proto_rawDescGZIP(), []int{0}
}

var File_ChapterState_proto protoreflect.FileDescriptor

var file_ChapterState_proto_rawDesc = []byte{
	0x0a, 0x12, 0x43, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x7c, 0x0a, 0x0c, 0x43, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x12, 0x19, 0x0a, 0x15, 0x43, 0x48, 0x41, 0x50, 0x54, 0x45, 0x52, 0x5f,
	0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x00, 0x12,
	0x21, 0x0a, 0x1d, 0x43, 0x48, 0x41, 0x50, 0x54, 0x45, 0x52, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45,
	0x5f, 0x55, 0x4e, 0x41, 0x42, 0x4c, 0x45, 0x5f, 0x54, 0x4f, 0x5f, 0x42, 0x45, 0x47, 0x49, 0x4e,
	0x10, 0x01, 0x12, 0x17, 0x0a, 0x13, 0x43, 0x48, 0x41, 0x50, 0x54, 0x45, 0x52, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x10, 0x02, 0x12, 0x15, 0x0a, 0x11, 0x43,
	0x48, 0x41, 0x50, 0x54, 0x45, 0x52, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x45, 0x4e, 0x44,
	0x10, 0x03, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_ChapterState_proto_rawDescOnce sync.Once
	file_ChapterState_proto_rawDescData = file_ChapterState_proto_rawDesc
)

func file_ChapterState_proto_rawDescGZIP() []byte {
	file_ChapterState_proto_rawDescOnce.Do(func() {
		file_ChapterState_proto_rawDescData = protoimpl.X.CompressGZIP(file_ChapterState_proto_rawDescData)
	})
	return file_ChapterState_proto_rawDescData
}

var file_ChapterState_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ChapterState_proto_goTypes = []interface{}{
	(ChapterState)(0), // 0: ChapterState
}
var file_ChapterState_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ChapterState_proto_init() }
func file_ChapterState_proto_init() {
	if File_ChapterState_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ChapterState_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ChapterState_proto_goTypes,
		DependencyIndexes: file_ChapterState_proto_depIdxs,
		EnumInfos:         file_ChapterState_proto_enumTypes,
	}.Build()
	File_ChapterState_proto = out.File
	file_ChapterState_proto_rawDesc = nil
	file_ChapterState_proto_goTypes = nil
	file_ChapterState_proto_depIdxs = nil
}
