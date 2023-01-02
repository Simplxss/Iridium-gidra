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
// source: FetterState.proto

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

type FetterState int32

const (
	FetterState_FETTER_STATE_NONE     FetterState = 0
	FetterState_FETTER_STATE_NOT_OPEN FetterState = 1
	FetterState_FETTER_STATE_OPEN     FetterState = 2
	FetterState_FETTER_STATE_FINISH   FetterState = 3
	FetterState_FETTER_STATE_CONCEAL  FetterState = 4
)

// Enum value maps for FetterState.
var (
	FetterState_name = map[int32]string{
		0: "FETTER_STATE_NONE",
		1: "FETTER_STATE_NOT_OPEN",
		2: "FETTER_STATE_OPEN",
		3: "FETTER_STATE_FINISH",
		4: "FETTER_STATE_CONCEAL",
	}
	FetterState_value = map[string]int32{
		"FETTER_STATE_NONE":     0,
		"FETTER_STATE_NOT_OPEN": 1,
		"FETTER_STATE_OPEN":     2,
		"FETTER_STATE_FINISH":   3,
		"FETTER_STATE_CONCEAL":  4,
	}
)

func (x FetterState) Enum() *FetterState {
	p := new(FetterState)
	*p = x
	return p
}

func (x FetterState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (FetterState) Descriptor() protoreflect.EnumDescriptor {
	return file_FetterState_proto_enumTypes[0].Descriptor()
}

func (FetterState) Type() protoreflect.EnumType {
	return &file_FetterState_proto_enumTypes[0]
}

func (x FetterState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use FetterState.Descriptor instead.
func (FetterState) EnumDescriptor() ([]byte, []int) {
	return file_FetterState_proto_rawDescGZIP(), []int{0}
}

var File_FetterState_proto protoreflect.FileDescriptor

var file_FetterState_proto_rawDesc = []byte{
	0x0a, 0x11, 0x46, 0x65, 0x74, 0x74, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0x89, 0x01, 0x0a, 0x0b, 0x46, 0x65, 0x74, 0x74, 0x65, 0x72, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x12, 0x15, 0x0a, 0x11, 0x46, 0x45, 0x54, 0x54, 0x45, 0x52, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x19, 0x0a, 0x15, 0x46, 0x45,
	0x54, 0x54, 0x45, 0x52, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x4f,
	0x50, 0x45, 0x4e, 0x10, 0x01, 0x12, 0x15, 0x0a, 0x11, 0x46, 0x45, 0x54, 0x54, 0x45, 0x52, 0x5f,
	0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x4f, 0x50, 0x45, 0x4e, 0x10, 0x02, 0x12, 0x17, 0x0a, 0x13,
	0x46, 0x45, 0x54, 0x54, 0x45, 0x52, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x46, 0x49, 0x4e,
	0x49, 0x53, 0x48, 0x10, 0x03, 0x12, 0x18, 0x0a, 0x14, 0x46, 0x45, 0x54, 0x54, 0x45, 0x52, 0x5f,
	0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x43, 0x4f, 0x4e, 0x43, 0x45, 0x41, 0x4c, 0x10, 0x04, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_FetterState_proto_rawDescOnce sync.Once
	file_FetterState_proto_rawDescData = file_FetterState_proto_rawDesc
)

func file_FetterState_proto_rawDescGZIP() []byte {
	file_FetterState_proto_rawDescOnce.Do(func() {
		file_FetterState_proto_rawDescData = protoimpl.X.CompressGZIP(file_FetterState_proto_rawDescData)
	})
	return file_FetterState_proto_rawDescData
}

var file_FetterState_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_FetterState_proto_goTypes = []interface{}{
	(FetterState)(0), // 0: FetterState
}
var file_FetterState_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_FetterState_proto_init() }
func file_FetterState_proto_init() {
	if File_FetterState_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_FetterState_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_FetterState_proto_goTypes,
		DependencyIndexes: file_FetterState_proto_depIdxs,
		EnumInfos:         file_FetterState_proto_enumTypes,
	}.Build()
	File_FetterState_proto = out.File
	file_FetterState_proto_rawDesc = nil
	file_FetterState_proto_goTypes = nil
	file_FetterState_proto_depIdxs = nil
}
