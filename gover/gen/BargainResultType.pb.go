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
// source: BargainResultType.proto

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

// Obf: AGEMDFOGNBD
type BargainResultType int32

const (
	BargainResultType_BARGAIN_COMPLETE_SUCC BargainResultType = 0
	BargainResultType_BARGAIN_SINGLE_FAIL   BargainResultType = 1
	BargainResultType_BARGAIN_COMPLETE_FAIL BargainResultType = 2
)

// Enum value maps for BargainResultType.
var (
	BargainResultType_name = map[int32]string{
		0: "BARGAIN_COMPLETE_SUCC",
		1: "BARGAIN_SINGLE_FAIL",
		2: "BARGAIN_COMPLETE_FAIL",
	}
	BargainResultType_value = map[string]int32{
		"BARGAIN_COMPLETE_SUCC": 0,
		"BARGAIN_SINGLE_FAIL":   1,
		"BARGAIN_COMPLETE_FAIL": 2,
	}
)

func (x BargainResultType) Enum() *BargainResultType {
	p := new(BargainResultType)
	*p = x
	return p
}

func (x BargainResultType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (BargainResultType) Descriptor() protoreflect.EnumDescriptor {
	return file_BargainResultType_proto_enumTypes[0].Descriptor()
}

func (BargainResultType) Type() protoreflect.EnumType {
	return &file_BargainResultType_proto_enumTypes[0]
}

func (x BargainResultType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use BargainResultType.Descriptor instead.
func (BargainResultType) EnumDescriptor() ([]byte, []int) {
	return file_BargainResultType_proto_rawDescGZIP(), []int{0}
}

var File_BargainResultType_proto protoreflect.FileDescriptor

var file_BargainResultType_proto_rawDesc = []byte{
	0x0a, 0x17, 0x42, 0x61, 0x72, 0x67, 0x61, 0x69, 0x6e, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x54,
	0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x62, 0x0a, 0x11, 0x42, 0x61, 0x72,
	0x67, 0x61, 0x69, 0x6e, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x19,
	0x0a, 0x15, 0x42, 0x41, 0x52, 0x47, 0x41, 0x49, 0x4e, 0x5f, 0x43, 0x4f, 0x4d, 0x50, 0x4c, 0x45,
	0x54, 0x45, 0x5f, 0x53, 0x55, 0x43, 0x43, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x42, 0x41, 0x52,
	0x47, 0x41, 0x49, 0x4e, 0x5f, 0x53, 0x49, 0x4e, 0x47, 0x4c, 0x45, 0x5f, 0x46, 0x41, 0x49, 0x4c,
	0x10, 0x01, 0x12, 0x19, 0x0a, 0x15, 0x42, 0x41, 0x52, 0x47, 0x41, 0x49, 0x4e, 0x5f, 0x43, 0x4f,
	0x4d, 0x50, 0x4c, 0x45, 0x54, 0x45, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x10, 0x02, 0x42, 0x06, 0x5a,
	0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_BargainResultType_proto_rawDescOnce sync.Once
	file_BargainResultType_proto_rawDescData = file_BargainResultType_proto_rawDesc
)

func file_BargainResultType_proto_rawDescGZIP() []byte {
	file_BargainResultType_proto_rawDescOnce.Do(func() {
		file_BargainResultType_proto_rawDescData = protoimpl.X.CompressGZIP(file_BargainResultType_proto_rawDescData)
	})
	return file_BargainResultType_proto_rawDescData
}

var file_BargainResultType_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_BargainResultType_proto_goTypes = []interface{}{
	(BargainResultType)(0), // 0: BargainResultType
}
var file_BargainResultType_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_BargainResultType_proto_init() }
func file_BargainResultType_proto_init() {
	if File_BargainResultType_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_BargainResultType_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_BargainResultType_proto_goTypes,
		DependencyIndexes: file_BargainResultType_proto_depIdxs,
		EnumInfos:         file_BargainResultType_proto_enumTypes,
	}.Build()
	File_BargainResultType_proto = out.File
	file_BargainResultType_proto_rawDesc = nil
	file_BargainResultType_proto_goTypes = nil
	file_BargainResultType_proto_depIdxs = nil
}
