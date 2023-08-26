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
// source: GFNGKFFJHHJ.proto

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

type GFNGKFFJHHJ int32

const (
	GFNGKFFJHHJ_GFNGKFFJHHJ_None     GFNGKFFJHHJ = 0
	GFNGKFFJHHJ_GFNGKFFJHHJ_Starred  GFNGKFFJHHJ = 1
	GFNGKFFJHHJ_GFNGKFFJHHJ_Official GFNGKFFJHHJ = 2
	GFNGKFFJHHJ_GFNGKFFJHHJ_Template GFNGKFFJHHJ = 3
)

// Enum value maps for GFNGKFFJHHJ.
var (
	GFNGKFFJHHJ_name = map[int32]string{
		0: "GFNGKFFJHHJ_None",
		1: "GFNGKFFJHHJ_Starred",
		2: "GFNGKFFJHHJ_Official",
		3: "GFNGKFFJHHJ_Template",
	}
	GFNGKFFJHHJ_value = map[string]int32{
		"GFNGKFFJHHJ_None":     0,
		"GFNGKFFJHHJ_Starred":  1,
		"GFNGKFFJHHJ_Official": 2,
		"GFNGKFFJHHJ_Template": 3,
	}
)

func (x GFNGKFFJHHJ) Enum() *GFNGKFFJHHJ {
	p := new(GFNGKFFJHHJ)
	*p = x
	return p
}

func (x GFNGKFFJHHJ) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (GFNGKFFJHHJ) Descriptor() protoreflect.EnumDescriptor {
	return file_GFNGKFFJHHJ_proto_enumTypes[0].Descriptor()
}

func (GFNGKFFJHHJ) Type() protoreflect.EnumType {
	return &file_GFNGKFFJHHJ_proto_enumTypes[0]
}

func (x GFNGKFFJHHJ) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use GFNGKFFJHHJ.Descriptor instead.
func (GFNGKFFJHHJ) EnumDescriptor() ([]byte, []int) {
	return file_GFNGKFFJHHJ_proto_rawDescGZIP(), []int{0}
}

var File_GFNGKFFJHHJ_proto protoreflect.FileDescriptor

var file_GFNGKFFJHHJ_proto_rawDesc = []byte{
	0x0a, 0x11, 0x47, 0x46, 0x4e, 0x47, 0x4b, 0x46, 0x46, 0x4a, 0x48, 0x48, 0x4a, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0x70, 0x0a, 0x0b, 0x47, 0x46, 0x4e, 0x47, 0x4b, 0x46, 0x46, 0x4a, 0x48,
	0x48, 0x4a, 0x12, 0x14, 0x0a, 0x10, 0x47, 0x46, 0x4e, 0x47, 0x4b, 0x46, 0x46, 0x4a, 0x48, 0x48,
	0x4a, 0x5f, 0x4e, 0x6f, 0x6e, 0x65, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x47, 0x46, 0x4e, 0x47,
	0x4b, 0x46, 0x46, 0x4a, 0x48, 0x48, 0x4a, 0x5f, 0x53, 0x74, 0x61, 0x72, 0x72, 0x65, 0x64, 0x10,
	0x01, 0x12, 0x18, 0x0a, 0x14, 0x47, 0x46, 0x4e, 0x47, 0x4b, 0x46, 0x46, 0x4a, 0x48, 0x48, 0x4a,
	0x5f, 0x4f, 0x66, 0x66, 0x69, 0x63, 0x69, 0x61, 0x6c, 0x10, 0x02, 0x12, 0x18, 0x0a, 0x14, 0x47,
	0x46, 0x4e, 0x47, 0x4b, 0x46, 0x46, 0x4a, 0x48, 0x48, 0x4a, 0x5f, 0x54, 0x65, 0x6d, 0x70, 0x6c,
	0x61, 0x74, 0x65, 0x10, 0x03, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GFNGKFFJHHJ_proto_rawDescOnce sync.Once
	file_GFNGKFFJHHJ_proto_rawDescData = file_GFNGKFFJHHJ_proto_rawDesc
)

func file_GFNGKFFJHHJ_proto_rawDescGZIP() []byte {
	file_GFNGKFFJHHJ_proto_rawDescOnce.Do(func() {
		file_GFNGKFFJHHJ_proto_rawDescData = protoimpl.X.CompressGZIP(file_GFNGKFFJHHJ_proto_rawDescData)
	})
	return file_GFNGKFFJHHJ_proto_rawDescData
}

var file_GFNGKFFJHHJ_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_GFNGKFFJHHJ_proto_goTypes = []interface{}{
	(GFNGKFFJHHJ)(0), // 0: GFNGKFFJHHJ
}
var file_GFNGKFFJHHJ_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GFNGKFFJHHJ_proto_init() }
func file_GFNGKFFJHHJ_proto_init() {
	if File_GFNGKFFJHHJ_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_GFNGKFFJHHJ_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GFNGKFFJHHJ_proto_goTypes,
		DependencyIndexes: file_GFNGKFFJHHJ_proto_depIdxs,
		EnumInfos:         file_GFNGKFFJHHJ_proto_enumTypes,
	}.Build()
	File_GFNGKFFJHHJ_proto = out.File
	file_GFNGKFFJHHJ_proto_rawDesc = nil
	file_GFNGKFFJHHJ_proto_goTypes = nil
	file_GFNGKFFJHHJ_proto_depIdxs = nil
}
