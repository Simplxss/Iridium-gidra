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
// source: CNBAFAGNCLI.proto

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

type CNBAFAGNCLI int32

const (
	CNBAFAGNCLI_CNBAFAGNCLI_CustomGalleryScoreBoardNormal    CNBAFAGNCLI = 0
	CNBAFAGNCLI_CNBAFAGNCLI_CustomGalleryScoreBoardCountdown CNBAFAGNCLI = 1
	CNBAFAGNCLI_CNBAFAGNCLI_CustomGalleryScoreBoardTimer     CNBAFAGNCLI = 2
)

// Enum value maps for CNBAFAGNCLI.
var (
	CNBAFAGNCLI_name = map[int32]string{
		0: "CNBAFAGNCLI_CustomGalleryScoreBoardNormal",
		1: "CNBAFAGNCLI_CustomGalleryScoreBoardCountdown",
		2: "CNBAFAGNCLI_CustomGalleryScoreBoardTimer",
	}
	CNBAFAGNCLI_value = map[string]int32{
		"CNBAFAGNCLI_CustomGalleryScoreBoardNormal":    0,
		"CNBAFAGNCLI_CustomGalleryScoreBoardCountdown": 1,
		"CNBAFAGNCLI_CustomGalleryScoreBoardTimer":     2,
	}
)

func (x CNBAFAGNCLI) Enum() *CNBAFAGNCLI {
	p := new(CNBAFAGNCLI)
	*p = x
	return p
}

func (x CNBAFAGNCLI) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (CNBAFAGNCLI) Descriptor() protoreflect.EnumDescriptor {
	return file_CNBAFAGNCLI_proto_enumTypes[0].Descriptor()
}

func (CNBAFAGNCLI) Type() protoreflect.EnumType {
	return &file_CNBAFAGNCLI_proto_enumTypes[0]
}

func (x CNBAFAGNCLI) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use CNBAFAGNCLI.Descriptor instead.
func (CNBAFAGNCLI) EnumDescriptor() ([]byte, []int) {
	return file_CNBAFAGNCLI_proto_rawDescGZIP(), []int{0}
}

var File_CNBAFAGNCLI_proto protoreflect.FileDescriptor

var file_CNBAFAGNCLI_proto_rawDesc = []byte{
	0x0a, 0x11, 0x43, 0x4e, 0x42, 0x41, 0x46, 0x41, 0x47, 0x4e, 0x43, 0x4c, 0x49, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0x9c, 0x01, 0x0a, 0x0b, 0x43, 0x4e, 0x42, 0x41, 0x46, 0x41, 0x47, 0x4e,
	0x43, 0x4c, 0x49, 0x12, 0x2d, 0x0a, 0x29, 0x43, 0x4e, 0x42, 0x41, 0x46, 0x41, 0x47, 0x4e, 0x43,
	0x4c, 0x49, 0x5f, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79,
	0x53, 0x63, 0x6f, 0x72, 0x65, 0x42, 0x6f, 0x61, 0x72, 0x64, 0x4e, 0x6f, 0x72, 0x6d, 0x61, 0x6c,
	0x10, 0x00, 0x12, 0x30, 0x0a, 0x2c, 0x43, 0x4e, 0x42, 0x41, 0x46, 0x41, 0x47, 0x4e, 0x43, 0x4c,
	0x49, 0x5f, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53,
	0x63, 0x6f, 0x72, 0x65, 0x42, 0x6f, 0x61, 0x72, 0x64, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x64, 0x6f,
	0x77, 0x6e, 0x10, 0x01, 0x12, 0x2c, 0x0a, 0x28, 0x43, 0x4e, 0x42, 0x41, 0x46, 0x41, 0x47, 0x4e,
	0x43, 0x4c, 0x49, 0x5f, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72,
	0x79, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x42, 0x6f, 0x61, 0x72, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x72,
	0x10, 0x02, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_CNBAFAGNCLI_proto_rawDescOnce sync.Once
	file_CNBAFAGNCLI_proto_rawDescData = file_CNBAFAGNCLI_proto_rawDesc
)

func file_CNBAFAGNCLI_proto_rawDescGZIP() []byte {
	file_CNBAFAGNCLI_proto_rawDescOnce.Do(func() {
		file_CNBAFAGNCLI_proto_rawDescData = protoimpl.X.CompressGZIP(file_CNBAFAGNCLI_proto_rawDescData)
	})
	return file_CNBAFAGNCLI_proto_rawDescData
}

var file_CNBAFAGNCLI_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_CNBAFAGNCLI_proto_goTypes = []interface{}{
	(CNBAFAGNCLI)(0), // 0: CNBAFAGNCLI
}
var file_CNBAFAGNCLI_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_CNBAFAGNCLI_proto_init() }
func file_CNBAFAGNCLI_proto_init() {
	if File_CNBAFAGNCLI_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_CNBAFAGNCLI_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_CNBAFAGNCLI_proto_goTypes,
		DependencyIndexes: file_CNBAFAGNCLI_proto_depIdxs,
		EnumInfos:         file_CNBAFAGNCLI_proto_enumTypes,
	}.Build()
	File_CNBAFAGNCLI_proto = out.File
	file_CNBAFAGNCLI_proto_rawDesc = nil
	file_CNBAFAGNCLI_proto_goTypes = nil
	file_CNBAFAGNCLI_proto_depIdxs = nil
}
