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
// source: DNKNPOGNOFP.proto

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

type DNKNPOGNOFP int32

const (
	DNKNPOGNOFP_DNKNPOGNOFP_SandwormCannonNoneEffect   DNKNPOGNOFP = 0
	DNKNPOGNOFP_DNKNPOGNOFP_SandwormCannonWeakEffect   DNKNPOGNOFP = 1
	DNKNPOGNOFP_DNKNPOGNOFP_SandwormCannonStrongEffect DNKNPOGNOFP = 2
)

// Enum value maps for DNKNPOGNOFP.
var (
	DNKNPOGNOFP_name = map[int32]string{
		0: "DNKNPOGNOFP_SandwormCannonNoneEffect",
		1: "DNKNPOGNOFP_SandwormCannonWeakEffect",
		2: "DNKNPOGNOFP_SandwormCannonStrongEffect",
	}
	DNKNPOGNOFP_value = map[string]int32{
		"DNKNPOGNOFP_SandwormCannonNoneEffect":   0,
		"DNKNPOGNOFP_SandwormCannonWeakEffect":   1,
		"DNKNPOGNOFP_SandwormCannonStrongEffect": 2,
	}
)

func (x DNKNPOGNOFP) Enum() *DNKNPOGNOFP {
	p := new(DNKNPOGNOFP)
	*p = x
	return p
}

func (x DNKNPOGNOFP) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DNKNPOGNOFP) Descriptor() protoreflect.EnumDescriptor {
	return file_DNKNPOGNOFP_proto_enumTypes[0].Descriptor()
}

func (DNKNPOGNOFP) Type() protoreflect.EnumType {
	return &file_DNKNPOGNOFP_proto_enumTypes[0]
}

func (x DNKNPOGNOFP) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DNKNPOGNOFP.Descriptor instead.
func (DNKNPOGNOFP) EnumDescriptor() ([]byte, []int) {
	return file_DNKNPOGNOFP_proto_rawDescGZIP(), []int{0}
}

var File_DNKNPOGNOFP_proto protoreflect.FileDescriptor

var file_DNKNPOGNOFP_proto_rawDesc = []byte{
	0x0a, 0x11, 0x44, 0x4e, 0x4b, 0x4e, 0x50, 0x4f, 0x47, 0x4e, 0x4f, 0x46, 0x50, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0x8d, 0x01, 0x0a, 0x0b, 0x44, 0x4e, 0x4b, 0x4e, 0x50, 0x4f, 0x47, 0x4e,
	0x4f, 0x46, 0x50, 0x12, 0x28, 0x0a, 0x24, 0x44, 0x4e, 0x4b, 0x4e, 0x50, 0x4f, 0x47, 0x4e, 0x4f,
	0x46, 0x50, 0x5f, 0x53, 0x61, 0x6e, 0x64, 0x77, 0x6f, 0x72, 0x6d, 0x43, 0x61, 0x6e, 0x6e, 0x6f,
	0x6e, 0x4e, 0x6f, 0x6e, 0x65, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x10, 0x00, 0x12, 0x28, 0x0a,
	0x24, 0x44, 0x4e, 0x4b, 0x4e, 0x50, 0x4f, 0x47, 0x4e, 0x4f, 0x46, 0x50, 0x5f, 0x53, 0x61, 0x6e,
	0x64, 0x77, 0x6f, 0x72, 0x6d, 0x43, 0x61, 0x6e, 0x6e, 0x6f, 0x6e, 0x57, 0x65, 0x61, 0x6b, 0x45,
	0x66, 0x66, 0x65, 0x63, 0x74, 0x10, 0x01, 0x12, 0x2a, 0x0a, 0x26, 0x44, 0x4e, 0x4b, 0x4e, 0x50,
	0x4f, 0x47, 0x4e, 0x4f, 0x46, 0x50, 0x5f, 0x53, 0x61, 0x6e, 0x64, 0x77, 0x6f, 0x72, 0x6d, 0x43,
	0x61, 0x6e, 0x6e, 0x6f, 0x6e, 0x53, 0x74, 0x72, 0x6f, 0x6e, 0x67, 0x45, 0x66, 0x66, 0x65, 0x63,
	0x74, 0x10, 0x02, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_DNKNPOGNOFP_proto_rawDescOnce sync.Once
	file_DNKNPOGNOFP_proto_rawDescData = file_DNKNPOGNOFP_proto_rawDesc
)

func file_DNKNPOGNOFP_proto_rawDescGZIP() []byte {
	file_DNKNPOGNOFP_proto_rawDescOnce.Do(func() {
		file_DNKNPOGNOFP_proto_rawDescData = protoimpl.X.CompressGZIP(file_DNKNPOGNOFP_proto_rawDescData)
	})
	return file_DNKNPOGNOFP_proto_rawDescData
}

var file_DNKNPOGNOFP_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_DNKNPOGNOFP_proto_goTypes = []interface{}{
	(DNKNPOGNOFP)(0), // 0: DNKNPOGNOFP
}
var file_DNKNPOGNOFP_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_DNKNPOGNOFP_proto_init() }
func file_DNKNPOGNOFP_proto_init() {
	if File_DNKNPOGNOFP_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_DNKNPOGNOFP_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DNKNPOGNOFP_proto_goTypes,
		DependencyIndexes: file_DNKNPOGNOFP_proto_depIdxs,
		EnumInfos:         file_DNKNPOGNOFP_proto_enumTypes,
	}.Build()
	File_DNKNPOGNOFP_proto = out.File
	file_DNKNPOGNOFP_proto_rawDesc = nil
	file_DNKNPOGNOFP_proto_goTypes = nil
	file_DNKNPOGNOFP_proto_depIdxs = nil
}
