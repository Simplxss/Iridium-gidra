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
// source: FDGOOBGNJMP.proto

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

type FDGOOBGNJMP int32

const (
	FDGOOBGNJMP_FDGOOBGNJMP_EnterUgcDungeonNone               FDGOOBGNJMP = 0
	FDGOOBGNJMP_FDGOOBGNJMP_EnterUgcDungeonTrialInEditDungeon FDGOOBGNJMP = 1
	FDGOOBGNJMP_FDGOOBGNJMP_EnterUgcDungeonTrialInWorld       FDGOOBGNJMP = 2
	FDGOOBGNJMP_FDGOOBGNJMP_EnterUgcDungeonPlay               FDGOOBGNJMP = 3
	FDGOOBGNJMP_FDGOOBGNJMP_EnterUgcDungeonOfficial           FDGOOBGNJMP = 4
	FDGOOBGNJMP_FDGOOBGNJMP_EnterUgcDungeonByGm               FDGOOBGNJMP = 5
	FDGOOBGNJMP_FDGOOBGNJMP_EnterUgcDungeonByEdit             FDGOOBGNJMP = 6
	FDGOOBGNJMP_FDGOOBGNJMP_EnterUgcDungeonTrialOneRoom       FDGOOBGNJMP = 7
)

// Enum value maps for FDGOOBGNJMP.
var (
	FDGOOBGNJMP_name = map[int32]string{
		0: "FDGOOBGNJMP_EnterUgcDungeonNone",
		1: "FDGOOBGNJMP_EnterUgcDungeonTrialInEditDungeon",
		2: "FDGOOBGNJMP_EnterUgcDungeonTrialInWorld",
		3: "FDGOOBGNJMP_EnterUgcDungeonPlay",
		4: "FDGOOBGNJMP_EnterUgcDungeonOfficial",
		5: "FDGOOBGNJMP_EnterUgcDungeonByGm",
		6: "FDGOOBGNJMP_EnterUgcDungeonByEdit",
		7: "FDGOOBGNJMP_EnterUgcDungeonTrialOneRoom",
	}
	FDGOOBGNJMP_value = map[string]int32{
		"FDGOOBGNJMP_EnterUgcDungeonNone":               0,
		"FDGOOBGNJMP_EnterUgcDungeonTrialInEditDungeon": 1,
		"FDGOOBGNJMP_EnterUgcDungeonTrialInWorld":       2,
		"FDGOOBGNJMP_EnterUgcDungeonPlay":               3,
		"FDGOOBGNJMP_EnterUgcDungeonOfficial":           4,
		"FDGOOBGNJMP_EnterUgcDungeonByGm":               5,
		"FDGOOBGNJMP_EnterUgcDungeonByEdit":             6,
		"FDGOOBGNJMP_EnterUgcDungeonTrialOneRoom":       7,
	}
)

func (x FDGOOBGNJMP) Enum() *FDGOOBGNJMP {
	p := new(FDGOOBGNJMP)
	*p = x
	return p
}

func (x FDGOOBGNJMP) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (FDGOOBGNJMP) Descriptor() protoreflect.EnumDescriptor {
	return file_FDGOOBGNJMP_proto_enumTypes[0].Descriptor()
}

func (FDGOOBGNJMP) Type() protoreflect.EnumType {
	return &file_FDGOOBGNJMP_proto_enumTypes[0]
}

func (x FDGOOBGNJMP) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use FDGOOBGNJMP.Descriptor instead.
func (FDGOOBGNJMP) EnumDescriptor() ([]byte, []int) {
	return file_FDGOOBGNJMP_proto_rawDescGZIP(), []int{0}
}

var File_FDGOOBGNJMP_proto protoreflect.FileDescriptor

var file_FDGOOBGNJMP_proto_rawDesc = []byte{
	0x0a, 0x11, 0x46, 0x44, 0x47, 0x4f, 0x4f, 0x42, 0x47, 0x4e, 0x4a, 0x4d, 0x50, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0xd9, 0x02, 0x0a, 0x0b, 0x46, 0x44, 0x47, 0x4f, 0x4f, 0x42, 0x47, 0x4e,
	0x4a, 0x4d, 0x50, 0x12, 0x23, 0x0a, 0x1f, 0x46, 0x44, 0x47, 0x4f, 0x4f, 0x42, 0x47, 0x4e, 0x4a,
	0x4d, 0x50, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65,
	0x6f, 0x6e, 0x4e, 0x6f, 0x6e, 0x65, 0x10, 0x00, 0x12, 0x31, 0x0a, 0x2d, 0x46, 0x44, 0x47, 0x4f,
	0x4f, 0x42, 0x47, 0x4e, 0x4a, 0x4d, 0x50, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63,
	0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x54, 0x72, 0x69, 0x61, 0x6c, 0x49, 0x6e, 0x45, 0x64,
	0x69, 0x74, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x10, 0x01, 0x12, 0x2b, 0x0a, 0x27, 0x46,
	0x44, 0x47, 0x4f, 0x4f, 0x42, 0x47, 0x4e, 0x4a, 0x4d, 0x50, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72,
	0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x54, 0x72, 0x69, 0x61, 0x6c, 0x49,
	0x6e, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x10, 0x02, 0x12, 0x23, 0x0a, 0x1f, 0x46, 0x44, 0x47, 0x4f,
	0x4f, 0x42, 0x47, 0x4e, 0x4a, 0x4d, 0x50, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63,
	0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x50, 0x6c, 0x61, 0x79, 0x10, 0x03, 0x12, 0x27, 0x0a,
	0x23, 0x46, 0x44, 0x47, 0x4f, 0x4f, 0x42, 0x47, 0x4e, 0x4a, 0x4d, 0x50, 0x5f, 0x45, 0x6e, 0x74,
	0x65, 0x72, 0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x4f, 0x66, 0x66, 0x69,
	0x63, 0x69, 0x61, 0x6c, 0x10, 0x04, 0x12, 0x23, 0x0a, 0x1f, 0x46, 0x44, 0x47, 0x4f, 0x4f, 0x42,
	0x47, 0x4e, 0x4a, 0x4d, 0x50, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63, 0x44, 0x75,
	0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x42, 0x79, 0x47, 0x6d, 0x10, 0x05, 0x12, 0x25, 0x0a, 0x21, 0x46,
	0x44, 0x47, 0x4f, 0x4f, 0x42, 0x47, 0x4e, 0x4a, 0x4d, 0x50, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72,
	0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x42, 0x79, 0x45, 0x64, 0x69, 0x74,
	0x10, 0x06, 0x12, 0x2b, 0x0a, 0x27, 0x46, 0x44, 0x47, 0x4f, 0x4f, 0x42, 0x47, 0x4e, 0x4a, 0x4d,
	0x50, 0x5f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x55, 0x67, 0x63, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f,
	0x6e, 0x54, 0x72, 0x69, 0x61, 0x6c, 0x4f, 0x6e, 0x65, 0x52, 0x6f, 0x6f, 0x6d, 0x10, 0x07, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_FDGOOBGNJMP_proto_rawDescOnce sync.Once
	file_FDGOOBGNJMP_proto_rawDescData = file_FDGOOBGNJMP_proto_rawDesc
)

func file_FDGOOBGNJMP_proto_rawDescGZIP() []byte {
	file_FDGOOBGNJMP_proto_rawDescOnce.Do(func() {
		file_FDGOOBGNJMP_proto_rawDescData = protoimpl.X.CompressGZIP(file_FDGOOBGNJMP_proto_rawDescData)
	})
	return file_FDGOOBGNJMP_proto_rawDescData
}

var file_FDGOOBGNJMP_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_FDGOOBGNJMP_proto_goTypes = []interface{}{
	(FDGOOBGNJMP)(0), // 0: FDGOOBGNJMP
}
var file_FDGOOBGNJMP_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_FDGOOBGNJMP_proto_init() }
func file_FDGOOBGNJMP_proto_init() {
	if File_FDGOOBGNJMP_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_FDGOOBGNJMP_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_FDGOOBGNJMP_proto_goTypes,
		DependencyIndexes: file_FDGOOBGNJMP_proto_depIdxs,
		EnumInfos:         file_FDGOOBGNJMP_proto_enumTypes,
	}.Build()
	File_FDGOOBGNJMP_proto = out.File
	file_FDGOOBGNJMP_proto_rawDesc = nil
	file_FDGOOBGNJMP_proto_goTypes = nil
	file_FDGOOBGNJMP_proto_depIdxs = nil
}
