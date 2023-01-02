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
// source: HomePlantFieldStatus.proto

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

type HomePlantFieldStatus int32

const (
	HomePlantFieldStatus_HOME_PLANT_FIELD_STATUS_STATUE_NONE   HomePlantFieldStatus = 0
	HomePlantFieldStatus_HOME_PLANT_FIELD_STATUS_STATUE_SEED   HomePlantFieldStatus = 1
	HomePlantFieldStatus_HOME_PLANT_FIELD_STATUS_STATUE_SPROUT HomePlantFieldStatus = 2
	HomePlantFieldStatus_HOME_PLANT_FIELD_STATUS_STATUE_GATHER HomePlantFieldStatus = 3
)

// Enum value maps for HomePlantFieldStatus.
var (
	HomePlantFieldStatus_name = map[int32]string{
		0: "HOME_PLANT_FIELD_STATUS_STATUE_NONE",
		1: "HOME_PLANT_FIELD_STATUS_STATUE_SEED",
		2: "HOME_PLANT_FIELD_STATUS_STATUE_SPROUT",
		3: "HOME_PLANT_FIELD_STATUS_STATUE_GATHER",
	}
	HomePlantFieldStatus_value = map[string]int32{
		"HOME_PLANT_FIELD_STATUS_STATUE_NONE":   0,
		"HOME_PLANT_FIELD_STATUS_STATUE_SEED":   1,
		"HOME_PLANT_FIELD_STATUS_STATUE_SPROUT": 2,
		"HOME_PLANT_FIELD_STATUS_STATUE_GATHER": 3,
	}
)

func (x HomePlantFieldStatus) Enum() *HomePlantFieldStatus {
	p := new(HomePlantFieldStatus)
	*p = x
	return p
}

func (x HomePlantFieldStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HomePlantFieldStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_HomePlantFieldStatus_proto_enumTypes[0].Descriptor()
}

func (HomePlantFieldStatus) Type() protoreflect.EnumType {
	return &file_HomePlantFieldStatus_proto_enumTypes[0]
}

func (x HomePlantFieldStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HomePlantFieldStatus.Descriptor instead.
func (HomePlantFieldStatus) EnumDescriptor() ([]byte, []int) {
	return file_HomePlantFieldStatus_proto_rawDescGZIP(), []int{0}
}

var File_HomePlantFieldStatus_proto protoreflect.FileDescriptor

var file_HomePlantFieldStatus_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x48, 0x6f, 0x6d, 0x65, 0x50, 0x6c, 0x61, 0x6e, 0x74, 0x46, 0x69, 0x65, 0x6c, 0x64,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0xbe, 0x01, 0x0a,
	0x14, 0x48, 0x6f, 0x6d, 0x65, 0x50, 0x6c, 0x61, 0x6e, 0x74, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x27, 0x0a, 0x23, 0x48, 0x4f, 0x4d, 0x45, 0x5f, 0x50, 0x4c,
	0x41, 0x4e, 0x54, 0x5f, 0x46, 0x49, 0x45, 0x4c, 0x44, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53,
	0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x45, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x27,
	0x0a, 0x23, 0x48, 0x4f, 0x4d, 0x45, 0x5f, 0x50, 0x4c, 0x41, 0x4e, 0x54, 0x5f, 0x46, 0x49, 0x45,
	0x4c, 0x44, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x45,
	0x5f, 0x53, 0x45, 0x45, 0x44, 0x10, 0x01, 0x12, 0x29, 0x0a, 0x25, 0x48, 0x4f, 0x4d, 0x45, 0x5f,
	0x50, 0x4c, 0x41, 0x4e, 0x54, 0x5f, 0x46, 0x49, 0x45, 0x4c, 0x44, 0x5f, 0x53, 0x54, 0x41, 0x54,
	0x55, 0x53, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x45, 0x5f, 0x53, 0x50, 0x52, 0x4f, 0x55, 0x54,
	0x10, 0x02, 0x12, 0x29, 0x0a, 0x25, 0x48, 0x4f, 0x4d, 0x45, 0x5f, 0x50, 0x4c, 0x41, 0x4e, 0x54,
	0x5f, 0x46, 0x49, 0x45, 0x4c, 0x44, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x55, 0x45, 0x5f, 0x47, 0x41, 0x54, 0x48, 0x45, 0x52, 0x10, 0x03, 0x42, 0x06, 0x5a,
	0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_HomePlantFieldStatus_proto_rawDescOnce sync.Once
	file_HomePlantFieldStatus_proto_rawDescData = file_HomePlantFieldStatus_proto_rawDesc
)

func file_HomePlantFieldStatus_proto_rawDescGZIP() []byte {
	file_HomePlantFieldStatus_proto_rawDescOnce.Do(func() {
		file_HomePlantFieldStatus_proto_rawDescData = protoimpl.X.CompressGZIP(file_HomePlantFieldStatus_proto_rawDescData)
	})
	return file_HomePlantFieldStatus_proto_rawDescData
}

var file_HomePlantFieldStatus_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_HomePlantFieldStatus_proto_goTypes = []interface{}{
	(HomePlantFieldStatus)(0), // 0: HomePlantFieldStatus
}
var file_HomePlantFieldStatus_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_HomePlantFieldStatus_proto_init() }
func file_HomePlantFieldStatus_proto_init() {
	if File_HomePlantFieldStatus_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_HomePlantFieldStatus_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_HomePlantFieldStatus_proto_goTypes,
		DependencyIndexes: file_HomePlantFieldStatus_proto_depIdxs,
		EnumInfos:         file_HomePlantFieldStatus_proto_enumTypes,
	}.Build()
	File_HomePlantFieldStatus_proto = out.File
	file_HomePlantFieldStatus_proto_rawDesc = nil
	file_HomePlantFieldStatus_proto_goTypes = nil
	file_HomePlantFieldStatus_proto_depIdxs = nil
}
