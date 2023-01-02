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
// source: ReliquaryFilterKey.proto

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

type ReliquaryFilterKey int32

const (
	ReliquaryFilterKey_RELIQUARY_FILTER_KEY_NONE    ReliquaryFilterKey = 0
	ReliquaryFilterKey_RELIQUARY_FILTER_KEY_LOCK    ReliquaryFilterKey = 1
	ReliquaryFilterKey_RELIQUARY_FILTER_KEY_LEVEL   ReliquaryFilterKey = 2
	ReliquaryFilterKey_RELIQUARY_FILTER_KEY_WEARING ReliquaryFilterKey = 3
)

// Enum value maps for ReliquaryFilterKey.
var (
	ReliquaryFilterKey_name = map[int32]string{
		0: "RELIQUARY_FILTER_KEY_NONE",
		1: "RELIQUARY_FILTER_KEY_LOCK",
		2: "RELIQUARY_FILTER_KEY_LEVEL",
		3: "RELIQUARY_FILTER_KEY_WEARING",
	}
	ReliquaryFilterKey_value = map[string]int32{
		"RELIQUARY_FILTER_KEY_NONE":    0,
		"RELIQUARY_FILTER_KEY_LOCK":    1,
		"RELIQUARY_FILTER_KEY_LEVEL":   2,
		"RELIQUARY_FILTER_KEY_WEARING": 3,
	}
)

func (x ReliquaryFilterKey) Enum() *ReliquaryFilterKey {
	p := new(ReliquaryFilterKey)
	*p = x
	return p
}

func (x ReliquaryFilterKey) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ReliquaryFilterKey) Descriptor() protoreflect.EnumDescriptor {
	return file_ReliquaryFilterKey_proto_enumTypes[0].Descriptor()
}

func (ReliquaryFilterKey) Type() protoreflect.EnumType {
	return &file_ReliquaryFilterKey_proto_enumTypes[0]
}

func (x ReliquaryFilterKey) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ReliquaryFilterKey.Descriptor instead.
func (ReliquaryFilterKey) EnumDescriptor() ([]byte, []int) {
	return file_ReliquaryFilterKey_proto_rawDescGZIP(), []int{0}
}

var File_ReliquaryFilterKey_proto protoreflect.FileDescriptor

var file_ReliquaryFilterKey_proto_rawDesc = []byte{
	0x0a, 0x18, 0x52, 0x65, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x4b, 0x65, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x94, 0x01, 0x0a, 0x12, 0x52,
	0x65, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x4b, 0x65,
	0x79, 0x12, 0x1d, 0x0a, 0x19, 0x52, 0x45, 0x4c, 0x49, 0x51, 0x55, 0x41, 0x52, 0x59, 0x5f, 0x46,
	0x49, 0x4c, 0x54, 0x45, 0x52, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00,
	0x12, 0x1d, 0x0a, 0x19, 0x52, 0x45, 0x4c, 0x49, 0x51, 0x55, 0x41, 0x52, 0x59, 0x5f, 0x46, 0x49,
	0x4c, 0x54, 0x45, 0x52, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x4c, 0x4f, 0x43, 0x4b, 0x10, 0x01, 0x12,
	0x1e, 0x0a, 0x1a, 0x52, 0x45, 0x4c, 0x49, 0x51, 0x55, 0x41, 0x52, 0x59, 0x5f, 0x46, 0x49, 0x4c,
	0x54, 0x45, 0x52, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x4c, 0x45, 0x56, 0x45, 0x4c, 0x10, 0x02, 0x12,
	0x20, 0x0a, 0x1c, 0x52, 0x45, 0x4c, 0x49, 0x51, 0x55, 0x41, 0x52, 0x59, 0x5f, 0x46, 0x49, 0x4c,
	0x54, 0x45, 0x52, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x57, 0x45, 0x41, 0x52, 0x49, 0x4e, 0x47, 0x10,
	0x03, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_ReliquaryFilterKey_proto_rawDescOnce sync.Once
	file_ReliquaryFilterKey_proto_rawDescData = file_ReliquaryFilterKey_proto_rawDesc
)

func file_ReliquaryFilterKey_proto_rawDescGZIP() []byte {
	file_ReliquaryFilterKey_proto_rawDescOnce.Do(func() {
		file_ReliquaryFilterKey_proto_rawDescData = protoimpl.X.CompressGZIP(file_ReliquaryFilterKey_proto_rawDescData)
	})
	return file_ReliquaryFilterKey_proto_rawDescData
}

var file_ReliquaryFilterKey_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ReliquaryFilterKey_proto_goTypes = []interface{}{
	(ReliquaryFilterKey)(0), // 0: ReliquaryFilterKey
}
var file_ReliquaryFilterKey_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ReliquaryFilterKey_proto_init() }
func file_ReliquaryFilterKey_proto_init() {
	if File_ReliquaryFilterKey_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ReliquaryFilterKey_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ReliquaryFilterKey_proto_goTypes,
		DependencyIndexes: file_ReliquaryFilterKey_proto_depIdxs,
		EnumInfos:         file_ReliquaryFilterKey_proto_enumTypes,
	}.Build()
	File_ReliquaryFilterKey_proto = out.File
	file_ReliquaryFilterKey_proto_rawDesc = nil
	file_ReliquaryFilterKey_proto_goTypes = nil
	file_ReliquaryFilterKey_proto_depIdxs = nil
}
