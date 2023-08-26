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
// source: MatchReason.proto

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

// Obf: LKAMMLNBBDM
type MatchReason int32

const (
	MatchReason_MATCH_NONE            MatchReason = 0
	MatchReason_MATCH_FINISH          MatchReason = 1
	MatchReason_MATCH_PLAYER_CANCEL   MatchReason = 2
	MatchReason_MATCH_TIMEOUT         MatchReason = 3
	MatchReason_MATCH_PLAYER_CONFIRM  MatchReason = 4
	MatchReason_MATCH_FAILED          MatchReason = 5
	MatchReason_MATCH_SYSTEM_ERROR    MatchReason = 6
	MatchReason_MATCH_INTERRUPTED     MatchReason = 7
	MatchReason_MATCH_MP_UNAVAILABLE  MatchReason = 8
	MatchReason_MATCH_CONFIRM_TIMEOUT MatchReason = 9
)

// Enum value maps for MatchReason.
var (
	MatchReason_name = map[int32]string{
		0: "MATCH_NONE",
		1: "MATCH_FINISH",
		2: "MATCH_PLAYER_CANCEL",
		3: "MATCH_TIMEOUT",
		4: "MATCH_PLAYER_CONFIRM",
		5: "MATCH_FAILED",
		6: "MATCH_SYSTEM_ERROR",
		7: "MATCH_INTERRUPTED",
		8: "MATCH_MP_UNAVAILABLE",
		9: "MATCH_CONFIRM_TIMEOUT",
	}
	MatchReason_value = map[string]int32{
		"MATCH_NONE":            0,
		"MATCH_FINISH":          1,
		"MATCH_PLAYER_CANCEL":   2,
		"MATCH_TIMEOUT":         3,
		"MATCH_PLAYER_CONFIRM":  4,
		"MATCH_FAILED":          5,
		"MATCH_SYSTEM_ERROR":    6,
		"MATCH_INTERRUPTED":     7,
		"MATCH_MP_UNAVAILABLE":  8,
		"MATCH_CONFIRM_TIMEOUT": 9,
	}
)

func (x MatchReason) Enum() *MatchReason {
	p := new(MatchReason)
	*p = x
	return p
}

func (x MatchReason) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MatchReason) Descriptor() protoreflect.EnumDescriptor {
	return file_MatchReason_proto_enumTypes[0].Descriptor()
}

func (MatchReason) Type() protoreflect.EnumType {
	return &file_MatchReason_proto_enumTypes[0]
}

func (x MatchReason) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MatchReason.Descriptor instead.
func (MatchReason) EnumDescriptor() ([]byte, []int) {
	return file_MatchReason_proto_rawDescGZIP(), []int{0}
}

var File_MatchReason_proto protoreflect.FileDescriptor

var file_MatchReason_proto_rawDesc = []byte{
	0x0a, 0x11, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0xeb, 0x01, 0x0a, 0x0b, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x52, 0x65, 0x61,
	0x73, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x0a, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x4e, 0x4f, 0x4e,
	0x45, 0x10, 0x00, 0x12, 0x10, 0x0a, 0x0c, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x46, 0x49, 0x4e,
	0x49, 0x53, 0x48, 0x10, 0x01, 0x12, 0x17, 0x0a, 0x13, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x50,
	0x4c, 0x41, 0x59, 0x45, 0x52, 0x5f, 0x43, 0x41, 0x4e, 0x43, 0x45, 0x4c, 0x10, 0x02, 0x12, 0x11,
	0x0a, 0x0d, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x54, 0x49, 0x4d, 0x45, 0x4f, 0x55, 0x54, 0x10,
	0x03, 0x12, 0x18, 0x0a, 0x14, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x50, 0x4c, 0x41, 0x59, 0x45,
	0x52, 0x5f, 0x43, 0x4f, 0x4e, 0x46, 0x49, 0x52, 0x4d, 0x10, 0x04, 0x12, 0x10, 0x0a, 0x0c, 0x4d,
	0x41, 0x54, 0x43, 0x48, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x45, 0x44, 0x10, 0x05, 0x12, 0x16, 0x0a,
	0x12, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x53, 0x59, 0x53, 0x54, 0x45, 0x4d, 0x5f, 0x45, 0x52,
	0x52, 0x4f, 0x52, 0x10, 0x06, 0x12, 0x15, 0x0a, 0x11, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x49,
	0x4e, 0x54, 0x45, 0x52, 0x52, 0x55, 0x50, 0x54, 0x45, 0x44, 0x10, 0x07, 0x12, 0x18, 0x0a, 0x14,
	0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f, 0x4d, 0x50, 0x5f, 0x55, 0x4e, 0x41, 0x56, 0x41, 0x49, 0x4c,
	0x41, 0x42, 0x4c, 0x45, 0x10, 0x08, 0x12, 0x19, 0x0a, 0x15, 0x4d, 0x41, 0x54, 0x43, 0x48, 0x5f,
	0x43, 0x4f, 0x4e, 0x46, 0x49, 0x52, 0x4d, 0x5f, 0x54, 0x49, 0x4d, 0x45, 0x4f, 0x55, 0x54, 0x10,
	0x09, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_MatchReason_proto_rawDescOnce sync.Once
	file_MatchReason_proto_rawDescData = file_MatchReason_proto_rawDesc
)

func file_MatchReason_proto_rawDescGZIP() []byte {
	file_MatchReason_proto_rawDescOnce.Do(func() {
		file_MatchReason_proto_rawDescData = protoimpl.X.CompressGZIP(file_MatchReason_proto_rawDescData)
	})
	return file_MatchReason_proto_rawDescData
}

var file_MatchReason_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_MatchReason_proto_goTypes = []interface{}{
	(MatchReason)(0), // 0: MatchReason
}
var file_MatchReason_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_MatchReason_proto_init() }
func file_MatchReason_proto_init() {
	if File_MatchReason_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_MatchReason_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_MatchReason_proto_goTypes,
		DependencyIndexes: file_MatchReason_proto_depIdxs,
		EnumInfos:         file_MatchReason_proto_enumTypes,
	}.Build()
	File_MatchReason_proto = out.File
	file_MatchReason_proto_rawDesc = nil
	file_MatchReason_proto_goTypes = nil
	file_MatchReason_proto_depIdxs = nil
}
