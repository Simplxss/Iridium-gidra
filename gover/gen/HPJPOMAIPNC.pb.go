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
// source: HPJPOMAIPNC.proto

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

type HPJPOMAIPNC int32

const (
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelNone        HPJPOMAIPNC = 0
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelConst       HPJPOMAIPNC = 1
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelWeek        HPJPOMAIPNC = 2
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelWorld       HPJPOMAIPNC = 3
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelBoss        HPJPOMAIPNC = 4
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelCharacter   HPJPOMAIPNC = 5
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelBreak       HPJPOMAIPNC = 6
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelQuest       HPJPOMAIPNC = 7
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelGuideGroup  HPJPOMAIPNC = 8
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelOther       HPJPOMAIPNC = 9
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelJourney     HPJPOMAIPNC = 10
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelPve         HPJPOMAIPNC = 11
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelPveInfinite HPJPOMAIPNC = 12
	HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelPvePuzzle   HPJPOMAIPNC = 13
)

// Enum value maps for HPJPOMAIPNC.
var (
	HPJPOMAIPNC_name = map[int32]string{
		0:  "HPJPOMAIPNC_GcgLevelNone",
		1:  "HPJPOMAIPNC_GcgLevelConst",
		2:  "HPJPOMAIPNC_GcgLevelWeek",
		3:  "HPJPOMAIPNC_GcgLevelWorld",
		4:  "HPJPOMAIPNC_GcgLevelBoss",
		5:  "HPJPOMAIPNC_GcgLevelCharacter",
		6:  "HPJPOMAIPNC_GcgLevelBreak",
		7:  "HPJPOMAIPNC_GcgLevelQuest",
		8:  "HPJPOMAIPNC_GcgLevelGuideGroup",
		9:  "HPJPOMAIPNC_GcgLevelOther",
		10: "HPJPOMAIPNC_GcgLevelJourney",
		11: "HPJPOMAIPNC_GcgLevelPve",
		12: "HPJPOMAIPNC_GcgLevelPveInfinite",
		13: "HPJPOMAIPNC_GcgLevelPvePuzzle",
	}
	HPJPOMAIPNC_value = map[string]int32{
		"HPJPOMAIPNC_GcgLevelNone":        0,
		"HPJPOMAIPNC_GcgLevelConst":       1,
		"HPJPOMAIPNC_GcgLevelWeek":        2,
		"HPJPOMAIPNC_GcgLevelWorld":       3,
		"HPJPOMAIPNC_GcgLevelBoss":        4,
		"HPJPOMAIPNC_GcgLevelCharacter":   5,
		"HPJPOMAIPNC_GcgLevelBreak":       6,
		"HPJPOMAIPNC_GcgLevelQuest":       7,
		"HPJPOMAIPNC_GcgLevelGuideGroup":  8,
		"HPJPOMAIPNC_GcgLevelOther":       9,
		"HPJPOMAIPNC_GcgLevelJourney":     10,
		"HPJPOMAIPNC_GcgLevelPve":         11,
		"HPJPOMAIPNC_GcgLevelPveInfinite": 12,
		"HPJPOMAIPNC_GcgLevelPvePuzzle":   13,
	}
)

func (x HPJPOMAIPNC) Enum() *HPJPOMAIPNC {
	p := new(HPJPOMAIPNC)
	*p = x
	return p
}

func (x HPJPOMAIPNC) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HPJPOMAIPNC) Descriptor() protoreflect.EnumDescriptor {
	return file_HPJPOMAIPNC_proto_enumTypes[0].Descriptor()
}

func (HPJPOMAIPNC) Type() protoreflect.EnumType {
	return &file_HPJPOMAIPNC_proto_enumTypes[0]
}

func (x HPJPOMAIPNC) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HPJPOMAIPNC.Descriptor instead.
func (HPJPOMAIPNC) EnumDescriptor() ([]byte, []int) {
	return file_HPJPOMAIPNC_proto_rawDescGZIP(), []int{0}
}

var File_HPJPOMAIPNC_proto protoreflect.FileDescriptor

var file_HPJPOMAIPNC_proto_rawDesc = []byte{
	0x0a, 0x11, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0xcf, 0x03, 0x0a, 0x0b, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49,
	0x50, 0x4e, 0x43, 0x12, 0x1c, 0x0a, 0x18, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50,
	0x4e, 0x43, 0x5f, 0x47, 0x63, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x4e, 0x6f, 0x6e, 0x65, 0x10,
	0x00, 0x12, 0x1d, 0x0a, 0x19, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43,
	0x5f, 0x47, 0x63, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x10, 0x01,
	0x12, 0x1c, 0x0a, 0x18, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f,
	0x47, 0x63, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x57, 0x65, 0x65, 0x6b, 0x10, 0x02, 0x12, 0x1d,
	0x0a, 0x19, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f, 0x47, 0x63,
	0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x10, 0x03, 0x12, 0x1c, 0x0a,
	0x18, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f, 0x47, 0x63, 0x67,
	0x4c, 0x65, 0x76, 0x65, 0x6c, 0x42, 0x6f, 0x73, 0x73, 0x10, 0x04, 0x12, 0x21, 0x0a, 0x1d, 0x48,
	0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f, 0x47, 0x63, 0x67, 0x4c, 0x65,
	0x76, 0x65, 0x6c, 0x43, 0x68, 0x61, 0x72, 0x61, 0x63, 0x74, 0x65, 0x72, 0x10, 0x05, 0x12, 0x1d,
	0x0a, 0x19, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f, 0x47, 0x63,
	0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x42, 0x72, 0x65, 0x61, 0x6b, 0x10, 0x06, 0x12, 0x1d, 0x0a,
	0x19, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f, 0x47, 0x63, 0x67,
	0x4c, 0x65, 0x76, 0x65, 0x6c, 0x51, 0x75, 0x65, 0x73, 0x74, 0x10, 0x07, 0x12, 0x22, 0x0a, 0x1e,
	0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f, 0x47, 0x63, 0x67, 0x4c,
	0x65, 0x76, 0x65, 0x6c, 0x47, 0x75, 0x69, 0x64, 0x65, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x10, 0x08,
	0x12, 0x1d, 0x0a, 0x19, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f,
	0x47, 0x63, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x4f, 0x74, 0x68, 0x65, 0x72, 0x10, 0x09, 0x12,
	0x1f, 0x0a, 0x1b, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f, 0x47,
	0x63, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x4a, 0x6f, 0x75, 0x72, 0x6e, 0x65, 0x79, 0x10, 0x0a,
	0x12, 0x1b, 0x0a, 0x17, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f,
	0x47, 0x63, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x50, 0x76, 0x65, 0x10, 0x0b, 0x12, 0x23, 0x0a,
	0x1f, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x5f, 0x47, 0x63, 0x67,
	0x4c, 0x65, 0x76, 0x65, 0x6c, 0x50, 0x76, 0x65, 0x49, 0x6e, 0x66, 0x69, 0x6e, 0x69, 0x74, 0x65,
	0x10, 0x0c, 0x12, 0x21, 0x0a, 0x1d, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d, 0x41, 0x49, 0x50, 0x4e,
	0x43, 0x5f, 0x47, 0x63, 0x67, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x50, 0x76, 0x65, 0x50, 0x75, 0x7a,
	0x7a, 0x6c, 0x65, 0x10, 0x0d, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_HPJPOMAIPNC_proto_rawDescOnce sync.Once
	file_HPJPOMAIPNC_proto_rawDescData = file_HPJPOMAIPNC_proto_rawDesc
)

func file_HPJPOMAIPNC_proto_rawDescGZIP() []byte {
	file_HPJPOMAIPNC_proto_rawDescOnce.Do(func() {
		file_HPJPOMAIPNC_proto_rawDescData = protoimpl.X.CompressGZIP(file_HPJPOMAIPNC_proto_rawDescData)
	})
	return file_HPJPOMAIPNC_proto_rawDescData
}

var file_HPJPOMAIPNC_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_HPJPOMAIPNC_proto_goTypes = []interface{}{
	(HPJPOMAIPNC)(0), // 0: HPJPOMAIPNC
}
var file_HPJPOMAIPNC_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_HPJPOMAIPNC_proto_init() }
func file_HPJPOMAIPNC_proto_init() {
	if File_HPJPOMAIPNC_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_HPJPOMAIPNC_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_HPJPOMAIPNC_proto_goTypes,
		DependencyIndexes: file_HPJPOMAIPNC_proto_depIdxs,
		EnumInfos:         file_HPJPOMAIPNC_proto_enumTypes,
	}.Build()
	File_HPJPOMAIPNC_proto = out.File
	file_HPJPOMAIPNC_proto_rawDesc = nil
	file_HPJPOMAIPNC_proto_goTypes = nil
	file_HPJPOMAIPNC_proto_depIdxs = nil
}
