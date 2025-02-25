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
// source: GCGReason.proto

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

// Obf: MEDIDIAPFAD
type GCGReason int32

const (
	GCGReason_MNDCMMKBIBP_Default            GCGReason = 0
	GCGReason_MNDCMMKBIBP_Effect             GCGReason = 1
	GCGReason_MNDCMMKBIBP_Cost               GCGReason = 2
	GCGReason_MNDCMMKBIBP_Gm                 GCGReason = 3
	GCGReason_MNDCMMKBIBP_Attack             GCGReason = 4
	GCGReason_MNDCMMKBIBP_Reboot             GCGReason = 5
	GCGReason_MNDCMMKBIBP_PlayCard           GCGReason = 6
	GCGReason_MNDCMMKBIBP_QuicklyOnstage     GCGReason = 7
	GCGReason_MNDCMMKBIBP_RemoveAfterDie     GCGReason = 8
	GCGReason_MNDCMMKBIBP_Init               GCGReason = 9
	GCGReason_MNDCMMKBIBP_EffectDamage       GCGReason = 10
	GCGReason_MNDCMMKBIBP_EffectHeal         GCGReason = 11
	GCGReason_MNDCMMKBIBP_EffectRevive       GCGReason = 12
	GCGReason_MNDCMMKBIBP_InitOnstage        GCGReason = 13
	GCGReason_MNDCMMKBIBP_DieOnstage         GCGReason = 14
	GCGReason_MNDCMMKBIBP_SelectOnstage      GCGReason = 15
	GCGReason_MNDCMMKBIBP_CharacterDie       GCGReason = 16
	GCGReason_MNDCMMKBIBP_ReviveWhenDeath    GCGReason = 17
	GCGReason_MNDCMMKBIBP_TransferToOpponent GCGReason = 18
	GCGReason_MNDCMMKBIBP_TransferDice       GCGReason = 19
)

// Enum value maps for GCGReason.
var (
	GCGReason_name = map[int32]string{
		0:  "MNDCMMKBIBP_Default",
		1:  "MNDCMMKBIBP_Effect",
		2:  "MNDCMMKBIBP_Cost",
		3:  "MNDCMMKBIBP_Gm",
		4:  "MNDCMMKBIBP_Attack",
		5:  "MNDCMMKBIBP_Reboot",
		6:  "MNDCMMKBIBP_PlayCard",
		7:  "MNDCMMKBIBP_QuicklyOnstage",
		8:  "MNDCMMKBIBP_RemoveAfterDie",
		9:  "MNDCMMKBIBP_Init",
		10: "MNDCMMKBIBP_EffectDamage",
		11: "MNDCMMKBIBP_EffectHeal",
		12: "MNDCMMKBIBP_EffectRevive",
		13: "MNDCMMKBIBP_InitOnstage",
		14: "MNDCMMKBIBP_DieOnstage",
		15: "MNDCMMKBIBP_SelectOnstage",
		16: "MNDCMMKBIBP_CharacterDie",
		17: "MNDCMMKBIBP_ReviveWhenDeath",
		18: "MNDCMMKBIBP_TransferToOpponent",
		19: "MNDCMMKBIBP_TransferDice",
	}
	GCGReason_value = map[string]int32{
		"MNDCMMKBIBP_Default":            0,
		"MNDCMMKBIBP_Effect":             1,
		"MNDCMMKBIBP_Cost":               2,
		"MNDCMMKBIBP_Gm":                 3,
		"MNDCMMKBIBP_Attack":             4,
		"MNDCMMKBIBP_Reboot":             5,
		"MNDCMMKBIBP_PlayCard":           6,
		"MNDCMMKBIBP_QuicklyOnstage":     7,
		"MNDCMMKBIBP_RemoveAfterDie":     8,
		"MNDCMMKBIBP_Init":               9,
		"MNDCMMKBIBP_EffectDamage":       10,
		"MNDCMMKBIBP_EffectHeal":         11,
		"MNDCMMKBIBP_EffectRevive":       12,
		"MNDCMMKBIBP_InitOnstage":        13,
		"MNDCMMKBIBP_DieOnstage":         14,
		"MNDCMMKBIBP_SelectOnstage":      15,
		"MNDCMMKBIBP_CharacterDie":       16,
		"MNDCMMKBIBP_ReviveWhenDeath":    17,
		"MNDCMMKBIBP_TransferToOpponent": 18,
		"MNDCMMKBIBP_TransferDice":       19,
	}
)

func (x GCGReason) Enum() *GCGReason {
	p := new(GCGReason)
	*p = x
	return p
}

func (x GCGReason) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (GCGReason) Descriptor() protoreflect.EnumDescriptor {
	return file_GCGReason_proto_enumTypes[0].Descriptor()
}

func (GCGReason) Type() protoreflect.EnumType {
	return &file_GCGReason_proto_enumTypes[0]
}

func (x GCGReason) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use GCGReason.Descriptor instead.
func (GCGReason) EnumDescriptor() ([]byte, []int) {
	return file_GCGReason_proto_rawDescGZIP(), []int{0}
}

var File_GCGReason_proto protoreflect.FileDescriptor

var file_GCGReason_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x47, 0x43, 0x47, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2a, 0xb7, 0x04, 0x0a, 0x09, 0x47, 0x43, 0x47, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12,
	0x17, 0x0a, 0x13, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x44,
	0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x10, 0x00, 0x12, 0x16, 0x0a, 0x12, 0x4d, 0x4e, 0x44, 0x43,
	0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x10, 0x01,
	0x12, 0x14, 0x0a, 0x10, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f,
	0x43, 0x6f, 0x73, 0x74, 0x10, 0x02, 0x12, 0x12, 0x0a, 0x0e, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d,
	0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x47, 0x6d, 0x10, 0x03, 0x12, 0x16, 0x0a, 0x12, 0x4d, 0x4e,
	0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6b,
	0x10, 0x04, 0x12, 0x16, 0x0a, 0x12, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42,
	0x50, 0x5f, 0x52, 0x65, 0x62, 0x6f, 0x6f, 0x74, 0x10, 0x05, 0x12, 0x18, 0x0a, 0x14, 0x4d, 0x4e,
	0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x50, 0x6c, 0x61, 0x79, 0x43, 0x61,
	0x72, 0x64, 0x10, 0x06, 0x12, 0x1e, 0x0a, 0x1a, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42,
	0x49, 0x42, 0x50, 0x5f, 0x51, 0x75, 0x69, 0x63, 0x6b, 0x6c, 0x79, 0x4f, 0x6e, 0x73, 0x74, 0x61,
	0x67, 0x65, 0x10, 0x07, 0x12, 0x1e, 0x0a, 0x1a, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42,
	0x49, 0x42, 0x50, 0x5f, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x41, 0x66, 0x74, 0x65, 0x72, 0x44,
	0x69, 0x65, 0x10, 0x08, 0x12, 0x14, 0x0a, 0x10, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42,
	0x49, 0x42, 0x50, 0x5f, 0x49, 0x6e, 0x69, 0x74, 0x10, 0x09, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4e,
	0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74,
	0x44, 0x61, 0x6d, 0x61, 0x67, 0x65, 0x10, 0x0a, 0x12, 0x1a, 0x0a, 0x16, 0x4d, 0x4e, 0x44, 0x43,
	0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x48, 0x65,
	0x61, 0x6c, 0x10, 0x0b, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42,
	0x49, 0x42, 0x50, 0x5f, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x52, 0x65, 0x76, 0x69, 0x76, 0x65,
	0x10, 0x0c, 0x12, 0x1b, 0x0a, 0x17, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42,
	0x50, 0x5f, 0x49, 0x6e, 0x69, 0x74, 0x4f, 0x6e, 0x73, 0x74, 0x61, 0x67, 0x65, 0x10, 0x0d, 0x12,
	0x1a, 0x0a, 0x16, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x44,
	0x69, 0x65, 0x4f, 0x6e, 0x73, 0x74, 0x61, 0x67, 0x65, 0x10, 0x0e, 0x12, 0x1d, 0x0a, 0x19, 0x4d,
	0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x53, 0x65, 0x6c, 0x65, 0x63,
	0x74, 0x4f, 0x6e, 0x73, 0x74, 0x61, 0x67, 0x65, 0x10, 0x0f, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4e,
	0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x43, 0x68, 0x61, 0x72, 0x61, 0x63,
	0x74, 0x65, 0x72, 0x44, 0x69, 0x65, 0x10, 0x10, 0x12, 0x1f, 0x0a, 0x1b, 0x4d, 0x4e, 0x44, 0x43,
	0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x52, 0x65, 0x76, 0x69, 0x76, 0x65, 0x57, 0x68,
	0x65, 0x6e, 0x44, 0x65, 0x61, 0x74, 0x68, 0x10, 0x11, 0x12, 0x22, 0x0a, 0x1e, 0x4d, 0x4e, 0x44,
	0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65,
	0x72, 0x54, 0x6f, 0x4f, 0x70, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74, 0x10, 0x12, 0x12, 0x1c, 0x0a,
	0x18, 0x4d, 0x4e, 0x44, 0x43, 0x4d, 0x4d, 0x4b, 0x42, 0x49, 0x42, 0x50, 0x5f, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x66, 0x65, 0x72, 0x44, 0x69, 0x63, 0x65, 0x10, 0x13, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGReason_proto_rawDescOnce sync.Once
	file_GCGReason_proto_rawDescData = file_GCGReason_proto_rawDesc
)

func file_GCGReason_proto_rawDescGZIP() []byte {
	file_GCGReason_proto_rawDescOnce.Do(func() {
		file_GCGReason_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGReason_proto_rawDescData)
	})
	return file_GCGReason_proto_rawDescData
}

var file_GCGReason_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_GCGReason_proto_goTypes = []interface{}{
	(GCGReason)(0), // 0: GCGReason
}
var file_GCGReason_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GCGReason_proto_init() }
func file_GCGReason_proto_init() {
	if File_GCGReason_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_GCGReason_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGReason_proto_goTypes,
		DependencyIndexes: file_GCGReason_proto_depIdxs,
		EnumInfos:         file_GCGReason_proto_enumTypes,
	}.Build()
	File_GCGReason_proto = out.File
	file_GCGReason_proto_rawDesc = nil
	file_GCGReason_proto_goTypes = nil
	file_GCGReason_proto_depIdxs = nil
}
