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
// source: AbilityMetaUpdateBaseReactionDamage.proto

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

// Obf: HGBOKEDCLOO
type AbilityMetaUpdateBaseReactionDamage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AbilityName    *AbilityString `protobuf:"bytes,4,opt,name=ability_name,json=abilityName,proto3" json:"ability_name,omitempty"`
	GlobalValueKey *AbilityString `protobuf:"bytes,8,opt,name=global_value_key,json=globalValueKey,proto3" json:"global_value_key,omitempty"`
	EJOIOADINHE    uint32         `protobuf:"varint,5,opt,name=EJOIOADINHE,proto3" json:"EJOIOADINHE,omitempty"`
	EJHCLCMJIMM    uint32         `protobuf:"varint,12,opt,name=EJHCLCMJIMM,proto3" json:"EJHCLCMJIMM,omitempty"`
}

func (x *AbilityMetaUpdateBaseReactionDamage) Reset() {
	*x = AbilityMetaUpdateBaseReactionDamage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_AbilityMetaUpdateBaseReactionDamage_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AbilityMetaUpdateBaseReactionDamage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AbilityMetaUpdateBaseReactionDamage) ProtoMessage() {}

func (x *AbilityMetaUpdateBaseReactionDamage) ProtoReflect() protoreflect.Message {
	mi := &file_AbilityMetaUpdateBaseReactionDamage_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AbilityMetaUpdateBaseReactionDamage.ProtoReflect.Descriptor instead.
func (*AbilityMetaUpdateBaseReactionDamage) Descriptor() ([]byte, []int) {
	return file_AbilityMetaUpdateBaseReactionDamage_proto_rawDescGZIP(), []int{0}
}

func (x *AbilityMetaUpdateBaseReactionDamage) GetAbilityName() *AbilityString {
	if x != nil {
		return x.AbilityName
	}
	return nil
}

func (x *AbilityMetaUpdateBaseReactionDamage) GetGlobalValueKey() *AbilityString {
	if x != nil {
		return x.GlobalValueKey
	}
	return nil
}

func (x *AbilityMetaUpdateBaseReactionDamage) GetEJOIOADINHE() uint32 {
	if x != nil {
		return x.EJOIOADINHE
	}
	return 0
}

func (x *AbilityMetaUpdateBaseReactionDamage) GetEJHCLCMJIMM() uint32 {
	if x != nil {
		return x.EJHCLCMJIMM
	}
	return 0
}

var File_AbilityMetaUpdateBaseReactionDamage_proto protoreflect.FileDescriptor

var file_AbilityMetaUpdateBaseReactionDamage_proto_rawDesc = []byte{
	0x0a, 0x29, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x4d, 0x65, 0x74, 0x61, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x44,
	0x61, 0x6d, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13, 0x41, 0x62, 0x69,
	0x6c, 0x69, 0x74, 0x79, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xd6, 0x01, 0x0a, 0x23, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x4d, 0x65, 0x74, 0x61,
	0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x42, 0x61, 0x73, 0x65, 0x52, 0x65, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x44, 0x61, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x31, 0x0a, 0x0c, 0x61, 0x62, 0x69, 0x6c,
	0x69, 0x74, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e,
	0x2e, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x0b,
	0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x38, 0x0a, 0x10, 0x67,
	0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x53,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x0e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x20, 0x0a, 0x0b, 0x45, 0x4a, 0x4f, 0x49, 0x4f, 0x41, 0x44,
	0x49, 0x4e, 0x48, 0x45, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x45, 0x4a, 0x4f, 0x49,
	0x4f, 0x41, 0x44, 0x49, 0x4e, 0x48, 0x45, 0x12, 0x20, 0x0a, 0x0b, 0x45, 0x4a, 0x48, 0x43, 0x4c,
	0x43, 0x4d, 0x4a, 0x49, 0x4d, 0x4d, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x45, 0x4a,
	0x48, 0x43, 0x4c, 0x43, 0x4d, 0x4a, 0x49, 0x4d, 0x4d, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_AbilityMetaUpdateBaseReactionDamage_proto_rawDescOnce sync.Once
	file_AbilityMetaUpdateBaseReactionDamage_proto_rawDescData = file_AbilityMetaUpdateBaseReactionDamage_proto_rawDesc
)

func file_AbilityMetaUpdateBaseReactionDamage_proto_rawDescGZIP() []byte {
	file_AbilityMetaUpdateBaseReactionDamage_proto_rawDescOnce.Do(func() {
		file_AbilityMetaUpdateBaseReactionDamage_proto_rawDescData = protoimpl.X.CompressGZIP(file_AbilityMetaUpdateBaseReactionDamage_proto_rawDescData)
	})
	return file_AbilityMetaUpdateBaseReactionDamage_proto_rawDescData
}

var file_AbilityMetaUpdateBaseReactionDamage_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_AbilityMetaUpdateBaseReactionDamage_proto_goTypes = []interface{}{
	(*AbilityMetaUpdateBaseReactionDamage)(nil), // 0: AbilityMetaUpdateBaseReactionDamage
	(*AbilityString)(nil),                       // 1: AbilityString
}
var file_AbilityMetaUpdateBaseReactionDamage_proto_depIdxs = []int32{
	1, // 0: AbilityMetaUpdateBaseReactionDamage.ability_name:type_name -> AbilityString
	1, // 1: AbilityMetaUpdateBaseReactionDamage.global_value_key:type_name -> AbilityString
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_AbilityMetaUpdateBaseReactionDamage_proto_init() }
func file_AbilityMetaUpdateBaseReactionDamage_proto_init() {
	if File_AbilityMetaUpdateBaseReactionDamage_proto != nil {
		return
	}
	file_AbilityString_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_AbilityMetaUpdateBaseReactionDamage_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AbilityMetaUpdateBaseReactionDamage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_AbilityMetaUpdateBaseReactionDamage_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_AbilityMetaUpdateBaseReactionDamage_proto_goTypes,
		DependencyIndexes: file_AbilityMetaUpdateBaseReactionDamage_proto_depIdxs,
		MessageInfos:      file_AbilityMetaUpdateBaseReactionDamage_proto_msgTypes,
	}.Build()
	File_AbilityMetaUpdateBaseReactionDamage_proto = out.File
	file_AbilityMetaUpdateBaseReactionDamage_proto_rawDesc = nil
	file_AbilityMetaUpdateBaseReactionDamage_proto_goTypes = nil
	file_AbilityMetaUpdateBaseReactionDamage_proto_depIdxs = nil
}
