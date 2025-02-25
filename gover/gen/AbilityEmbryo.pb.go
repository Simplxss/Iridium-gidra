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
// source: AbilityEmbryo.proto

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

// Obf: PLELJEGMEOD
type AbilityEmbryo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AbilityId               uint32 `protobuf:"varint,1,opt,name=ability_id,json=abilityId,proto3" json:"ability_id,omitempty"`
	AbilityNameHash         uint32 `protobuf:"fixed32,2,opt,name=ability_name_hash,json=abilityNameHash,proto3" json:"ability_name_hash,omitempty"`
	AbilityOverrideNameHash uint32 `protobuf:"fixed32,3,opt,name=ability_override_name_hash,json=abilityOverrideNameHash,proto3" json:"ability_override_name_hash,omitempty"`
}

func (x *AbilityEmbryo) Reset() {
	*x = AbilityEmbryo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_AbilityEmbryo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AbilityEmbryo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AbilityEmbryo) ProtoMessage() {}

func (x *AbilityEmbryo) ProtoReflect() protoreflect.Message {
	mi := &file_AbilityEmbryo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AbilityEmbryo.ProtoReflect.Descriptor instead.
func (*AbilityEmbryo) Descriptor() ([]byte, []int) {
	return file_AbilityEmbryo_proto_rawDescGZIP(), []int{0}
}

func (x *AbilityEmbryo) GetAbilityId() uint32 {
	if x != nil {
		return x.AbilityId
	}
	return 0
}

func (x *AbilityEmbryo) GetAbilityNameHash() uint32 {
	if x != nil {
		return x.AbilityNameHash
	}
	return 0
}

func (x *AbilityEmbryo) GetAbilityOverrideNameHash() uint32 {
	if x != nil {
		return x.AbilityOverrideNameHash
	}
	return 0
}

var File_AbilityEmbryo_proto protoreflect.FileDescriptor

var file_AbilityEmbryo_proto_rawDesc = []byte{
	0x0a, 0x13, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x45, 0x6d, 0x62, 0x72, 0x79, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x97, 0x01, 0x0a, 0x0d, 0x41, 0x62, 0x69, 0x6c, 0x69, 0x74,
	0x79, 0x45, 0x6d, 0x62, 0x72, 0x79, 0x6f, 0x12, 0x1d, 0x0a, 0x0a, 0x61, 0x62, 0x69, 0x6c, 0x69,
	0x74, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x61, 0x62, 0x69,
	0x6c, 0x69, 0x74, 0x79, 0x49, 0x64, 0x12, 0x2a, 0x0a, 0x11, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74,
	0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x07, 0x52, 0x0f, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x48, 0x61,
	0x73, 0x68, 0x12, 0x3b, 0x0a, 0x1a, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x5f, 0x6f, 0x76,
	0x65, 0x72, 0x72, 0x69, 0x64, 0x65, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x07, 0x52, 0x17, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x4f,
	0x76, 0x65, 0x72, 0x72, 0x69, 0x64, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x48, 0x61, 0x73, 0x68, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_AbilityEmbryo_proto_rawDescOnce sync.Once
	file_AbilityEmbryo_proto_rawDescData = file_AbilityEmbryo_proto_rawDesc
)

func file_AbilityEmbryo_proto_rawDescGZIP() []byte {
	file_AbilityEmbryo_proto_rawDescOnce.Do(func() {
		file_AbilityEmbryo_proto_rawDescData = protoimpl.X.CompressGZIP(file_AbilityEmbryo_proto_rawDescData)
	})
	return file_AbilityEmbryo_proto_rawDescData
}

var file_AbilityEmbryo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_AbilityEmbryo_proto_goTypes = []interface{}{
	(*AbilityEmbryo)(nil), // 0: AbilityEmbryo
}
var file_AbilityEmbryo_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_AbilityEmbryo_proto_init() }
func file_AbilityEmbryo_proto_init() {
	if File_AbilityEmbryo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_AbilityEmbryo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AbilityEmbryo); i {
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
			RawDescriptor: file_AbilityEmbryo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_AbilityEmbryo_proto_goTypes,
		DependencyIndexes: file_AbilityEmbryo_proto_depIdxs,
		MessageInfos:      file_AbilityEmbryo_proto_msgTypes,
	}.Build()
	File_AbilityEmbryo_proto = out.File
	file_AbilityEmbryo_proto_rawDesc = nil
	file_AbilityEmbryo_proto_goTypes = nil
	file_AbilityEmbryo_proto_depIdxs = nil
}
