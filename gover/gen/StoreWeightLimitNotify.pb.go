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
// source: StoreWeightLimitNotify.proto

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

// CmdId: 22706
// Obf: OLOEDFBEHGA
type StoreWeightLimitNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WeightLimit         uint32    `protobuf:"varint,2,opt,name=weight_limit,json=weightLimit,proto3" json:"weight_limit,omitempty"`
	FurnitureCountLimit uint32    `protobuf:"varint,1,opt,name=furniture_count_limit,json=furnitureCountLimit,proto3" json:"furniture_count_limit,omitempty"`
	WeaponCountLimit    uint32    `protobuf:"varint,10,opt,name=weapon_count_limit,json=weaponCountLimit,proto3" json:"weapon_count_limit,omitempty"`
	ReliquaryCountLimit uint32    `protobuf:"varint,11,opt,name=reliquary_count_limit,json=reliquaryCountLimit,proto3" json:"reliquary_count_limit,omitempty"`
	MaterialCountLimit  uint32    `protobuf:"varint,14,opt,name=material_count_limit,json=materialCountLimit,proto3" json:"material_count_limit,omitempty"`
	StoreType           StoreType `protobuf:"varint,4,opt,name=store_type,json=storeType,proto3,enum=StoreType" json:"store_type,omitempty"`
}

func (x *StoreWeightLimitNotify) Reset() {
	*x = StoreWeightLimitNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_StoreWeightLimitNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StoreWeightLimitNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StoreWeightLimitNotify) ProtoMessage() {}

func (x *StoreWeightLimitNotify) ProtoReflect() protoreflect.Message {
	mi := &file_StoreWeightLimitNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StoreWeightLimitNotify.ProtoReflect.Descriptor instead.
func (*StoreWeightLimitNotify) Descriptor() ([]byte, []int) {
	return file_StoreWeightLimitNotify_proto_rawDescGZIP(), []int{0}
}

func (x *StoreWeightLimitNotify) GetWeightLimit() uint32 {
	if x != nil {
		return x.WeightLimit
	}
	return 0
}

func (x *StoreWeightLimitNotify) GetFurnitureCountLimit() uint32 {
	if x != nil {
		return x.FurnitureCountLimit
	}
	return 0
}

func (x *StoreWeightLimitNotify) GetWeaponCountLimit() uint32 {
	if x != nil {
		return x.WeaponCountLimit
	}
	return 0
}

func (x *StoreWeightLimitNotify) GetReliquaryCountLimit() uint32 {
	if x != nil {
		return x.ReliquaryCountLimit
	}
	return 0
}

func (x *StoreWeightLimitNotify) GetMaterialCountLimit() uint32 {
	if x != nil {
		return x.MaterialCountLimit
	}
	return 0
}

func (x *StoreWeightLimitNotify) GetStoreType() StoreType {
	if x != nil {
		return x.StoreType
	}
	return StoreType_STORE_TYPE_NONE
}

var File_StoreWeightLimitNotify_proto protoreflect.FileDescriptor

var file_StoreWeightLimitNotify_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x4c, 0x69, 0x6d,
	0x69, 0x74, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f,
	0x53, 0x74, 0x6f, 0x72, 0x65, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xae, 0x02, 0x0a, 0x16, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x4c,
	0x69, 0x6d, 0x69, 0x74, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x77, 0x65,
	0x69, 0x67, 0x68, 0x74, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0b, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x32, 0x0a,
	0x15, 0x66, 0x75, 0x72, 0x6e, 0x69, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74,
	0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x13, 0x66, 0x75,
	0x72, 0x6e, 0x69, 0x74, 0x75, 0x72, 0x65, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x4c, 0x69, 0x6d, 0x69,
	0x74, 0x12, 0x2c, 0x0a, 0x12, 0x77, 0x65, 0x61, 0x70, 0x6f, 0x6e, 0x5f, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x77,
	0x65, 0x61, 0x70, 0x6f, 0x6e, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12,
	0x32, 0x0a, 0x15, 0x72, 0x65, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x72, 0x79, 0x5f, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x13,
	0x72, 0x65, 0x6c, 0x69, 0x71, 0x75, 0x61, 0x72, 0x79, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x4c, 0x69,
	0x6d, 0x69, 0x74, 0x12, 0x30, 0x0a, 0x14, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x5f,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x0e, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x12, 0x6d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x43, 0x6f, 0x75, 0x6e, 0x74,
	0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x29, 0x0a, 0x0a, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0a, 0x2e, 0x53, 0x74, 0x6f, 0x72,
	0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x09, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x54, 0x79, 0x70, 0x65,
	0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_StoreWeightLimitNotify_proto_rawDescOnce sync.Once
	file_StoreWeightLimitNotify_proto_rawDescData = file_StoreWeightLimitNotify_proto_rawDesc
)

func file_StoreWeightLimitNotify_proto_rawDescGZIP() []byte {
	file_StoreWeightLimitNotify_proto_rawDescOnce.Do(func() {
		file_StoreWeightLimitNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_StoreWeightLimitNotify_proto_rawDescData)
	})
	return file_StoreWeightLimitNotify_proto_rawDescData
}

var file_StoreWeightLimitNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_StoreWeightLimitNotify_proto_goTypes = []interface{}{
	(*StoreWeightLimitNotify)(nil), // 0: StoreWeightLimitNotify
	(StoreType)(0),                 // 1: StoreType
}
var file_StoreWeightLimitNotify_proto_depIdxs = []int32{
	1, // 0: StoreWeightLimitNotify.store_type:type_name -> StoreType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_StoreWeightLimitNotify_proto_init() }
func file_StoreWeightLimitNotify_proto_init() {
	if File_StoreWeightLimitNotify_proto != nil {
		return
	}
	file_StoreType_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_StoreWeightLimitNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StoreWeightLimitNotify); i {
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
			RawDescriptor: file_StoreWeightLimitNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_StoreWeightLimitNotify_proto_goTypes,
		DependencyIndexes: file_StoreWeightLimitNotify_proto_depIdxs,
		MessageInfos:      file_StoreWeightLimitNotify_proto_msgTypes,
	}.Build()
	File_StoreWeightLimitNotify_proto = out.File
	file_StoreWeightLimitNotify_proto_rawDesc = nil
	file_StoreWeightLimitNotify_proto_goTypes = nil
	file_StoreWeightLimitNotify_proto_depIdxs = nil
}
