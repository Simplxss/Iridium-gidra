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
// source: SceneFishInfo.proto

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

// Obf: HNLLCGHHGFM
type SceneFishInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FishId           uint32  `protobuf:"varint,1,opt,name=fish_id,json=fishId,proto3" json:"fish_id,omitempty"`
	FishPoolEntityId uint32  `protobuf:"varint,2,opt,name=fish_pool_entity_id,json=fishPoolEntityId,proto3" json:"fish_pool_entity_id,omitempty"`
	FishPoolPos      *Vector `protobuf:"bytes,3,opt,name=fish_pool_pos,json=fishPoolPos,proto3" json:"fish_pool_pos,omitempty"`
	FishPoolGadgetId uint32  `protobuf:"varint,4,opt,name=fish_pool_gadget_id,json=fishPoolGadgetId,proto3" json:"fish_pool_gadget_id,omitempty"`
	LastShockTime    uint32  `protobuf:"varint,5,opt,name=last_shock_time,json=lastShockTime,proto3" json:"last_shock_time,omitempty"`
}

func (x *SceneFishInfo) Reset() {
	*x = SceneFishInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SceneFishInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SceneFishInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SceneFishInfo) ProtoMessage() {}

func (x *SceneFishInfo) ProtoReflect() protoreflect.Message {
	mi := &file_SceneFishInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SceneFishInfo.ProtoReflect.Descriptor instead.
func (*SceneFishInfo) Descriptor() ([]byte, []int) {
	return file_SceneFishInfo_proto_rawDescGZIP(), []int{0}
}

func (x *SceneFishInfo) GetFishId() uint32 {
	if x != nil {
		return x.FishId
	}
	return 0
}

func (x *SceneFishInfo) GetFishPoolEntityId() uint32 {
	if x != nil {
		return x.FishPoolEntityId
	}
	return 0
}

func (x *SceneFishInfo) GetFishPoolPos() *Vector {
	if x != nil {
		return x.FishPoolPos
	}
	return nil
}

func (x *SceneFishInfo) GetFishPoolGadgetId() uint32 {
	if x != nil {
		return x.FishPoolGadgetId
	}
	return 0
}

func (x *SceneFishInfo) GetLastShockTime() uint32 {
	if x != nil {
		return x.LastShockTime
	}
	return 0
}

var File_SceneFishInfo_proto protoreflect.FileDescriptor

var file_SceneFishInfo_proto_rawDesc = []byte{
	0x0a, 0x13, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x46, 0x69, 0x73, 0x68, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xdb, 0x01, 0x0a, 0x0d, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x46, 0x69, 0x73,
	0x68, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x17, 0x0a, 0x07, 0x66, 0x69, 0x73, 0x68, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x66, 0x69, 0x73, 0x68, 0x49, 0x64, 0x12, 0x2d,
	0x0a, 0x13, 0x66, 0x69, 0x73, 0x68, 0x5f, 0x70, 0x6f, 0x6f, 0x6c, 0x5f, 0x65, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x66, 0x69, 0x73,
	0x68, 0x50, 0x6f, 0x6f, 0x6c, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x64, 0x12, 0x2b, 0x0a,
	0x0d, 0x66, 0x69, 0x73, 0x68, 0x5f, 0x70, 0x6f, 0x6f, 0x6c, 0x5f, 0x70, 0x6f, 0x73, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x0b, 0x66,
	0x69, 0x73, 0x68, 0x50, 0x6f, 0x6f, 0x6c, 0x50, 0x6f, 0x73, 0x12, 0x2d, 0x0a, 0x13, 0x66, 0x69,
	0x73, 0x68, 0x5f, 0x70, 0x6f, 0x6f, 0x6c, 0x5f, 0x67, 0x61, 0x64, 0x67, 0x65, 0x74, 0x5f, 0x69,
	0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x66, 0x69, 0x73, 0x68, 0x50, 0x6f, 0x6f,
	0x6c, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x49, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x6c, 0x61, 0x73,
	0x74, 0x5f, 0x73, 0x68, 0x6f, 0x63, 0x6b, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0d, 0x6c, 0x61, 0x73, 0x74, 0x53, 0x68, 0x6f, 0x63, 0x6b, 0x54, 0x69, 0x6d,
	0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_SceneFishInfo_proto_rawDescOnce sync.Once
	file_SceneFishInfo_proto_rawDescData = file_SceneFishInfo_proto_rawDesc
)

func file_SceneFishInfo_proto_rawDescGZIP() []byte {
	file_SceneFishInfo_proto_rawDescOnce.Do(func() {
		file_SceneFishInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_SceneFishInfo_proto_rawDescData)
	})
	return file_SceneFishInfo_proto_rawDescData
}

var file_SceneFishInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SceneFishInfo_proto_goTypes = []interface{}{
	(*SceneFishInfo)(nil), // 0: SceneFishInfo
	(*Vector)(nil),        // 1: Vector
}
var file_SceneFishInfo_proto_depIdxs = []int32{
	1, // 0: SceneFishInfo.fish_pool_pos:type_name -> Vector
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_SceneFishInfo_proto_init() }
func file_SceneFishInfo_proto_init() {
	if File_SceneFishInfo_proto != nil {
		return
	}
	file_Vector_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SceneFishInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SceneFishInfo); i {
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
			RawDescriptor: file_SceneFishInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SceneFishInfo_proto_goTypes,
		DependencyIndexes: file_SceneFishInfo_proto_depIdxs,
		MessageInfos:      file_SceneFishInfo_proto_msgTypes,
	}.Build()
	File_SceneFishInfo_proto = out.File
	file_SceneFishInfo_proto_rawDesc = nil
	file_SceneFishInfo_proto_goTypes = nil
	file_SceneFishInfo_proto_depIdxs = nil
}
