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
// source: GlobalBuildingInfoNotify.proto

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

// CmdId: 3344
// Obf: KGCFGIGOKLC
type GlobalBuildingInfoNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CurrentNum   uint32          `protobuf:"varint,1,opt,name=current_num,json=currentNum,proto3" json:"current_num,omitempty"`
	MaxNum       uint32          `protobuf:"varint,5,opt,name=max_num,json=maxNum,proto3" json:"max_num,omitempty"`
	BuildingList []*BuildingInfo `protobuf:"bytes,7,rep,name=building_list,json=buildingList,proto3" json:"building_list,omitempty"`
}

func (x *GlobalBuildingInfoNotify) Reset() {
	*x = GlobalBuildingInfoNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GlobalBuildingInfoNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GlobalBuildingInfoNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GlobalBuildingInfoNotify) ProtoMessage() {}

func (x *GlobalBuildingInfoNotify) ProtoReflect() protoreflect.Message {
	mi := &file_GlobalBuildingInfoNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GlobalBuildingInfoNotify.ProtoReflect.Descriptor instead.
func (*GlobalBuildingInfoNotify) Descriptor() ([]byte, []int) {
	return file_GlobalBuildingInfoNotify_proto_rawDescGZIP(), []int{0}
}

func (x *GlobalBuildingInfoNotify) GetCurrentNum() uint32 {
	if x != nil {
		return x.CurrentNum
	}
	return 0
}

func (x *GlobalBuildingInfoNotify) GetMaxNum() uint32 {
	if x != nil {
		return x.MaxNum
	}
	return 0
}

func (x *GlobalBuildingInfoNotify) GetBuildingList() []*BuildingInfo {
	if x != nil {
		return x.BuildingList
	}
	return nil
}

var File_GlobalBuildingInfoNotify_proto protoreflect.FileDescriptor

var file_GlobalBuildingInfoNotify_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67,
	0x49, 0x6e, 0x66, 0x6f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x12, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x88, 0x01, 0x0a, 0x18, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x42,
	0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x4e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x75, 0x6d,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x4e,
	0x75, 0x6d, 0x12, 0x17, 0x0a, 0x07, 0x6d, 0x61, 0x78, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x06, 0x6d, 0x61, 0x78, 0x4e, 0x75, 0x6d, 0x12, 0x32, 0x0a, 0x0d, 0x62,
	0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x07, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x0c, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x4c, 0x69, 0x73, 0x74, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GlobalBuildingInfoNotify_proto_rawDescOnce sync.Once
	file_GlobalBuildingInfoNotify_proto_rawDescData = file_GlobalBuildingInfoNotify_proto_rawDesc
)

func file_GlobalBuildingInfoNotify_proto_rawDescGZIP() []byte {
	file_GlobalBuildingInfoNotify_proto_rawDescOnce.Do(func() {
		file_GlobalBuildingInfoNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_GlobalBuildingInfoNotify_proto_rawDescData)
	})
	return file_GlobalBuildingInfoNotify_proto_rawDescData
}

var file_GlobalBuildingInfoNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GlobalBuildingInfoNotify_proto_goTypes = []interface{}{
	(*GlobalBuildingInfoNotify)(nil), // 0: GlobalBuildingInfoNotify
	(*BuildingInfo)(nil),             // 1: BuildingInfo
}
var file_GlobalBuildingInfoNotify_proto_depIdxs = []int32{
	1, // 0: GlobalBuildingInfoNotify.building_list:type_name -> BuildingInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GlobalBuildingInfoNotify_proto_init() }
func file_GlobalBuildingInfoNotify_proto_init() {
	if File_GlobalBuildingInfoNotify_proto != nil {
		return
	}
	file_BuildingInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GlobalBuildingInfoNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GlobalBuildingInfoNotify); i {
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
			RawDescriptor: file_GlobalBuildingInfoNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GlobalBuildingInfoNotify_proto_goTypes,
		DependencyIndexes: file_GlobalBuildingInfoNotify_proto_depIdxs,
		MessageInfos:      file_GlobalBuildingInfoNotify_proto_msgTypes,
	}.Build()
	File_GlobalBuildingInfoNotify_proto = out.File
	file_GlobalBuildingInfoNotify_proto_rawDesc = nil
	file_GlobalBuildingInfoNotify_proto_goTypes = nil
	file_GlobalBuildingInfoNotify_proto_depIdxs = nil
}
