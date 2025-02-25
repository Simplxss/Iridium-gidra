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
// source: PlayerCompoundMaterialBoostRsp.proto

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

// CmdId: 26999
// Obf: MGJOFINPPAE
type PlayerCompoundMaterialBoostRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CompoundQueueDataList []*CompoundQueueData        `protobuf:"bytes,15,rep,name=compoundQueueDataList,proto3" json:"compoundQueueDataList,omitempty"`
	TakeStatus            CompoundBoostTakeStatusType `protobuf:"varint,9,opt,name=take_status,json=takeStatus,proto3,enum=CompoundBoostTakeStatusType" json:"take_status,omitempty"`
	TakeItemList          []*ItemParam                `protobuf:"bytes,12,rep,name=take_item_list,json=takeItemList,proto3" json:"take_item_list,omitempty"`
	Retcode               int32                       `protobuf:"varint,4,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *PlayerCompoundMaterialBoostRsp) Reset() {
	*x = PlayerCompoundMaterialBoostRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_PlayerCompoundMaterialBoostRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PlayerCompoundMaterialBoostRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PlayerCompoundMaterialBoostRsp) ProtoMessage() {}

func (x *PlayerCompoundMaterialBoostRsp) ProtoReflect() protoreflect.Message {
	mi := &file_PlayerCompoundMaterialBoostRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PlayerCompoundMaterialBoostRsp.ProtoReflect.Descriptor instead.
func (*PlayerCompoundMaterialBoostRsp) Descriptor() ([]byte, []int) {
	return file_PlayerCompoundMaterialBoostRsp_proto_rawDescGZIP(), []int{0}
}

func (x *PlayerCompoundMaterialBoostRsp) GetCompoundQueueDataList() []*CompoundQueueData {
	if x != nil {
		return x.CompoundQueueDataList
	}
	return nil
}

func (x *PlayerCompoundMaterialBoostRsp) GetTakeStatus() CompoundBoostTakeStatusType {
	if x != nil {
		return x.TakeStatus
	}
	return CompoundBoostTakeStatusType_COMPOUND_BOOST_TAKE_STATUS_NONE
}

func (x *PlayerCompoundMaterialBoostRsp) GetTakeItemList() []*ItemParam {
	if x != nil {
		return x.TakeItemList
	}
	return nil
}

func (x *PlayerCompoundMaterialBoostRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

var File_PlayerCompoundMaterialBoostRsp_proto protoreflect.FileDescriptor

var file_PlayerCompoundMaterialBoostRsp_proto_rawDesc = []byte{
	0x0a, 0x24, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x75, 0x6e, 0x64,
	0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x42, 0x6f, 0x6f, 0x73, 0x74, 0x52, 0x73, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x75, 0x6e, 0x64,
	0x51, 0x75, 0x65, 0x75, 0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x21, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x75, 0x6e, 0x64, 0x42, 0x6f, 0x6f, 0x73, 0x74, 0x54, 0x61,
	0x6b, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x0f, 0x49, 0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xf5, 0x01, 0x0a, 0x1e, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x43, 0x6f,
	0x6d, 0x70, 0x6f, 0x75, 0x6e, 0x64, 0x4d, 0x61, 0x74, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x42, 0x6f,
	0x6f, 0x73, 0x74, 0x52, 0x73, 0x70, 0x12, 0x48, 0x0a, 0x15, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x75,
	0x6e, 0x64, 0x51, 0x75, 0x65, 0x75, 0x65, 0x44, 0x61, 0x74, 0x61, 0x4c, 0x69, 0x73, 0x74, 0x18,
	0x0f, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x75, 0x6e, 0x64,
	0x51, 0x75, 0x65, 0x75, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x15, 0x63, 0x6f, 0x6d, 0x70, 0x6f,
	0x75, 0x6e, 0x64, 0x51, 0x75, 0x65, 0x75, 0x65, 0x44, 0x61, 0x74, 0x61, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x3d, 0x0a, 0x0b, 0x74, 0x61, 0x6b, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18,
	0x09, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1c, 0x2e, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x75, 0x6e, 0x64,
	0x42, 0x6f, 0x6f, 0x73, 0x74, 0x54, 0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x0a, 0x74, 0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12,
	0x30, 0x0a, 0x0e, 0x74, 0x61, 0x6b, 0x65, 0x5f, 0x69, 0x74, 0x65, 0x6d, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x0c, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x49, 0x74, 0x65, 0x6d, 0x50, 0x61,
	0x72, 0x61, 0x6d, 0x52, 0x0c, 0x74, 0x61, 0x6b, 0x65, 0x49, 0x74, 0x65, 0x6d, 0x4c, 0x69, 0x73,
	0x74, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_PlayerCompoundMaterialBoostRsp_proto_rawDescOnce sync.Once
	file_PlayerCompoundMaterialBoostRsp_proto_rawDescData = file_PlayerCompoundMaterialBoostRsp_proto_rawDesc
)

func file_PlayerCompoundMaterialBoostRsp_proto_rawDescGZIP() []byte {
	file_PlayerCompoundMaterialBoostRsp_proto_rawDescOnce.Do(func() {
		file_PlayerCompoundMaterialBoostRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_PlayerCompoundMaterialBoostRsp_proto_rawDescData)
	})
	return file_PlayerCompoundMaterialBoostRsp_proto_rawDescData
}

var file_PlayerCompoundMaterialBoostRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_PlayerCompoundMaterialBoostRsp_proto_goTypes = []interface{}{
	(*PlayerCompoundMaterialBoostRsp)(nil), // 0: PlayerCompoundMaterialBoostRsp
	(*CompoundQueueData)(nil),              // 1: CompoundQueueData
	(CompoundBoostTakeStatusType)(0),       // 2: CompoundBoostTakeStatusType
	(*ItemParam)(nil),                      // 3: ItemParam
}
var file_PlayerCompoundMaterialBoostRsp_proto_depIdxs = []int32{
	1, // 0: PlayerCompoundMaterialBoostRsp.compoundQueueDataList:type_name -> CompoundQueueData
	2, // 1: PlayerCompoundMaterialBoostRsp.take_status:type_name -> CompoundBoostTakeStatusType
	3, // 2: PlayerCompoundMaterialBoostRsp.take_item_list:type_name -> ItemParam
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_PlayerCompoundMaterialBoostRsp_proto_init() }
func file_PlayerCompoundMaterialBoostRsp_proto_init() {
	if File_PlayerCompoundMaterialBoostRsp_proto != nil {
		return
	}
	file_CompoundQueueData_proto_init()
	file_CompoundBoostTakeStatusType_proto_init()
	file_ItemParam_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_PlayerCompoundMaterialBoostRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PlayerCompoundMaterialBoostRsp); i {
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
			RawDescriptor: file_PlayerCompoundMaterialBoostRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PlayerCompoundMaterialBoostRsp_proto_goTypes,
		DependencyIndexes: file_PlayerCompoundMaterialBoostRsp_proto_depIdxs,
		MessageInfos:      file_PlayerCompoundMaterialBoostRsp_proto_msgTypes,
	}.Build()
	File_PlayerCompoundMaterialBoostRsp_proto = out.File
	file_PlayerCompoundMaterialBoostRsp_proto_rawDesc = nil
	file_PlayerCompoundMaterialBoostRsp_proto_goTypes = nil
	file_PlayerCompoundMaterialBoostRsp_proto_depIdxs = nil
}
