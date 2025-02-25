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
// source: GetHomeExchangeWoodInfoRsp.proto

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

// CmdId: 27659
// Obf: GLMEBEPIKNK
type GetHomeExchangeWoodInfoRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	WoodInfoList []*GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo `protobuf:"bytes,11,rep,name=wood_info_list,json=woodInfoList,proto3" json:"wood_info_list,omitempty"`
	Retcode      int32                                              `protobuf:"varint,5,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *GetHomeExchangeWoodInfoRsp) Reset() {
	*x = GetHomeExchangeWoodInfoRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetHomeExchangeWoodInfoRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetHomeExchangeWoodInfoRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetHomeExchangeWoodInfoRsp) ProtoMessage() {}

func (x *GetHomeExchangeWoodInfoRsp) ProtoReflect() protoreflect.Message {
	mi := &file_GetHomeExchangeWoodInfoRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetHomeExchangeWoodInfoRsp.ProtoReflect.Descriptor instead.
func (*GetHomeExchangeWoodInfoRsp) Descriptor() ([]byte, []int) {
	return file_GetHomeExchangeWoodInfoRsp_proto_rawDescGZIP(), []int{0}
}

func (x *GetHomeExchangeWoodInfoRsp) GetWoodInfoList() []*GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo {
	if x != nil {
		return x.WoodInfoList
	}
	return nil
}

func (x *GetHomeExchangeWoodInfoRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

// Obf: HAGHCNJCHNF
type GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ExchangedCount  uint32 `protobuf:"varint,7,opt,name=exchangedCount,proto3" json:"exchangedCount,omitempty"`
	ExchangeLimit   uint32 `protobuf:"varint,1,opt,name=exchangeLimit,proto3" json:"exchangeLimit,omitempty"`
	NextRefreshTime uint32 `protobuf:"fixed32,4,opt,name=next_refresh_time,json=nextRefreshTime,proto3" json:"next_refresh_time,omitempty"`
	WoodId          uint32 `protobuf:"varint,13,opt,name=wood_id,json=woodId,proto3" json:"wood_id,omitempty"`
}

func (x *GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) Reset() {
	*x = GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetHomeExchangeWoodInfoRsp_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) ProtoMessage() {}

func (x *GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) ProtoReflect() protoreflect.Message {
	mi := &file_GetHomeExchangeWoodInfoRsp_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo.ProtoReflect.Descriptor instead.
func (*GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) Descriptor() ([]byte, []int) {
	return file_GetHomeExchangeWoodInfoRsp_proto_rawDescGZIP(), []int{0, 0}
}

func (x *GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) GetExchangedCount() uint32 {
	if x != nil {
		return x.ExchangedCount
	}
	return 0
}

func (x *GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) GetExchangeLimit() uint32 {
	if x != nil {
		return x.ExchangeLimit
	}
	return 0
}

func (x *GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) GetNextRefreshTime() uint32 {
	if x != nil {
		return x.NextRefreshTime
	}
	return 0
}

func (x *GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo) GetWoodId() uint32 {
	if x != nil {
		return x.WoodId
	}
	return 0
}

var File_GetHomeExchangeWoodInfoRsp_proto protoreflect.FileDescriptor

var file_GetHomeExchangeWoodInfoRsp_proto_rawDesc = []byte{
	0x0a, 0x20, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x6d, 0x65, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67,
	0x65, 0x57, 0x6f, 0x6f, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xba, 0x02, 0x0a, 0x1a, 0x47, 0x65, 0x74, 0x48, 0x6f, 0x6d, 0x65, 0x45, 0x78,
	0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x57, 0x6f, 0x6f, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x73,
	0x70, 0x12, 0x56, 0x0a, 0x0e, 0x77, 0x6f, 0x6f, 0x64, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x47, 0x65, 0x74, 0x48,
	0x6f, 0x6d, 0x65, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x57, 0x6f, 0x6f, 0x64, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x73, 0x70, 0x2e, 0x48, 0x6f, 0x6d, 0x65, 0x45, 0x78, 0x63, 0x68, 0x61,
	0x6e, 0x67, 0x65, 0x57, 0x6f, 0x6f, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0c, 0x77, 0x6f, 0x6f,
	0x64, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74,
	0x63, 0x6f, 0x64, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63,
	0x6f, 0x64, 0x65, 0x1a, 0xa9, 0x01, 0x0a, 0x14, 0x48, 0x6f, 0x6d, 0x65, 0x45, 0x78, 0x63, 0x68,
	0x61, 0x6e, 0x67, 0x65, 0x57, 0x6f, 0x6f, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x26, 0x0a, 0x0e,
	0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x64, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x64, 0x43,
	0x6f, 0x75, 0x6e, 0x74, 0x12, 0x24, 0x0a, 0x0d, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65,
	0x4c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x65, 0x78, 0x63,
	0x68, 0x61, 0x6e, 0x67, 0x65, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x2a, 0x0a, 0x11, 0x6e, 0x65,
	0x78, 0x74, 0x5f, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x07, 0x52, 0x0f, 0x6e, 0x65, 0x78, 0x74, 0x52, 0x65, 0x66, 0x72, 0x65,
	0x73, 0x68, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x77, 0x6f, 0x6f, 0x64, 0x5f, 0x69,
	0x64, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x77, 0x6f, 0x6f, 0x64, 0x49, 0x64, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GetHomeExchangeWoodInfoRsp_proto_rawDescOnce sync.Once
	file_GetHomeExchangeWoodInfoRsp_proto_rawDescData = file_GetHomeExchangeWoodInfoRsp_proto_rawDesc
)

func file_GetHomeExchangeWoodInfoRsp_proto_rawDescGZIP() []byte {
	file_GetHomeExchangeWoodInfoRsp_proto_rawDescOnce.Do(func() {
		file_GetHomeExchangeWoodInfoRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_GetHomeExchangeWoodInfoRsp_proto_rawDescData)
	})
	return file_GetHomeExchangeWoodInfoRsp_proto_rawDescData
}

var file_GetHomeExchangeWoodInfoRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_GetHomeExchangeWoodInfoRsp_proto_goTypes = []interface{}{
	(*GetHomeExchangeWoodInfoRsp)(nil),                      // 0: GetHomeExchangeWoodInfoRsp
	(*GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo)(nil), // 1: GetHomeExchangeWoodInfoRsp.HomeExchangeWoodInfo
}
var file_GetHomeExchangeWoodInfoRsp_proto_depIdxs = []int32{
	1, // 0: GetHomeExchangeWoodInfoRsp.wood_info_list:type_name -> GetHomeExchangeWoodInfoRsp.HomeExchangeWoodInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GetHomeExchangeWoodInfoRsp_proto_init() }
func file_GetHomeExchangeWoodInfoRsp_proto_init() {
	if File_GetHomeExchangeWoodInfoRsp_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_GetHomeExchangeWoodInfoRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetHomeExchangeWoodInfoRsp); i {
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
		file_GetHomeExchangeWoodInfoRsp_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetHomeExchangeWoodInfoRsp_HomeExchangeWoodInfo); i {
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
			RawDescriptor: file_GetHomeExchangeWoodInfoRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GetHomeExchangeWoodInfoRsp_proto_goTypes,
		DependencyIndexes: file_GetHomeExchangeWoodInfoRsp_proto_depIdxs,
		MessageInfos:      file_GetHomeExchangeWoodInfoRsp_proto_msgTypes,
	}.Build()
	File_GetHomeExchangeWoodInfoRsp_proto = out.File
	file_GetHomeExchangeWoodInfoRsp_proto_rawDesc = nil
	file_GetHomeExchangeWoodInfoRsp_proto_goTypes = nil
	file_GetHomeExchangeWoodInfoRsp_proto_depIdxs = nil
}
