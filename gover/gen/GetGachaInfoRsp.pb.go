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
// source: GetGachaInfoRsp.proto

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

// CmdId: 23881
// Obf: IAAKKGACPDM
type GetGachaInfoRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GachaInfoList          []*GachaInfo `protobuf:"bytes,3,rep,name=gacha_info_list,json=gachaInfoList,proto3" json:"gacha_info_list,omitempty"`
	GachaRandom            uint32       `protobuf:"varint,12,opt,name=gachaRandom,proto3" json:"gachaRandom,omitempty"`
	DailyGachaTimes        uint32       `protobuf:"varint,9,opt,name=dailyGachaTimes,proto3" json:"dailyGachaTimes,omitempty"`
	IsUnderGeneralRestrict bool         `protobuf:"varint,7,opt,name=is_under_general_restrict,json=isUnderGeneralRestrict,proto3" json:"is_under_general_restrict,omitempty"`
	Retcode                int32        `protobuf:"varint,2,opt,name=retcode,proto3" json:"retcode,omitempty"`
	IsUnderMinorsRestrict  bool         `protobuf:"varint,5,opt,name=is_under_minors_restrict,json=isUnderMinorsRestrict,proto3" json:"is_under_minors_restrict,omitempty"`
}

func (x *GetGachaInfoRsp) Reset() {
	*x = GetGachaInfoRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetGachaInfoRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetGachaInfoRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetGachaInfoRsp) ProtoMessage() {}

func (x *GetGachaInfoRsp) ProtoReflect() protoreflect.Message {
	mi := &file_GetGachaInfoRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetGachaInfoRsp.ProtoReflect.Descriptor instead.
func (*GetGachaInfoRsp) Descriptor() ([]byte, []int) {
	return file_GetGachaInfoRsp_proto_rawDescGZIP(), []int{0}
}

func (x *GetGachaInfoRsp) GetGachaInfoList() []*GachaInfo {
	if x != nil {
		return x.GachaInfoList
	}
	return nil
}

func (x *GetGachaInfoRsp) GetGachaRandom() uint32 {
	if x != nil {
		return x.GachaRandom
	}
	return 0
}

func (x *GetGachaInfoRsp) GetDailyGachaTimes() uint32 {
	if x != nil {
		return x.DailyGachaTimes
	}
	return 0
}

func (x *GetGachaInfoRsp) GetIsUnderGeneralRestrict() bool {
	if x != nil {
		return x.IsUnderGeneralRestrict
	}
	return false
}

func (x *GetGachaInfoRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *GetGachaInfoRsp) GetIsUnderMinorsRestrict() bool {
	if x != nil {
		return x.IsUnderMinorsRestrict
	}
	return false
}

var File_GetGachaInfoRsp_proto protoreflect.FileDescriptor

var file_GetGachaInfoRsp_proto_rawDesc = []byte{
	0x0a, 0x15, 0x47, 0x65, 0x74, 0x47, 0x61, 0x63, 0x68, 0x61, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x73,
	0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x47, 0x61, 0x63, 0x68, 0x61, 0x49, 0x6e,
	0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9f, 0x02, 0x0a, 0x0f, 0x47, 0x65, 0x74,
	0x47, 0x61, 0x63, 0x68, 0x61, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x73, 0x70, 0x12, 0x32, 0x0a, 0x0f,
	0x67, 0x61, 0x63, 0x68, 0x61, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18,
	0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x47, 0x61, 0x63, 0x68, 0x61, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x0d, 0x67, 0x61, 0x63, 0x68, 0x61, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x20, 0x0a, 0x0b, 0x67, 0x61, 0x63, 0x68, 0x61, 0x52, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x18,
	0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x67, 0x61, 0x63, 0x68, 0x61, 0x52, 0x61, 0x6e, 0x64,
	0x6f, 0x6d, 0x12, 0x28, 0x0a, 0x0f, 0x64, 0x61, 0x69, 0x6c, 0x79, 0x47, 0x61, 0x63, 0x68, 0x61,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x64, 0x61, 0x69,
	0x6c, 0x79, 0x47, 0x61, 0x63, 0x68, 0x61, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x12, 0x39, 0x0a, 0x19,
	0x69, 0x73, 0x5f, 0x75, 0x6e, 0x64, 0x65, 0x72, 0x5f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x5f, 0x72, 0x65, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x16, 0x69, 0x73, 0x55, 0x6e, 0x64, 0x65, 0x72, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c, 0x52,
	0x65, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f,
	0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64,
	0x65, 0x12, 0x37, 0x0a, 0x18, 0x69, 0x73, 0x5f, 0x75, 0x6e, 0x64, 0x65, 0x72, 0x5f, 0x6d, 0x69,
	0x6e, 0x6f, 0x72, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x15, 0x69, 0x73, 0x55, 0x6e, 0x64, 0x65, 0x72, 0x4d, 0x69, 0x6e, 0x6f,
	0x72, 0x73, 0x52, 0x65, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GetGachaInfoRsp_proto_rawDescOnce sync.Once
	file_GetGachaInfoRsp_proto_rawDescData = file_GetGachaInfoRsp_proto_rawDesc
)

func file_GetGachaInfoRsp_proto_rawDescGZIP() []byte {
	file_GetGachaInfoRsp_proto_rawDescOnce.Do(func() {
		file_GetGachaInfoRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_GetGachaInfoRsp_proto_rawDescData)
	})
	return file_GetGachaInfoRsp_proto_rawDescData
}

var file_GetGachaInfoRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GetGachaInfoRsp_proto_goTypes = []interface{}{
	(*GetGachaInfoRsp)(nil), // 0: GetGachaInfoRsp
	(*GachaInfo)(nil),       // 1: GachaInfo
}
var file_GetGachaInfoRsp_proto_depIdxs = []int32{
	1, // 0: GetGachaInfoRsp.gacha_info_list:type_name -> GachaInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GetGachaInfoRsp_proto_init() }
func file_GetGachaInfoRsp_proto_init() {
	if File_GetGachaInfoRsp_proto != nil {
		return
	}
	file_GachaInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GetGachaInfoRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetGachaInfoRsp); i {
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
			RawDescriptor: file_GetGachaInfoRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GetGachaInfoRsp_proto_goTypes,
		DependencyIndexes: file_GetGachaInfoRsp_proto_depIdxs,
		MessageInfos:      file_GetGachaInfoRsp_proto_msgTypes,
	}.Build()
	File_GetGachaInfoRsp_proto = out.File
	file_GetGachaInfoRsp_proto_rawDesc = nil
	file_GetGachaInfoRsp_proto_goTypes = nil
	file_GetGachaInfoRsp_proto_depIdxs = nil
}
