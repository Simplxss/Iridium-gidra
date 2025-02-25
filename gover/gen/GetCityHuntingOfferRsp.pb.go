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
// source: GetCityHuntingOfferRsp.proto

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

// CmdId: 6015
// Obf: PHNMECOCEEN
type GetCityHuntingOfferRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Retcode              int32               `protobuf:"varint,12,opt,name=retcode,proto3" json:"retcode,omitempty"`
	HuntingOfferList     []*HuntingOfferData `protobuf:"bytes,9,rep,name=hunting_offer_list,json=huntingOfferList,proto3" json:"hunting_offer_list,omitempty"`
	NextRefreshTime      uint32              `protobuf:"varint,3,opt,name=next_refresh_time,json=nextRefreshTime,proto3" json:"next_refresh_time,omitempty"`
	CityId               uint32              `protobuf:"varint,6,opt,name=city_id,json=cityId,proto3" json:"city_id,omitempty"`
	CurWeekFinishedCount uint32              `protobuf:"varint,4,opt,name=cur_week_finished_count,json=curWeekFinishedCount,proto3" json:"cur_week_finished_count,omitempty"`
	OngoingHuntingPair   *HuntingPair        `protobuf:"bytes,15,opt,name=ongoing_hunting_pair,json=ongoingHuntingPair,proto3" json:"ongoing_hunting_pair,omitempty"`
}

func (x *GetCityHuntingOfferRsp) Reset() {
	*x = GetCityHuntingOfferRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetCityHuntingOfferRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCityHuntingOfferRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCityHuntingOfferRsp) ProtoMessage() {}

func (x *GetCityHuntingOfferRsp) ProtoReflect() protoreflect.Message {
	mi := &file_GetCityHuntingOfferRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCityHuntingOfferRsp.ProtoReflect.Descriptor instead.
func (*GetCityHuntingOfferRsp) Descriptor() ([]byte, []int) {
	return file_GetCityHuntingOfferRsp_proto_rawDescGZIP(), []int{0}
}

func (x *GetCityHuntingOfferRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *GetCityHuntingOfferRsp) GetHuntingOfferList() []*HuntingOfferData {
	if x != nil {
		return x.HuntingOfferList
	}
	return nil
}

func (x *GetCityHuntingOfferRsp) GetNextRefreshTime() uint32 {
	if x != nil {
		return x.NextRefreshTime
	}
	return 0
}

func (x *GetCityHuntingOfferRsp) GetCityId() uint32 {
	if x != nil {
		return x.CityId
	}
	return 0
}

func (x *GetCityHuntingOfferRsp) GetCurWeekFinishedCount() uint32 {
	if x != nil {
		return x.CurWeekFinishedCount
	}
	return 0
}

func (x *GetCityHuntingOfferRsp) GetOngoingHuntingPair() *HuntingPair {
	if x != nil {
		return x.OngoingHuntingPair
	}
	return nil
}

var File_GetCityHuntingOfferRsp_proto protoreflect.FileDescriptor

var file_GetCityHuntingOfferRsp_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x47, 0x65, 0x74, 0x43, 0x69, 0x74, 0x79, 0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67,
	0x4f, 0x66, 0x66, 0x65, 0x72, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16,
	0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x4f, 0x66, 0x66, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x50,
	0x61, 0x69, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xaf, 0x02, 0x0a, 0x16, 0x47, 0x65,
	0x74, 0x43, 0x69, 0x74, 0x79, 0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x4f, 0x66, 0x66, 0x65,
	0x72, 0x52, 0x73, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18,
	0x0c, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x3f,
	0x0a, 0x12, 0x68, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x5f,
	0x6c, 0x69, 0x73, 0x74, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x48, 0x75, 0x6e,
	0x74, 0x69, 0x6e, 0x67, 0x4f, 0x66, 0x66, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x52, 0x10, 0x68,
	0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x4f, 0x66, 0x66, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x12,
	0x2a, 0x0a, 0x11, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x6e, 0x65, 0x78, 0x74,
	0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x63,
	0x69, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x63, 0x69,
	0x74, 0x79, 0x49, 0x64, 0x12, 0x35, 0x0a, 0x17, 0x63, 0x75, 0x72, 0x5f, 0x77, 0x65, 0x65, 0x6b,
	0x5f, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x14, 0x63, 0x75, 0x72, 0x57, 0x65, 0x65, 0x6b, 0x46, 0x69,
	0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x3e, 0x0a, 0x14, 0x6f,
	0x6e, 0x67, 0x6f, 0x69, 0x6e, 0x67, 0x5f, 0x68, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x70,
	0x61, 0x69, 0x72, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x48, 0x75, 0x6e, 0x74,
	0x69, 0x6e, 0x67, 0x50, 0x61, 0x69, 0x72, 0x52, 0x12, 0x6f, 0x6e, 0x67, 0x6f, 0x69, 0x6e, 0x67,
	0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67, 0x50, 0x61, 0x69, 0x72, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GetCityHuntingOfferRsp_proto_rawDescOnce sync.Once
	file_GetCityHuntingOfferRsp_proto_rawDescData = file_GetCityHuntingOfferRsp_proto_rawDesc
)

func file_GetCityHuntingOfferRsp_proto_rawDescGZIP() []byte {
	file_GetCityHuntingOfferRsp_proto_rawDescOnce.Do(func() {
		file_GetCityHuntingOfferRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_GetCityHuntingOfferRsp_proto_rawDescData)
	})
	return file_GetCityHuntingOfferRsp_proto_rawDescData
}

var file_GetCityHuntingOfferRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GetCityHuntingOfferRsp_proto_goTypes = []interface{}{
	(*GetCityHuntingOfferRsp)(nil), // 0: GetCityHuntingOfferRsp
	(*HuntingOfferData)(nil),       // 1: HuntingOfferData
	(*HuntingPair)(nil),            // 2: HuntingPair
}
var file_GetCityHuntingOfferRsp_proto_depIdxs = []int32{
	1, // 0: GetCityHuntingOfferRsp.hunting_offer_list:type_name -> HuntingOfferData
	2, // 1: GetCityHuntingOfferRsp.ongoing_hunting_pair:type_name -> HuntingPair
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_GetCityHuntingOfferRsp_proto_init() }
func file_GetCityHuntingOfferRsp_proto_init() {
	if File_GetCityHuntingOfferRsp_proto != nil {
		return
	}
	file_HuntingOfferData_proto_init()
	file_HuntingPair_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GetCityHuntingOfferRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCityHuntingOfferRsp); i {
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
			RawDescriptor: file_GetCityHuntingOfferRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GetCityHuntingOfferRsp_proto_goTypes,
		DependencyIndexes: file_GetCityHuntingOfferRsp_proto_depIdxs,
		MessageInfos:      file_GetCityHuntingOfferRsp_proto_msgTypes,
	}.Build()
	File_GetCityHuntingOfferRsp_proto = out.File
	file_GetCityHuntingOfferRsp_proto_rawDesc = nil
	file_GetCityHuntingOfferRsp_proto_goTypes = nil
	file_GetCityHuntingOfferRsp_proto_depIdxs = nil
}
