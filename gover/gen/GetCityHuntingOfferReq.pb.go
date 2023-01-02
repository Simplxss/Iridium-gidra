// Sorapointa - A server software re-implementation for a certain anime game, and avoid sorapointa.
// Copyright (C) 2022  Sorapointa Team
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
// 	protoc        v3.11.3
// source: GetCityHuntingOfferReq.proto

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

type GetCityHuntingOfferReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CityId uint32 `protobuf:"varint,3,opt,name=city_id,json=cityId,proto3" json:"city_id,omitempty"`
}

func (x *GetCityHuntingOfferReq) Reset() {
	*x = GetCityHuntingOfferReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetCityHuntingOfferReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCityHuntingOfferReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCityHuntingOfferReq) ProtoMessage() {}

func (x *GetCityHuntingOfferReq) ProtoReflect() protoreflect.Message {
	mi := &file_GetCityHuntingOfferReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCityHuntingOfferReq.ProtoReflect.Descriptor instead.
func (*GetCityHuntingOfferReq) Descriptor() ([]byte, []int) {
	return file_GetCityHuntingOfferReq_proto_rawDescGZIP(), []int{0}
}

func (x *GetCityHuntingOfferReq) GetCityId() uint32 {
	if x != nil {
		return x.CityId
	}
	return 0
}

var File_GetCityHuntingOfferReq_proto protoreflect.FileDescriptor

var file_GetCityHuntingOfferReq_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x47, 0x65, 0x74, 0x43, 0x69, 0x74, 0x79, 0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67,
	0x4f, 0x66, 0x66, 0x65, 0x72, 0x52, 0x65, 0x71, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x31,
	0x0a, 0x16, 0x47, 0x65, 0x74, 0x43, 0x69, 0x74, 0x79, 0x48, 0x75, 0x6e, 0x74, 0x69, 0x6e, 0x67,
	0x4f, 0x66, 0x66, 0x65, 0x72, 0x52, 0x65, 0x71, 0x12, 0x17, 0x0a, 0x07, 0x63, 0x69, 0x74, 0x79,
	0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x63, 0x69, 0x74, 0x79, 0x49,
	0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_GetCityHuntingOfferReq_proto_rawDescOnce sync.Once
	file_GetCityHuntingOfferReq_proto_rawDescData = file_GetCityHuntingOfferReq_proto_rawDesc
)

func file_GetCityHuntingOfferReq_proto_rawDescGZIP() []byte {
	file_GetCityHuntingOfferReq_proto_rawDescOnce.Do(func() {
		file_GetCityHuntingOfferReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_GetCityHuntingOfferReq_proto_rawDescData)
	})
	return file_GetCityHuntingOfferReq_proto_rawDescData
}

var file_GetCityHuntingOfferReq_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GetCityHuntingOfferReq_proto_goTypes = []interface{}{
	(*GetCityHuntingOfferReq)(nil), // 0: GetCityHuntingOfferReq
}
var file_GetCityHuntingOfferReq_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GetCityHuntingOfferReq_proto_init() }
func file_GetCityHuntingOfferReq_proto_init() {
	if File_GetCityHuntingOfferReq_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_GetCityHuntingOfferReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCityHuntingOfferReq); i {
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
			RawDescriptor: file_GetCityHuntingOfferReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GetCityHuntingOfferReq_proto_goTypes,
		DependencyIndexes: file_GetCityHuntingOfferReq_proto_depIdxs,
		MessageInfos:      file_GetCityHuntingOfferReq_proto_msgTypes,
	}.Build()
	File_GetCityHuntingOfferReq_proto = out.File
	file_GetCityHuntingOfferReq_proto_rawDesc = nil
	file_GetCityHuntingOfferReq_proto_goTypes = nil
	file_GetCityHuntingOfferReq_proto_depIdxs = nil
}
