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
// source: WinterCampAcceptAllGiveItemRsp.proto

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

// CmdId: 4655
// Obf: LJFOBNJDABD
type WinterCampAcceptAllGiveItemRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AcceptItemResultInfo []*WinterCampAcceptItemResultInfo `protobuf:"bytes,8,rep,name=accept_item_result_info,json=acceptItemResultInfo,proto3" json:"accept_item_result_info,omitempty"`
	Retcode              int32                             `protobuf:"varint,4,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *WinterCampAcceptAllGiveItemRsp) Reset() {
	*x = WinterCampAcceptAllGiveItemRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_WinterCampAcceptAllGiveItemRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WinterCampAcceptAllGiveItemRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WinterCampAcceptAllGiveItemRsp) ProtoMessage() {}

func (x *WinterCampAcceptAllGiveItemRsp) ProtoReflect() protoreflect.Message {
	mi := &file_WinterCampAcceptAllGiveItemRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WinterCampAcceptAllGiveItemRsp.ProtoReflect.Descriptor instead.
func (*WinterCampAcceptAllGiveItemRsp) Descriptor() ([]byte, []int) {
	return file_WinterCampAcceptAllGiveItemRsp_proto_rawDescGZIP(), []int{0}
}

func (x *WinterCampAcceptAllGiveItemRsp) GetAcceptItemResultInfo() []*WinterCampAcceptItemResultInfo {
	if x != nil {
		return x.AcceptItemResultInfo
	}
	return nil
}

func (x *WinterCampAcceptAllGiveItemRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

var File_WinterCampAcceptAllGiveItemRsp_proto protoreflect.FileDescriptor

var file_WinterCampAcceptAllGiveItemRsp_proto_rawDesc = []byte{
	0x0a, 0x24, 0x57, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x61, 0x6d, 0x70, 0x41, 0x63, 0x63, 0x65,
	0x70, 0x74, 0x41, 0x6c, 0x6c, 0x47, 0x69, 0x76, 0x65, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x73, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x24, 0x57, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x61,
	0x6d, 0x70, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x92, 0x01, 0x0a,
	0x1e, 0x57, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x61, 0x6d, 0x70, 0x41, 0x63, 0x63, 0x65, 0x70,
	0x74, 0x41, 0x6c, 0x6c, 0x47, 0x69, 0x76, 0x65, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x73, 0x70, 0x12,
	0x56, 0x0a, 0x17, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x5f, 0x69, 0x74, 0x65, 0x6d, 0x5f, 0x72,
	0x65, 0x73, 0x75, 0x6c, 0x74, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x1f, 0x2e, 0x57, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x61, 0x6d, 0x70, 0x41, 0x63, 0x63,
	0x65, 0x70, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x14, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x65, 0x73,
	0x75, 0x6c, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f,
	0x64, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64,
	0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_WinterCampAcceptAllGiveItemRsp_proto_rawDescOnce sync.Once
	file_WinterCampAcceptAllGiveItemRsp_proto_rawDescData = file_WinterCampAcceptAllGiveItemRsp_proto_rawDesc
)

func file_WinterCampAcceptAllGiveItemRsp_proto_rawDescGZIP() []byte {
	file_WinterCampAcceptAllGiveItemRsp_proto_rawDescOnce.Do(func() {
		file_WinterCampAcceptAllGiveItemRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_WinterCampAcceptAllGiveItemRsp_proto_rawDescData)
	})
	return file_WinterCampAcceptAllGiveItemRsp_proto_rawDescData
}

var file_WinterCampAcceptAllGiveItemRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_WinterCampAcceptAllGiveItemRsp_proto_goTypes = []interface{}{
	(*WinterCampAcceptAllGiveItemRsp)(nil), // 0: WinterCampAcceptAllGiveItemRsp
	(*WinterCampAcceptItemResultInfo)(nil), // 1: WinterCampAcceptItemResultInfo
}
var file_WinterCampAcceptAllGiveItemRsp_proto_depIdxs = []int32{
	1, // 0: WinterCampAcceptAllGiveItemRsp.accept_item_result_info:type_name -> WinterCampAcceptItemResultInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_WinterCampAcceptAllGiveItemRsp_proto_init() }
func file_WinterCampAcceptAllGiveItemRsp_proto_init() {
	if File_WinterCampAcceptAllGiveItemRsp_proto != nil {
		return
	}
	file_WinterCampAcceptItemResultInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_WinterCampAcceptAllGiveItemRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WinterCampAcceptAllGiveItemRsp); i {
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
			RawDescriptor: file_WinterCampAcceptAllGiveItemRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_WinterCampAcceptAllGiveItemRsp_proto_goTypes,
		DependencyIndexes: file_WinterCampAcceptAllGiveItemRsp_proto_depIdxs,
		MessageInfos:      file_WinterCampAcceptAllGiveItemRsp_proto_msgTypes,
	}.Build()
	File_WinterCampAcceptAllGiveItemRsp_proto = out.File
	file_WinterCampAcceptAllGiveItemRsp_proto_rawDesc = nil
	file_WinterCampAcceptAllGiveItemRsp_proto_goTypes = nil
	file_WinterCampAcceptAllGiveItemRsp_proto_depIdxs = nil
}
