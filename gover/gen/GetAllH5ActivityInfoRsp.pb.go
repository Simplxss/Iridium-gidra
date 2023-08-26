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
// source: GetAllH5ActivityInfoRsp.proto

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

// CmdId: 28822
// Obf: LHPLDILJKAG
type GetAllH5ActivityInfoRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	H5ActivityInfoList    []*H5ActivityInfo `protobuf:"bytes,6,rep,name=h5_activity_info_list,json=h5ActivityInfoList,proto3" json:"h5_activity_info_list,omitempty"`
	Retcode               int32             `protobuf:"varint,1,opt,name=retcode,proto3" json:"retcode,omitempty"`
	ClientRedDotTimestamp uint32            `protobuf:"varint,4,opt,name=client_red_dot_timestamp,json=clientRedDotTimestamp,proto3" json:"client_red_dot_timestamp,omitempty"`
}

func (x *GetAllH5ActivityInfoRsp) Reset() {
	*x = GetAllH5ActivityInfoRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GetAllH5ActivityInfoRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetAllH5ActivityInfoRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetAllH5ActivityInfoRsp) ProtoMessage() {}

func (x *GetAllH5ActivityInfoRsp) ProtoReflect() protoreflect.Message {
	mi := &file_GetAllH5ActivityInfoRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetAllH5ActivityInfoRsp.ProtoReflect.Descriptor instead.
func (*GetAllH5ActivityInfoRsp) Descriptor() ([]byte, []int) {
	return file_GetAllH5ActivityInfoRsp_proto_rawDescGZIP(), []int{0}
}

func (x *GetAllH5ActivityInfoRsp) GetH5ActivityInfoList() []*H5ActivityInfo {
	if x != nil {
		return x.H5ActivityInfoList
	}
	return nil
}

func (x *GetAllH5ActivityInfoRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *GetAllH5ActivityInfoRsp) GetClientRedDotTimestamp() uint32 {
	if x != nil {
		return x.ClientRedDotTimestamp
	}
	return 0
}

var File_GetAllH5ActivityInfoRsp_proto protoreflect.FileDescriptor

var file_GetAllH5ActivityInfoRsp_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x47, 0x65, 0x74, 0x41, 0x6c, 0x6c, 0x48, 0x35, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69,
	0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x14, 0x48, 0x35, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb0, 0x01, 0x0a, 0x17, 0x47, 0x65, 0x74, 0x41, 0x6c, 0x6c,
	0x48, 0x35, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x73,
	0x70, 0x12, 0x42, 0x0a, 0x15, 0x68, 0x35, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79,
	0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x0f, 0x2e, 0x48, 0x35, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x12, 0x68, 0x35, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66,
	0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12,
	0x37, 0x0a, 0x18, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x72, 0x65, 0x64, 0x5f, 0x64, 0x6f,
	0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x15, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x64, 0x44, 0x6f, 0x74, 0x54,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GetAllH5ActivityInfoRsp_proto_rawDescOnce sync.Once
	file_GetAllH5ActivityInfoRsp_proto_rawDescData = file_GetAllH5ActivityInfoRsp_proto_rawDesc
)

func file_GetAllH5ActivityInfoRsp_proto_rawDescGZIP() []byte {
	file_GetAllH5ActivityInfoRsp_proto_rawDescOnce.Do(func() {
		file_GetAllH5ActivityInfoRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_GetAllH5ActivityInfoRsp_proto_rawDescData)
	})
	return file_GetAllH5ActivityInfoRsp_proto_rawDescData
}

var file_GetAllH5ActivityInfoRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GetAllH5ActivityInfoRsp_proto_goTypes = []interface{}{
	(*GetAllH5ActivityInfoRsp)(nil), // 0: GetAllH5ActivityInfoRsp
	(*H5ActivityInfo)(nil),          // 1: H5ActivityInfo
}
var file_GetAllH5ActivityInfoRsp_proto_depIdxs = []int32{
	1, // 0: GetAllH5ActivityInfoRsp.h5_activity_info_list:type_name -> H5ActivityInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GetAllH5ActivityInfoRsp_proto_init() }
func file_GetAllH5ActivityInfoRsp_proto_init() {
	if File_GetAllH5ActivityInfoRsp_proto != nil {
		return
	}
	file_H5ActivityInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GetAllH5ActivityInfoRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetAllH5ActivityInfoRsp); i {
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
			RawDescriptor: file_GetAllH5ActivityInfoRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GetAllH5ActivityInfoRsp_proto_goTypes,
		DependencyIndexes: file_GetAllH5ActivityInfoRsp_proto_depIdxs,
		MessageInfos:      file_GetAllH5ActivityInfoRsp_proto_msgTypes,
	}.Build()
	File_GetAllH5ActivityInfoRsp_proto = out.File
	file_GetAllH5ActivityInfoRsp_proto_rawDesc = nil
	file_GetAllH5ActivityInfoRsp_proto_goTypes = nil
	file_GetAllH5ActivityInfoRsp_proto_depIdxs = nil
}
