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
// source: GMShowObstacleRsp.proto

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

// CmdId: 2327
// Obf: ICKFGENGGKI
type GMShowObstacleRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Retcode   int32             `protobuf:"varint,4,opt,name=retcode,proto3" json:"retcode,omitempty"`
	Obstacles []*GMObstacleInfo `protobuf:"bytes,12,rep,name=obstacles,proto3" json:"obstacles,omitempty"`
}

func (x *GMShowObstacleRsp) Reset() {
	*x = GMShowObstacleRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GMShowObstacleRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GMShowObstacleRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GMShowObstacleRsp) ProtoMessage() {}

func (x *GMShowObstacleRsp) ProtoReflect() protoreflect.Message {
	mi := &file_GMShowObstacleRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GMShowObstacleRsp.ProtoReflect.Descriptor instead.
func (*GMShowObstacleRsp) Descriptor() ([]byte, []int) {
	return file_GMShowObstacleRsp_proto_rawDescGZIP(), []int{0}
}

func (x *GMShowObstacleRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *GMShowObstacleRsp) GetObstacles() []*GMObstacleInfo {
	if x != nil {
		return x.Obstacles
	}
	return nil
}

var File_GMShowObstacleRsp_proto protoreflect.FileDescriptor

var file_GMShowObstacleRsp_proto_rawDesc = []byte{
	0x0a, 0x17, 0x47, 0x4d, 0x53, 0x68, 0x6f, 0x77, 0x4f, 0x62, 0x73, 0x74, 0x61, 0x63, 0x6c, 0x65,
	0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x47, 0x4d, 0x4f, 0x62, 0x73,
	0x74, 0x61, 0x63, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x5c, 0x0a, 0x11, 0x47, 0x4d, 0x53, 0x68, 0x6f, 0x77, 0x4f, 0x62, 0x73, 0x74, 0x61, 0x63, 0x6c,
	0x65, 0x52, 0x73, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x2d,
	0x0a, 0x09, 0x6f, 0x62, 0x73, 0x74, 0x61, 0x63, 0x6c, 0x65, 0x73, 0x18, 0x0c, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x0f, 0x2e, 0x47, 0x4d, 0x4f, 0x62, 0x73, 0x74, 0x61, 0x63, 0x6c, 0x65, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x09, 0x6f, 0x62, 0x73, 0x74, 0x61, 0x63, 0x6c, 0x65, 0x73, 0x42, 0x06, 0x5a,
	0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GMShowObstacleRsp_proto_rawDescOnce sync.Once
	file_GMShowObstacleRsp_proto_rawDescData = file_GMShowObstacleRsp_proto_rawDesc
)

func file_GMShowObstacleRsp_proto_rawDescGZIP() []byte {
	file_GMShowObstacleRsp_proto_rawDescOnce.Do(func() {
		file_GMShowObstacleRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_GMShowObstacleRsp_proto_rawDescData)
	})
	return file_GMShowObstacleRsp_proto_rawDescData
}

var file_GMShowObstacleRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GMShowObstacleRsp_proto_goTypes = []interface{}{
	(*GMShowObstacleRsp)(nil), // 0: GMShowObstacleRsp
	(*GMObstacleInfo)(nil),    // 1: GMObstacleInfo
}
var file_GMShowObstacleRsp_proto_depIdxs = []int32{
	1, // 0: GMShowObstacleRsp.obstacles:type_name -> GMObstacleInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GMShowObstacleRsp_proto_init() }
func file_GMShowObstacleRsp_proto_init() {
	if File_GMShowObstacleRsp_proto != nil {
		return
	}
	file_GMObstacleInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GMShowObstacleRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GMShowObstacleRsp); i {
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
			RawDescriptor: file_GMShowObstacleRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GMShowObstacleRsp_proto_goTypes,
		DependencyIndexes: file_GMShowObstacleRsp_proto_depIdxs,
		MessageInfos:      file_GMShowObstacleRsp_proto_msgTypes,
	}.Build()
	File_GMShowObstacleRsp_proto = out.File
	file_GMShowObstacleRsp_proto_rawDesc = nil
	file_GMShowObstacleRsp_proto_goTypes = nil
	file_GMShowObstacleRsp_proto_depIdxs = nil
}
