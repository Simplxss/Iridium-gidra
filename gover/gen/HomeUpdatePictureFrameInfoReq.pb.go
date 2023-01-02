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
// source: HomeUpdatePictureFrameInfoReq.proto

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

type HomeUpdatePictureFrameInfoReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PictureFrameInfo *HomePictureFrameInfo `protobuf:"bytes,13,opt,name=picture_frame_info,json=pictureFrameInfo,proto3" json:"picture_frame_info,omitempty"`
}

func (x *HomeUpdatePictureFrameInfoReq) Reset() {
	*x = HomeUpdatePictureFrameInfoReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_HomeUpdatePictureFrameInfoReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HomeUpdatePictureFrameInfoReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HomeUpdatePictureFrameInfoReq) ProtoMessage() {}

func (x *HomeUpdatePictureFrameInfoReq) ProtoReflect() protoreflect.Message {
	mi := &file_HomeUpdatePictureFrameInfoReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HomeUpdatePictureFrameInfoReq.ProtoReflect.Descriptor instead.
func (*HomeUpdatePictureFrameInfoReq) Descriptor() ([]byte, []int) {
	return file_HomeUpdatePictureFrameInfoReq_proto_rawDescGZIP(), []int{0}
}

func (x *HomeUpdatePictureFrameInfoReq) GetPictureFrameInfo() *HomePictureFrameInfo {
	if x != nil {
		return x.PictureFrameInfo
	}
	return nil
}

var File_HomeUpdatePictureFrameInfoReq_proto protoreflect.FileDescriptor

var file_HomeUpdatePictureFrameInfoReq_proto_rawDesc = []byte{
	0x0a, 0x23, 0x48, 0x6f, 0x6d, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x69, 0x63, 0x74,
	0x75, 0x72, 0x65, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x65, 0x71, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x48, 0x6f, 0x6d, 0x65, 0x50, 0x69, 0x63, 0x74, 0x75,
	0x72, 0x65, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x64, 0x0a, 0x1d, 0x48, 0x6f, 0x6d, 0x65, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50,
	0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52,
	0x65, 0x71, 0x12, 0x43, 0x0a, 0x12, 0x70, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x66, 0x72,
	0x61, 0x6d, 0x65, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15,
	0x2e, 0x48, 0x6f, 0x6d, 0x65, 0x50, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x46, 0x72, 0x61, 0x6d,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x10, 0x70, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x46, 0x72,
	0x61, 0x6d, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_HomeUpdatePictureFrameInfoReq_proto_rawDescOnce sync.Once
	file_HomeUpdatePictureFrameInfoReq_proto_rawDescData = file_HomeUpdatePictureFrameInfoReq_proto_rawDesc
)

func file_HomeUpdatePictureFrameInfoReq_proto_rawDescGZIP() []byte {
	file_HomeUpdatePictureFrameInfoReq_proto_rawDescOnce.Do(func() {
		file_HomeUpdatePictureFrameInfoReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_HomeUpdatePictureFrameInfoReq_proto_rawDescData)
	})
	return file_HomeUpdatePictureFrameInfoReq_proto_rawDescData
}

var file_HomeUpdatePictureFrameInfoReq_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_HomeUpdatePictureFrameInfoReq_proto_goTypes = []interface{}{
	(*HomeUpdatePictureFrameInfoReq)(nil), // 0: HomeUpdatePictureFrameInfoReq
	(*HomePictureFrameInfo)(nil),          // 1: HomePictureFrameInfo
}
var file_HomeUpdatePictureFrameInfoReq_proto_depIdxs = []int32{
	1, // 0: HomeUpdatePictureFrameInfoReq.picture_frame_info:type_name -> HomePictureFrameInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_HomeUpdatePictureFrameInfoReq_proto_init() }
func file_HomeUpdatePictureFrameInfoReq_proto_init() {
	if File_HomeUpdatePictureFrameInfoReq_proto != nil {
		return
	}
	file_HomePictureFrameInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_HomeUpdatePictureFrameInfoReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HomeUpdatePictureFrameInfoReq); i {
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
			RawDescriptor: file_HomeUpdatePictureFrameInfoReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_HomeUpdatePictureFrameInfoReq_proto_goTypes,
		DependencyIndexes: file_HomeUpdatePictureFrameInfoReq_proto_depIdxs,
		MessageInfos:      file_HomeUpdatePictureFrameInfoReq_proto_msgTypes,
	}.Build()
	File_HomeUpdatePictureFrameInfoReq_proto = out.File
	file_HomeUpdatePictureFrameInfoReq_proto_rawDesc = nil
	file_HomeUpdatePictureFrameInfoReq_proto_goTypes = nil
	file_HomeUpdatePictureFrameInfoReq_proto_depIdxs = nil
}
