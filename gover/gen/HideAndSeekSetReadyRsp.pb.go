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
// source: HideAndSeekSetReadyRsp.proto

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

type HideAndSeekSetReadyRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Retcode int32 `protobuf:"varint,15,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *HideAndSeekSetReadyRsp) Reset() {
	*x = HideAndSeekSetReadyRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_HideAndSeekSetReadyRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HideAndSeekSetReadyRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HideAndSeekSetReadyRsp) ProtoMessage() {}

func (x *HideAndSeekSetReadyRsp) ProtoReflect() protoreflect.Message {
	mi := &file_HideAndSeekSetReadyRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HideAndSeekSetReadyRsp.ProtoReflect.Descriptor instead.
func (*HideAndSeekSetReadyRsp) Descriptor() ([]byte, []int) {
	return file_HideAndSeekSetReadyRsp_proto_rawDescGZIP(), []int{0}
}

func (x *HideAndSeekSetReadyRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

var File_HideAndSeekSetReadyRsp_proto protoreflect.FileDescriptor

var file_HideAndSeekSetReadyRsp_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x48, 0x69, 0x64, 0x65, 0x41, 0x6e, 0x64, 0x53, 0x65, 0x65, 0x6b, 0x53, 0x65, 0x74,
	0x52, 0x65, 0x61, 0x64, 0x79, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x32,
	0x0a, 0x16, 0x48, 0x69, 0x64, 0x65, 0x41, 0x6e, 0x64, 0x53, 0x65, 0x65, 0x6b, 0x53, 0x65, 0x74,
	0x52, 0x65, 0x61, 0x64, 0x79, 0x52, 0x73, 0x70, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63,
	0x6f, 0x64, 0x65, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f,
	0x64, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_HideAndSeekSetReadyRsp_proto_rawDescOnce sync.Once
	file_HideAndSeekSetReadyRsp_proto_rawDescData = file_HideAndSeekSetReadyRsp_proto_rawDesc
)

func file_HideAndSeekSetReadyRsp_proto_rawDescGZIP() []byte {
	file_HideAndSeekSetReadyRsp_proto_rawDescOnce.Do(func() {
		file_HideAndSeekSetReadyRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_HideAndSeekSetReadyRsp_proto_rawDescData)
	})
	return file_HideAndSeekSetReadyRsp_proto_rawDescData
}

var file_HideAndSeekSetReadyRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_HideAndSeekSetReadyRsp_proto_goTypes = []interface{}{
	(*HideAndSeekSetReadyRsp)(nil), // 0: HideAndSeekSetReadyRsp
}
var file_HideAndSeekSetReadyRsp_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_HideAndSeekSetReadyRsp_proto_init() }
func file_HideAndSeekSetReadyRsp_proto_init() {
	if File_HideAndSeekSetReadyRsp_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_HideAndSeekSetReadyRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HideAndSeekSetReadyRsp); i {
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
			RawDescriptor: file_HideAndSeekSetReadyRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_HideAndSeekSetReadyRsp_proto_goTypes,
		DependencyIndexes: file_HideAndSeekSetReadyRsp_proto_depIdxs,
		MessageInfos:      file_HideAndSeekSetReadyRsp_proto_msgTypes,
	}.Build()
	File_HideAndSeekSetReadyRsp_proto = out.File
	file_HideAndSeekSetReadyRsp_proto_rawDesc = nil
	file_HideAndSeekSetReadyRsp_proto_goTypes = nil
	file_HideAndSeekSetReadyRsp_proto_depIdxs = nil
}
