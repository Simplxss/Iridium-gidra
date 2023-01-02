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
// source: PlayerApplyEnterMpNotify.proto

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

type PlayerApplyEnterMpNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SrcPlayerInfo  *OnlinePlayerInfo `protobuf:"bytes,12,opt,name=src_player_info,json=srcPlayerInfo,proto3" json:"src_player_info,omitempty"`
	SrcThreadIndex uint32            `protobuf:"varint,9,opt,name=src_thread_index,json=srcThreadIndex,proto3" json:"src_thread_index,omitempty"`
	SrcAppId       uint32            `protobuf:"varint,13,opt,name=src_app_id,json=srcAppId,proto3" json:"src_app_id,omitempty"`
}

func (x *PlayerApplyEnterMpNotify) Reset() {
	*x = PlayerApplyEnterMpNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_PlayerApplyEnterMpNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PlayerApplyEnterMpNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PlayerApplyEnterMpNotify) ProtoMessage() {}

func (x *PlayerApplyEnterMpNotify) ProtoReflect() protoreflect.Message {
	mi := &file_PlayerApplyEnterMpNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PlayerApplyEnterMpNotify.ProtoReflect.Descriptor instead.
func (*PlayerApplyEnterMpNotify) Descriptor() ([]byte, []int) {
	return file_PlayerApplyEnterMpNotify_proto_rawDescGZIP(), []int{0}
}

func (x *PlayerApplyEnterMpNotify) GetSrcPlayerInfo() *OnlinePlayerInfo {
	if x != nil {
		return x.SrcPlayerInfo
	}
	return nil
}

func (x *PlayerApplyEnterMpNotify) GetSrcThreadIndex() uint32 {
	if x != nil {
		return x.SrcThreadIndex
	}
	return 0
}

func (x *PlayerApplyEnterMpNotify) GetSrcAppId() uint32 {
	if x != nil {
		return x.SrcAppId
	}
	return 0
}

var File_PlayerApplyEnterMpNotify_proto protoreflect.FileDescriptor

var file_PlayerApplyEnterMpNotify_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x41, 0x70, 0x70, 0x6c, 0x79, 0x45, 0x6e, 0x74,
	0x65, 0x72, 0x4d, 0x70, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x16, 0x4f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x49, 0x6e,
	0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9d, 0x01, 0x0a, 0x18, 0x50, 0x6c, 0x61,
	0x79, 0x65, 0x72, 0x41, 0x70, 0x70, 0x6c, 0x79, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x4d, 0x70, 0x4e,
	0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x39, 0x0a, 0x0f, 0x73, 0x72, 0x63, 0x5f, 0x70, 0x6c, 0x61,
	0x79, 0x65, 0x72, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11,
	0x2e, 0x4f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x0d, 0x73, 0x72, 0x63, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f,
	0x12, 0x28, 0x0a, 0x10, 0x73, 0x72, 0x63, 0x5f, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x5f, 0x69,
	0x6e, 0x64, 0x65, 0x78, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x73, 0x72, 0x63, 0x54,
	0x68, 0x72, 0x65, 0x61, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1c, 0x0a, 0x0a, 0x73, 0x72,
	0x63, 0x5f, 0x61, 0x70, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08,
	0x73, 0x72, 0x63, 0x41, 0x70, 0x70, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_PlayerApplyEnterMpNotify_proto_rawDescOnce sync.Once
	file_PlayerApplyEnterMpNotify_proto_rawDescData = file_PlayerApplyEnterMpNotify_proto_rawDesc
)

func file_PlayerApplyEnterMpNotify_proto_rawDescGZIP() []byte {
	file_PlayerApplyEnterMpNotify_proto_rawDescOnce.Do(func() {
		file_PlayerApplyEnterMpNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_PlayerApplyEnterMpNotify_proto_rawDescData)
	})
	return file_PlayerApplyEnterMpNotify_proto_rawDescData
}

var file_PlayerApplyEnterMpNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_PlayerApplyEnterMpNotify_proto_goTypes = []interface{}{
	(*PlayerApplyEnterMpNotify)(nil), // 0: PlayerApplyEnterMpNotify
	(*OnlinePlayerInfo)(nil),         // 1: OnlinePlayerInfo
}
var file_PlayerApplyEnterMpNotify_proto_depIdxs = []int32{
	1, // 0: PlayerApplyEnterMpNotify.src_player_info:type_name -> OnlinePlayerInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_PlayerApplyEnterMpNotify_proto_init() }
func file_PlayerApplyEnterMpNotify_proto_init() {
	if File_PlayerApplyEnterMpNotify_proto != nil {
		return
	}
	file_OnlinePlayerInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_PlayerApplyEnterMpNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PlayerApplyEnterMpNotify); i {
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
			RawDescriptor: file_PlayerApplyEnterMpNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PlayerApplyEnterMpNotify_proto_goTypes,
		DependencyIndexes: file_PlayerApplyEnterMpNotify_proto_depIdxs,
		MessageInfos:      file_PlayerApplyEnterMpNotify_proto_msgTypes,
	}.Build()
	File_PlayerApplyEnterMpNotify_proto = out.File
	file_PlayerApplyEnterMpNotify_proto_rawDesc = nil
	file_PlayerApplyEnterMpNotify_proto_goTypes = nil
	file_PlayerApplyEnterMpNotify_proto_depIdxs = nil
}
