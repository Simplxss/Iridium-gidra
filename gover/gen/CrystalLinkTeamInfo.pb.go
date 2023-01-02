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
// source: CrystalLinkTeamInfo.proto

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

type CrystalLinkTeamInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AvatarInfoList []*CrystalLinkAvatarInfo `protobuf:"bytes,14,rep,name=avatar_info_list,json=avatarInfoList,proto3" json:"avatar_info_list,omitempty"`
	BuffInfoList   []*CrystalLinkBuffInfo   `protobuf:"bytes,12,rep,name=buff_info_list,json=buffInfoList,proto3" json:"buff_info_list,omitempty"`
}

func (x *CrystalLinkTeamInfo) Reset() {
	*x = CrystalLinkTeamInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CrystalLinkTeamInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CrystalLinkTeamInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CrystalLinkTeamInfo) ProtoMessage() {}

func (x *CrystalLinkTeamInfo) ProtoReflect() protoreflect.Message {
	mi := &file_CrystalLinkTeamInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CrystalLinkTeamInfo.ProtoReflect.Descriptor instead.
func (*CrystalLinkTeamInfo) Descriptor() ([]byte, []int) {
	return file_CrystalLinkTeamInfo_proto_rawDescGZIP(), []int{0}
}

func (x *CrystalLinkTeamInfo) GetAvatarInfoList() []*CrystalLinkAvatarInfo {
	if x != nil {
		return x.AvatarInfoList
	}
	return nil
}

func (x *CrystalLinkTeamInfo) GetBuffInfoList() []*CrystalLinkBuffInfo {
	if x != nil {
		return x.BuffInfoList
	}
	return nil
}

var File_CrystalLinkTeamInfo_proto protoreflect.FileDescriptor

var file_CrystalLinkTeamInfo_proto_rawDesc = []byte{
	0x0a, 0x19, 0x43, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x4c, 0x69, 0x6e, 0x6b, 0x54, 0x65, 0x61,
	0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x43, 0x72, 0x79,
	0x73, 0x74, 0x61, 0x6c, 0x4c, 0x69, 0x6e, 0x6b, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x6e,
	0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x43, 0x72, 0x79, 0x73, 0x74, 0x61,
	0x6c, 0x4c, 0x69, 0x6e, 0x6b, 0x42, 0x75, 0x66, 0x66, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x93, 0x01, 0x0a, 0x13, 0x43, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x4c,
	0x69, 0x6e, 0x6b, 0x54, 0x65, 0x61, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x40, 0x0a, 0x10, 0x61,
	0x76, 0x61, 0x74, 0x61, 0x72, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18,
	0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x43, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x4c,
	0x69, 0x6e, 0x6b, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0e, 0x61,
	0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x3a, 0x0a,
	0x0e, 0x62, 0x75, 0x66, 0x66, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18,
	0x0c, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x43, 0x72, 0x79, 0x73, 0x74, 0x61, 0x6c, 0x4c,
	0x69, 0x6e, 0x6b, 0x42, 0x75, 0x66, 0x66, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0c, 0x62, 0x75, 0x66,
	0x66, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_CrystalLinkTeamInfo_proto_rawDescOnce sync.Once
	file_CrystalLinkTeamInfo_proto_rawDescData = file_CrystalLinkTeamInfo_proto_rawDesc
)

func file_CrystalLinkTeamInfo_proto_rawDescGZIP() []byte {
	file_CrystalLinkTeamInfo_proto_rawDescOnce.Do(func() {
		file_CrystalLinkTeamInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_CrystalLinkTeamInfo_proto_rawDescData)
	})
	return file_CrystalLinkTeamInfo_proto_rawDescData
}

var file_CrystalLinkTeamInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_CrystalLinkTeamInfo_proto_goTypes = []interface{}{
	(*CrystalLinkTeamInfo)(nil),   // 0: CrystalLinkTeamInfo
	(*CrystalLinkAvatarInfo)(nil), // 1: CrystalLinkAvatarInfo
	(*CrystalLinkBuffInfo)(nil),   // 2: CrystalLinkBuffInfo
}
var file_CrystalLinkTeamInfo_proto_depIdxs = []int32{
	1, // 0: CrystalLinkTeamInfo.avatar_info_list:type_name -> CrystalLinkAvatarInfo
	2, // 1: CrystalLinkTeamInfo.buff_info_list:type_name -> CrystalLinkBuffInfo
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_CrystalLinkTeamInfo_proto_init() }
func file_CrystalLinkTeamInfo_proto_init() {
	if File_CrystalLinkTeamInfo_proto != nil {
		return
	}
	file_CrystalLinkAvatarInfo_proto_init()
	file_CrystalLinkBuffInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_CrystalLinkTeamInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CrystalLinkTeamInfo); i {
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
			RawDescriptor: file_CrystalLinkTeamInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_CrystalLinkTeamInfo_proto_goTypes,
		DependencyIndexes: file_CrystalLinkTeamInfo_proto_depIdxs,
		MessageInfos:      file_CrystalLinkTeamInfo_proto_msgTypes,
	}.Build()
	File_CrystalLinkTeamInfo_proto = out.File
	file_CrystalLinkTeamInfo_proto_rawDesc = nil
	file_CrystalLinkTeamInfo_proto_goTypes = nil
	file_CrystalLinkTeamInfo_proto_depIdxs = nil
}
