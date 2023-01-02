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
// source: SyncTeamEntityNotify.proto

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

type SyncTeamEntityNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TeamEntityInfoList []*TeamEntityInfo `protobuf:"bytes,10,rep,name=team_entity_info_list,json=teamEntityInfoList,proto3" json:"team_entity_info_list,omitempty"`
	SceneId            uint32            `protobuf:"varint,1,opt,name=scene_id,json=sceneId,proto3" json:"scene_id,omitempty"`
}

func (x *SyncTeamEntityNotify) Reset() {
	*x = SyncTeamEntityNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SyncTeamEntityNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SyncTeamEntityNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyncTeamEntityNotify) ProtoMessage() {}

func (x *SyncTeamEntityNotify) ProtoReflect() protoreflect.Message {
	mi := &file_SyncTeamEntityNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyncTeamEntityNotify.ProtoReflect.Descriptor instead.
func (*SyncTeamEntityNotify) Descriptor() ([]byte, []int) {
	return file_SyncTeamEntityNotify_proto_rawDescGZIP(), []int{0}
}

func (x *SyncTeamEntityNotify) GetTeamEntityInfoList() []*TeamEntityInfo {
	if x != nil {
		return x.TeamEntityInfoList
	}
	return nil
}

func (x *SyncTeamEntityNotify) GetSceneId() uint32 {
	if x != nil {
		return x.SceneId
	}
	return 0
}

var File_SyncTeamEntityNotify_proto protoreflect.FileDescriptor

var file_SyncTeamEntityNotify_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x53, 0x79, 0x6e, 0x63, 0x54, 0x65, 0x61, 0x6d, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x54, 0x65,
	0x61, 0x6d, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x75, 0x0a, 0x14, 0x53, 0x79, 0x6e, 0x63, 0x54, 0x65, 0x61, 0x6d, 0x45, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x42, 0x0a, 0x15, 0x74, 0x65,
	0x61, 0x6d, 0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x54, 0x65, 0x61, 0x6d,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x12, 0x74, 0x65, 0x61, 0x6d,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x19,
	0x0a, 0x08, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x07, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_SyncTeamEntityNotify_proto_rawDescOnce sync.Once
	file_SyncTeamEntityNotify_proto_rawDescData = file_SyncTeamEntityNotify_proto_rawDesc
)

func file_SyncTeamEntityNotify_proto_rawDescGZIP() []byte {
	file_SyncTeamEntityNotify_proto_rawDescOnce.Do(func() {
		file_SyncTeamEntityNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_SyncTeamEntityNotify_proto_rawDescData)
	})
	return file_SyncTeamEntityNotify_proto_rawDescData
}

var file_SyncTeamEntityNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SyncTeamEntityNotify_proto_goTypes = []interface{}{
	(*SyncTeamEntityNotify)(nil), // 0: SyncTeamEntityNotify
	(*TeamEntityInfo)(nil),       // 1: TeamEntityInfo
}
var file_SyncTeamEntityNotify_proto_depIdxs = []int32{
	1, // 0: SyncTeamEntityNotify.team_entity_info_list:type_name -> TeamEntityInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_SyncTeamEntityNotify_proto_init() }
func file_SyncTeamEntityNotify_proto_init() {
	if File_SyncTeamEntityNotify_proto != nil {
		return
	}
	file_TeamEntityInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SyncTeamEntityNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SyncTeamEntityNotify); i {
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
			RawDescriptor: file_SyncTeamEntityNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SyncTeamEntityNotify_proto_goTypes,
		DependencyIndexes: file_SyncTeamEntityNotify_proto_depIdxs,
		MessageInfos:      file_SyncTeamEntityNotify_proto_msgTypes,
	}.Build()
	File_SyncTeamEntityNotify_proto = out.File
	file_SyncTeamEntityNotify_proto_rawDesc = nil
	file_SyncTeamEntityNotify_proto_goTypes = nil
	file_SyncTeamEntityNotify_proto_depIdxs = nil
}
