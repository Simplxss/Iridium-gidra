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
// source: ProudSkillExtraLevelNotify.proto

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

type ProudSkillExtraLevelNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AvatarGuid  uint64 `protobuf:"varint,13,opt,name=avatar_guid,json=avatarGuid,proto3" json:"avatar_guid,omitempty"`
	ExtraLevel  uint32 `protobuf:"varint,4,opt,name=extra_level,json=extraLevel,proto3" json:"extra_level,omitempty"`
	TalentType  uint32 `protobuf:"varint,8,opt,name=talent_type,json=talentType,proto3" json:"talent_type,omitempty"`
	TalentIndex uint32 `protobuf:"varint,2,opt,name=talent_index,json=talentIndex,proto3" json:"talent_index,omitempty"`
}

func (x *ProudSkillExtraLevelNotify) Reset() {
	*x = ProudSkillExtraLevelNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ProudSkillExtraLevelNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProudSkillExtraLevelNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProudSkillExtraLevelNotify) ProtoMessage() {}

func (x *ProudSkillExtraLevelNotify) ProtoReflect() protoreflect.Message {
	mi := &file_ProudSkillExtraLevelNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProudSkillExtraLevelNotify.ProtoReflect.Descriptor instead.
func (*ProudSkillExtraLevelNotify) Descriptor() ([]byte, []int) {
	return file_ProudSkillExtraLevelNotify_proto_rawDescGZIP(), []int{0}
}

func (x *ProudSkillExtraLevelNotify) GetAvatarGuid() uint64 {
	if x != nil {
		return x.AvatarGuid
	}
	return 0
}

func (x *ProudSkillExtraLevelNotify) GetExtraLevel() uint32 {
	if x != nil {
		return x.ExtraLevel
	}
	return 0
}

func (x *ProudSkillExtraLevelNotify) GetTalentType() uint32 {
	if x != nil {
		return x.TalentType
	}
	return 0
}

func (x *ProudSkillExtraLevelNotify) GetTalentIndex() uint32 {
	if x != nil {
		return x.TalentIndex
	}
	return 0
}

var File_ProudSkillExtraLevelNotify_proto protoreflect.FileDescriptor

var file_ProudSkillExtraLevelNotify_proto_rawDesc = []byte{
	0x0a, 0x20, 0x50, 0x72, 0x6f, 0x75, 0x64, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x45, 0x78, 0x74, 0x72,
	0x61, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xa2, 0x01, 0x0a, 0x1a, 0x50, 0x72, 0x6f, 0x75, 0x64, 0x53, 0x6b, 0x69, 0x6c,
	0x6c, 0x45, 0x78, 0x74, 0x72, 0x61, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x4e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x12, 0x1f, 0x0a, 0x0b, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x5f, 0x67, 0x75, 0x69, 0x64,
	0x18, 0x0d, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x47, 0x75,
	0x69, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x65, 0x78, 0x74, 0x72, 0x61, 0x5f, 0x6c, 0x65, 0x76, 0x65,
	0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x65, 0x78, 0x74, 0x72, 0x61, 0x4c, 0x65,
	0x76, 0x65, 0x6c, 0x12, 0x1f, 0x0a, 0x0b, 0x74, 0x61, 0x6c, 0x65, 0x6e, 0x74, 0x5f, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x74, 0x61, 0x6c, 0x65, 0x6e, 0x74,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x74, 0x61, 0x6c, 0x65, 0x6e, 0x74, 0x5f, 0x69,
	0x6e, 0x64, 0x65, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x74, 0x61, 0x6c, 0x65,
	0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ProudSkillExtraLevelNotify_proto_rawDescOnce sync.Once
	file_ProudSkillExtraLevelNotify_proto_rawDescData = file_ProudSkillExtraLevelNotify_proto_rawDesc
)

func file_ProudSkillExtraLevelNotify_proto_rawDescGZIP() []byte {
	file_ProudSkillExtraLevelNotify_proto_rawDescOnce.Do(func() {
		file_ProudSkillExtraLevelNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_ProudSkillExtraLevelNotify_proto_rawDescData)
	})
	return file_ProudSkillExtraLevelNotify_proto_rawDescData
}

var file_ProudSkillExtraLevelNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ProudSkillExtraLevelNotify_proto_goTypes = []interface{}{
	(*ProudSkillExtraLevelNotify)(nil), // 0: ProudSkillExtraLevelNotify
}
var file_ProudSkillExtraLevelNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ProudSkillExtraLevelNotify_proto_init() }
func file_ProudSkillExtraLevelNotify_proto_init() {
	if File_ProudSkillExtraLevelNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ProudSkillExtraLevelNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProudSkillExtraLevelNotify); i {
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
			RawDescriptor: file_ProudSkillExtraLevelNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ProudSkillExtraLevelNotify_proto_goTypes,
		DependencyIndexes: file_ProudSkillExtraLevelNotify_proto_depIdxs,
		MessageInfos:      file_ProudSkillExtraLevelNotify_proto_msgTypes,
	}.Build()
	File_ProudSkillExtraLevelNotify_proto = out.File
	file_ProudSkillExtraLevelNotify_proto_rawDesc = nil
	file_ProudSkillExtraLevelNotify_proto_goTypes = nil
	file_ProudSkillExtraLevelNotify_proto_depIdxs = nil
}
