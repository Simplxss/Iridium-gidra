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
// source: ChannellerSlabLoopDungeonChallengeInfoNotify.proto

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

// CmdId: 9955
// Obf: OBHDPBPCFMN
type ChannellerSlabLoopDungeonChallengeInfoNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SchemeBuffIdList []uint32 `protobuf:"varint,15,rep,packed,name=scheme_buff_id_list,json=schemeBuffIdList,proto3" json:"scheme_buff_id_list,omitempty"`
	ConditionIdList  []uint32 `protobuf:"varint,7,rep,packed,name=condition_id_list,json=conditionIdList,proto3" json:"condition_id_list,omitempty"`
	DungeonIndex     uint32   `protobuf:"varint,5,opt,name=dungeon_index,json=dungeonIndex,proto3" json:"dungeon_index,omitempty"`
	ChallengeScore   uint32   `protobuf:"varint,10,opt,name=challenge_score,json=challengeScore,proto3" json:"challenge_score,omitempty"`
	DifficultyId     uint32   `protobuf:"varint,11,opt,name=difficulty_id,json=difficultyId,proto3" json:"difficulty_id,omitempty"`
}

func (x *ChannellerSlabLoopDungeonChallengeInfoNotify) Reset() {
	*x = ChannellerSlabLoopDungeonChallengeInfoNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChannellerSlabLoopDungeonChallengeInfoNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChannellerSlabLoopDungeonChallengeInfoNotify) ProtoMessage() {}

func (x *ChannellerSlabLoopDungeonChallengeInfoNotify) ProtoReflect() protoreflect.Message {
	mi := &file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChannellerSlabLoopDungeonChallengeInfoNotify.ProtoReflect.Descriptor instead.
func (*ChannellerSlabLoopDungeonChallengeInfoNotify) Descriptor() ([]byte, []int) {
	return file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDescGZIP(), []int{0}
}

func (x *ChannellerSlabLoopDungeonChallengeInfoNotify) GetSchemeBuffIdList() []uint32 {
	if x != nil {
		return x.SchemeBuffIdList
	}
	return nil
}

func (x *ChannellerSlabLoopDungeonChallengeInfoNotify) GetConditionIdList() []uint32 {
	if x != nil {
		return x.ConditionIdList
	}
	return nil
}

func (x *ChannellerSlabLoopDungeonChallengeInfoNotify) GetDungeonIndex() uint32 {
	if x != nil {
		return x.DungeonIndex
	}
	return 0
}

func (x *ChannellerSlabLoopDungeonChallengeInfoNotify) GetChallengeScore() uint32 {
	if x != nil {
		return x.ChallengeScore
	}
	return 0
}

func (x *ChannellerSlabLoopDungeonChallengeInfoNotify) GetDifficultyId() uint32 {
	if x != nil {
		return x.DifficultyId
	}
	return 0
}

var File_ChannellerSlabLoopDungeonChallengeInfoNotify_proto protoreflect.FileDescriptor

var file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDesc = []byte{
	0x0a, 0x32, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x62,
	0x4c, 0x6f, 0x6f, 0x70, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43, 0x68, 0x61, 0x6c, 0x6c,
	0x65, 0x6e, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xfc, 0x01, 0x0a, 0x2c, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c,
	0x6c, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x62, 0x4c, 0x6f, 0x6f, 0x70, 0x44, 0x75, 0x6e, 0x67, 0x65,
	0x6f, 0x6e, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x4e,
	0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x2d, 0x0a, 0x13, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x65, 0x5f,
	0x62, 0x75, 0x66, 0x66, 0x5f, 0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0f, 0x20, 0x03,
	0x28, 0x0d, 0x52, 0x10, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x65, 0x42, 0x75, 0x66, 0x66, 0x49, 0x64,
	0x4c, 0x69, 0x73, 0x74, 0x12, 0x2a, 0x0a, 0x11, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0d, 0x52,
	0x0f, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x23, 0x0a, 0x0d, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x5f, 0x69, 0x6e, 0x64, 0x65,
	0x78, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e,
	0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x27, 0x0a, 0x0f, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e,
	0x67, 0x65, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e,
	0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x12, 0x23,
	0x0a, 0x0d, 0x64, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75, 0x6c, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18,
	0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x64, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75, 0x6c, 0x74,
	0x79, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDescOnce sync.Once
	file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDescData = file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDesc
)

func file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDescGZIP() []byte {
	file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDescOnce.Do(func() {
		file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDescData)
	})
	return file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDescData
}

var file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_goTypes = []interface{}{
	(*ChannellerSlabLoopDungeonChallengeInfoNotify)(nil), // 0: ChannellerSlabLoopDungeonChallengeInfoNotify
}
var file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_init() }
func file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_init() {
	if File_ChannellerSlabLoopDungeonChallengeInfoNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChannellerSlabLoopDungeonChallengeInfoNotify); i {
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
			RawDescriptor: file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_goTypes,
		DependencyIndexes: file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_depIdxs,
		MessageInfos:      file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_msgTypes,
	}.Build()
	File_ChannellerSlabLoopDungeonChallengeInfoNotify_proto = out.File
	file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_rawDesc = nil
	file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_goTypes = nil
	file_ChannellerSlabLoopDungeonChallengeInfoNotify_proto_depIdxs = nil
}
