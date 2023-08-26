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
// source: ChannellerSlabLoopDungeonStageInfo.proto

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

// Obf: OIMGPMJMHJJ
type ChannellerSlabLoopDungeonStageInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsOpen               bool                             `protobuf:"varint,2,opt,name=is_open,json=isOpen,proto3" json:"is_open,omitempty"`
	DungeonInfoList      []*ChannellerSlabLoopDungeonInfo `protobuf:"bytes,14,rep,name=dungeon_info_list,json=dungeonInfoList,proto3" json:"dungeon_info_list,omitempty"`
	LastDifficultyId     uint32                           `protobuf:"varint,12,opt,name=last_difficulty_id,json=lastDifficultyId,proto3" json:"last_difficulty_id,omitempty"`
	OpenTime             uint32                           `protobuf:"varint,13,opt,name=open_time,json=openTime,proto3" json:"open_time,omitempty"`
	TakenRewardIndexList []uint32                         `protobuf:"varint,5,rep,packed,name=taken_reward_index_list,json=takenRewardIndexList,proto3" json:"taken_reward_index_list,omitempty"`
}

func (x *ChannellerSlabLoopDungeonStageInfo) Reset() {
	*x = ChannellerSlabLoopDungeonStageInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ChannellerSlabLoopDungeonStageInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChannellerSlabLoopDungeonStageInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChannellerSlabLoopDungeonStageInfo) ProtoMessage() {}

func (x *ChannellerSlabLoopDungeonStageInfo) ProtoReflect() protoreflect.Message {
	mi := &file_ChannellerSlabLoopDungeonStageInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChannellerSlabLoopDungeonStageInfo.ProtoReflect.Descriptor instead.
func (*ChannellerSlabLoopDungeonStageInfo) Descriptor() ([]byte, []int) {
	return file_ChannellerSlabLoopDungeonStageInfo_proto_rawDescGZIP(), []int{0}
}

func (x *ChannellerSlabLoopDungeonStageInfo) GetIsOpen() bool {
	if x != nil {
		return x.IsOpen
	}
	return false
}

func (x *ChannellerSlabLoopDungeonStageInfo) GetDungeonInfoList() []*ChannellerSlabLoopDungeonInfo {
	if x != nil {
		return x.DungeonInfoList
	}
	return nil
}

func (x *ChannellerSlabLoopDungeonStageInfo) GetLastDifficultyId() uint32 {
	if x != nil {
		return x.LastDifficultyId
	}
	return 0
}

func (x *ChannellerSlabLoopDungeonStageInfo) GetOpenTime() uint32 {
	if x != nil {
		return x.OpenTime
	}
	return 0
}

func (x *ChannellerSlabLoopDungeonStageInfo) GetTakenRewardIndexList() []uint32 {
	if x != nil {
		return x.TakenRewardIndexList
	}
	return nil
}

var File_ChannellerSlabLoopDungeonStageInfo_proto protoreflect.FileDescriptor

var file_ChannellerSlabLoopDungeonStageInfo_proto_rawDesc = []byte{
	0x0a, 0x28, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x62,
	0x4c, 0x6f, 0x6f, 0x70, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x67, 0x65,
	0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x43, 0x68, 0x61, 0x6e,
	0x6e, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x62, 0x4c, 0x6f, 0x6f, 0x70, 0x44, 0x75,
	0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x8b, 0x02, 0x0a, 0x22, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x53, 0x6c,
	0x61, 0x62, 0x4c, 0x6f, 0x6f, 0x70, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x53, 0x74, 0x61,
	0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x73, 0x5f, 0x6f, 0x70, 0x65,
	0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x69, 0x73, 0x4f, 0x70, 0x65, 0x6e, 0x12,
	0x4a, 0x0a, 0x11, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f,
	0x6c, 0x69, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x43, 0x68, 0x61,
	0x6e, 0x6e, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x62, 0x4c, 0x6f, 0x6f, 0x70, 0x44,
	0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0f, 0x64, 0x75, 0x6e, 0x67,
	0x65, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x2c, 0x0a, 0x12, 0x6c,
	0x61, 0x73, 0x74, 0x5f, 0x64, 0x69, 0x66, 0x66, 0x69, 0x63, 0x75, 0x6c, 0x74, 0x79, 0x5f, 0x69,
	0x64, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x6c, 0x61, 0x73, 0x74, 0x44, 0x69, 0x66,
	0x66, 0x69, 0x63, 0x75, 0x6c, 0x74, 0x79, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x6f, 0x70, 0x65,
	0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x6f, 0x70,
	0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x35, 0x0a, 0x17, 0x74, 0x61, 0x6b, 0x65, 0x6e, 0x5f,
	0x72, 0x65, 0x77, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x14, 0x74, 0x61, 0x6b, 0x65, 0x6e, 0x52, 0x65,
	0x77, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a,
	0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ChannellerSlabLoopDungeonStageInfo_proto_rawDescOnce sync.Once
	file_ChannellerSlabLoopDungeonStageInfo_proto_rawDescData = file_ChannellerSlabLoopDungeonStageInfo_proto_rawDesc
)

func file_ChannellerSlabLoopDungeonStageInfo_proto_rawDescGZIP() []byte {
	file_ChannellerSlabLoopDungeonStageInfo_proto_rawDescOnce.Do(func() {
		file_ChannellerSlabLoopDungeonStageInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_ChannellerSlabLoopDungeonStageInfo_proto_rawDescData)
	})
	return file_ChannellerSlabLoopDungeonStageInfo_proto_rawDescData
}

var file_ChannellerSlabLoopDungeonStageInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ChannellerSlabLoopDungeonStageInfo_proto_goTypes = []interface{}{
	(*ChannellerSlabLoopDungeonStageInfo)(nil), // 0: ChannellerSlabLoopDungeonStageInfo
	(*ChannellerSlabLoopDungeonInfo)(nil),      // 1: ChannellerSlabLoopDungeonInfo
}
var file_ChannellerSlabLoopDungeonStageInfo_proto_depIdxs = []int32{
	1, // 0: ChannellerSlabLoopDungeonStageInfo.dungeon_info_list:type_name -> ChannellerSlabLoopDungeonInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_ChannellerSlabLoopDungeonStageInfo_proto_init() }
func file_ChannellerSlabLoopDungeonStageInfo_proto_init() {
	if File_ChannellerSlabLoopDungeonStageInfo_proto != nil {
		return
	}
	file_ChannellerSlabLoopDungeonInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ChannellerSlabLoopDungeonStageInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChannellerSlabLoopDungeonStageInfo); i {
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
			RawDescriptor: file_ChannellerSlabLoopDungeonStageInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ChannellerSlabLoopDungeonStageInfo_proto_goTypes,
		DependencyIndexes: file_ChannellerSlabLoopDungeonStageInfo_proto_depIdxs,
		MessageInfos:      file_ChannellerSlabLoopDungeonStageInfo_proto_msgTypes,
	}.Build()
	File_ChannellerSlabLoopDungeonStageInfo_proto = out.File
	file_ChannellerSlabLoopDungeonStageInfo_proto_rawDesc = nil
	file_ChannellerSlabLoopDungeonStageInfo_proto_goTypes = nil
	file_ChannellerSlabLoopDungeonStageInfo_proto_depIdxs = nil
}
