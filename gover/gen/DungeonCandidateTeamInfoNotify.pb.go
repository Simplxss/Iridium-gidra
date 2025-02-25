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
// source: DungeonCandidateTeamInfoNotify.proto

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

// CmdId: 6824
// Obf: HLAOLGIKKIH
type DungeonCandidateTeamInfoNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DungeonId      uint32                        `protobuf:"varint,10,opt,name=dungeon_id,json=dungeonId,proto3" json:"dungeon_id,omitempty"`
	AvatarList     []*DungeonCandidateTeamAvatar `protobuf:"bytes,12,rep,name=avatar_list,json=avatarList,proto3" json:"avatar_list,omitempty"`
	MatchType      uint32                        `protobuf:"varint,15,opt,name=match_type,json=matchType,proto3" json:"match_type,omitempty"`
	KDNCFBHJCPJ    map[uint32]CBGEJFGFNNO        `protobuf:"bytes,3,rep,name=KDNCFBHJCPJ,proto3" json:"KDNCFBHJCPJ,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3,enum=CBGEJFGFNNO"`
	ReadyPlayerUid []uint32                      `protobuf:"varint,7,rep,packed,name=ready_player_uid,json=readyPlayerUid,proto3" json:"ready_player_uid,omitempty"`
	UgcTeamList    *UgcTeamInfo                  `protobuf:"bytes,1882,opt,name=ugc_team_list,json=ugcTeamList,proto3,oneof" json:"ugc_team_list,omitempty"`
}

func (x *DungeonCandidateTeamInfoNotify) Reset() {
	*x = DungeonCandidateTeamInfoNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_DungeonCandidateTeamInfoNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DungeonCandidateTeamInfoNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DungeonCandidateTeamInfoNotify) ProtoMessage() {}

func (x *DungeonCandidateTeamInfoNotify) ProtoReflect() protoreflect.Message {
	mi := &file_DungeonCandidateTeamInfoNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DungeonCandidateTeamInfoNotify.ProtoReflect.Descriptor instead.
func (*DungeonCandidateTeamInfoNotify) Descriptor() ([]byte, []int) {
	return file_DungeonCandidateTeamInfoNotify_proto_rawDescGZIP(), []int{0}
}

func (x *DungeonCandidateTeamInfoNotify) GetDungeonId() uint32 {
	if x != nil {
		return x.DungeonId
	}
	return 0
}

func (x *DungeonCandidateTeamInfoNotify) GetAvatarList() []*DungeonCandidateTeamAvatar {
	if x != nil {
		return x.AvatarList
	}
	return nil
}

func (x *DungeonCandidateTeamInfoNotify) GetMatchType() uint32 {
	if x != nil {
		return x.MatchType
	}
	return 0
}

func (x *DungeonCandidateTeamInfoNotify) GetKDNCFBHJCPJ() map[uint32]CBGEJFGFNNO {
	if x != nil {
		return x.KDNCFBHJCPJ
	}
	return nil
}

func (x *DungeonCandidateTeamInfoNotify) GetReadyPlayerUid() []uint32 {
	if x != nil {
		return x.ReadyPlayerUid
	}
	return nil
}

func (x *DungeonCandidateTeamInfoNotify) GetUgcTeamList() *UgcTeamInfo {
	if x != nil {
		return x.UgcTeamList
	}
	return nil
}

var File_DungeonCandidateTeamInfoNotify_proto protoreflect.FileDescriptor

var file_DungeonCandidateTeamInfoNotify_proto_rawDesc = []byte{
	0x0a, 0x24, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43,
	0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x41, 0x76, 0x61, 0x74,
	0x61, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x43, 0x42, 0x47, 0x45, 0x4a, 0x46,
	0x47, 0x46, 0x4e, 0x4e, 0x4f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x55, 0x67, 0x63,
	0x54, 0x65, 0x61, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb2,
	0x03, 0x0a, 0x1e, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43, 0x61, 0x6e, 0x64, 0x69, 0x64,
	0x61, 0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x4e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x12, 0x1d, 0x0a, 0x0a, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x49, 0x64,
	0x12, 0x3c, 0x0a, 0x0b, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18,
	0x0c, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43,
	0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x41, 0x76, 0x61, 0x74,
	0x61, 0x72, 0x52, 0x0a, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1d,
	0x0a, 0x0a, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x0f, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x09, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x54, 0x79, 0x70, 0x65, 0x12, 0x52, 0x0a,
	0x0b, 0x4b, 0x44, 0x4e, 0x43, 0x46, 0x42, 0x48, 0x4a, 0x43, 0x50, 0x4a, 0x18, 0x03, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x30, 0x2e, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43, 0x61, 0x6e, 0x64,
	0x69, 0x64, 0x61, 0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x49, 0x6e, 0x66, 0x6f, 0x4e, 0x6f, 0x74,
	0x69, 0x66, 0x79, 0x2e, 0x4b, 0x44, 0x4e, 0x43, 0x46, 0x42, 0x48, 0x4a, 0x43, 0x50, 0x4a, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x4b, 0x44, 0x4e, 0x43, 0x46, 0x42, 0x48, 0x4a, 0x43, 0x50,
	0x4a, 0x12, 0x28, 0x0a, 0x10, 0x72, 0x65, 0x61, 0x64, 0x79, 0x5f, 0x70, 0x6c, 0x61, 0x79, 0x65,
	0x72, 0x5f, 0x75, 0x69, 0x64, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0e, 0x72, 0x65, 0x61,
	0x64, 0x79, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x55, 0x69, 0x64, 0x12, 0x36, 0x0a, 0x0d, 0x75,
	0x67, 0x63, 0x5f, 0x74, 0x65, 0x61, 0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0xda, 0x0e, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x55, 0x67, 0x63, 0x54, 0x65, 0x61, 0x6d, 0x49, 0x6e, 0x66,
	0x6f, 0x48, 0x00, 0x52, 0x0b, 0x75, 0x67, 0x63, 0x54, 0x65, 0x61, 0x6d, 0x4c, 0x69, 0x73, 0x74,
	0x88, 0x01, 0x01, 0x1a, 0x4c, 0x0a, 0x10, 0x4b, 0x44, 0x4e, 0x43, 0x46, 0x42, 0x48, 0x4a, 0x43,
	0x50, 0x4a, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x22, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0c, 0x2e, 0x43, 0x42, 0x47, 0x45, 0x4a,
	0x46, 0x47, 0x46, 0x4e, 0x4e, 0x4f, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x42, 0x10, 0x0a, 0x0e, 0x5f, 0x75, 0x67, 0x63, 0x5f, 0x74, 0x65, 0x61, 0x6d, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_DungeonCandidateTeamInfoNotify_proto_rawDescOnce sync.Once
	file_DungeonCandidateTeamInfoNotify_proto_rawDescData = file_DungeonCandidateTeamInfoNotify_proto_rawDesc
)

func file_DungeonCandidateTeamInfoNotify_proto_rawDescGZIP() []byte {
	file_DungeonCandidateTeamInfoNotify_proto_rawDescOnce.Do(func() {
		file_DungeonCandidateTeamInfoNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_DungeonCandidateTeamInfoNotify_proto_rawDescData)
	})
	return file_DungeonCandidateTeamInfoNotify_proto_rawDescData
}

var file_DungeonCandidateTeamInfoNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_DungeonCandidateTeamInfoNotify_proto_goTypes = []interface{}{
	(*DungeonCandidateTeamInfoNotify)(nil), // 0: DungeonCandidateTeamInfoNotify
	nil,                                    // 1: DungeonCandidateTeamInfoNotify.KDNCFBHJCPJEntry
	(*DungeonCandidateTeamAvatar)(nil),     // 2: DungeonCandidateTeamAvatar
	(*UgcTeamInfo)(nil),                    // 3: UgcTeamInfo
	(CBGEJFGFNNO)(0),                       // 4: CBGEJFGFNNO
}
var file_DungeonCandidateTeamInfoNotify_proto_depIdxs = []int32{
	2, // 0: DungeonCandidateTeamInfoNotify.avatar_list:type_name -> DungeonCandidateTeamAvatar
	1, // 1: DungeonCandidateTeamInfoNotify.KDNCFBHJCPJ:type_name -> DungeonCandidateTeamInfoNotify.KDNCFBHJCPJEntry
	3, // 2: DungeonCandidateTeamInfoNotify.ugc_team_list:type_name -> UgcTeamInfo
	4, // 3: DungeonCandidateTeamInfoNotify.KDNCFBHJCPJEntry.value:type_name -> CBGEJFGFNNO
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_DungeonCandidateTeamInfoNotify_proto_init() }
func file_DungeonCandidateTeamInfoNotify_proto_init() {
	if File_DungeonCandidateTeamInfoNotify_proto != nil {
		return
	}
	file_DungeonCandidateTeamAvatar_proto_init()
	file_CBGEJFGFNNO_proto_init()
	file_UgcTeamInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_DungeonCandidateTeamInfoNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DungeonCandidateTeamInfoNotify); i {
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
	file_DungeonCandidateTeamInfoNotify_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_DungeonCandidateTeamInfoNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DungeonCandidateTeamInfoNotify_proto_goTypes,
		DependencyIndexes: file_DungeonCandidateTeamInfoNotify_proto_depIdxs,
		MessageInfos:      file_DungeonCandidateTeamInfoNotify_proto_msgTypes,
	}.Build()
	File_DungeonCandidateTeamInfoNotify_proto = out.File
	file_DungeonCandidateTeamInfoNotify_proto_rawDesc = nil
	file_DungeonCandidateTeamInfoNotify_proto_goTypes = nil
	file_DungeonCandidateTeamInfoNotify_proto_depIdxs = nil
}
