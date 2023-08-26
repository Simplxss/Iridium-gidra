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
// source: OtherCustomDungeonBrief.proto

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

// Obf: HKCCDHPNEEE
type OtherCustomDungeonBrief struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Setting            *CustomDungeonSetting  `protobuf:"bytes,7,opt,name=setting,proto3" json:"setting,omitempty"`
	TagList            []uint32               `protobuf:"varint,13,rep,packed,name=tag_list,json=tagList,proto3" json:"tag_list,omitempty"`
	DungeonGuid        uint64                 `protobuf:"varint,6,opt,name=dungeon_guid,json=dungeonGuid,proto3" json:"dungeon_guid,omitempty"`
	IsAdventureDungeon bool                   `protobuf:"varint,2,opt,name=is_adventure_dungeon,json=isAdventureDungeon,proto3" json:"is_adventure_dungeon,omitempty"`
	DungeonId          uint32                 `protobuf:"varint,4,opt,name=dungeon_id,json=dungeonId,proto3" json:"dungeon_id,omitempty"`
	IsPsnPlatform      bool                   `protobuf:"varint,10,opt,name=is_psn_platform,json=isPsnPlatform,proto3" json:"is_psn_platform,omitempty"`
	BattleMinCostTime  uint32                 `protobuf:"varint,3,opt,name=battle_min_cost_time,json=battleMinCostTime,proto3" json:"battle_min_cost_time,omitempty"`
	CreatorDetail      *SocialDetail          `protobuf:"bytes,9,opt,name=creator_detail,json=creatorDetail,proto3" json:"creator_detail,omitempty"`
	Abstract           *CustomDungeonAbstract `protobuf:"bytes,8,opt,name=abstract,proto3" json:"abstract,omitempty"`
	Social             *CustomDungeonSocial   `protobuf:"bytes,14,opt,name=social,proto3" json:"social,omitempty"`
	IsStored           bool                   `protobuf:"varint,5,opt,name=is_stored,json=isStored,proto3" json:"is_stored,omitempty"`
}

func (x *OtherCustomDungeonBrief) Reset() {
	*x = OtherCustomDungeonBrief{}
	if protoimpl.UnsafeEnabled {
		mi := &file_OtherCustomDungeonBrief_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OtherCustomDungeonBrief) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OtherCustomDungeonBrief) ProtoMessage() {}

func (x *OtherCustomDungeonBrief) ProtoReflect() protoreflect.Message {
	mi := &file_OtherCustomDungeonBrief_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OtherCustomDungeonBrief.ProtoReflect.Descriptor instead.
func (*OtherCustomDungeonBrief) Descriptor() ([]byte, []int) {
	return file_OtherCustomDungeonBrief_proto_rawDescGZIP(), []int{0}
}

func (x *OtherCustomDungeonBrief) GetSetting() *CustomDungeonSetting {
	if x != nil {
		return x.Setting
	}
	return nil
}

func (x *OtherCustomDungeonBrief) GetTagList() []uint32 {
	if x != nil {
		return x.TagList
	}
	return nil
}

func (x *OtherCustomDungeonBrief) GetDungeonGuid() uint64 {
	if x != nil {
		return x.DungeonGuid
	}
	return 0
}

func (x *OtherCustomDungeonBrief) GetIsAdventureDungeon() bool {
	if x != nil {
		return x.IsAdventureDungeon
	}
	return false
}

func (x *OtherCustomDungeonBrief) GetDungeonId() uint32 {
	if x != nil {
		return x.DungeonId
	}
	return 0
}

func (x *OtherCustomDungeonBrief) GetIsPsnPlatform() bool {
	if x != nil {
		return x.IsPsnPlatform
	}
	return false
}

func (x *OtherCustomDungeonBrief) GetBattleMinCostTime() uint32 {
	if x != nil {
		return x.BattleMinCostTime
	}
	return 0
}

func (x *OtherCustomDungeonBrief) GetCreatorDetail() *SocialDetail {
	if x != nil {
		return x.CreatorDetail
	}
	return nil
}

func (x *OtherCustomDungeonBrief) GetAbstract() *CustomDungeonAbstract {
	if x != nil {
		return x.Abstract
	}
	return nil
}

func (x *OtherCustomDungeonBrief) GetSocial() *CustomDungeonSocial {
	if x != nil {
		return x.Social
	}
	return nil
}

func (x *OtherCustomDungeonBrief) GetIsStored() bool {
	if x != nil {
		return x.IsStored
	}
	return false
}

var File_OtherCustomDungeonBrief_proto protoreflect.FileDescriptor

var file_OtherCustomDungeonBrief_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x4f, 0x74, 0x68, 0x65, 0x72, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e,
	0x67, 0x65, 0x6f, 0x6e, 0x42, 0x72, 0x69, 0x65, 0x66, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1a, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x53, 0x65,
	0x74, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x53, 0x6f, 0x63,
	0x69, 0x61, 0x6c, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1b, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x41, 0x62,
	0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x43, 0x75,
	0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x53, 0x6f, 0x63, 0x69, 0x61,
	0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe7, 0x03, 0x0a, 0x17, 0x4f, 0x74, 0x68, 0x65,
	0x72, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x42, 0x72,
	0x69, 0x65, 0x66, 0x12, 0x2f, 0x0a, 0x07, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e,
	0x67, 0x65, 0x6f, 0x6e, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x52, 0x07, 0x73, 0x65, 0x74,
	0x74, 0x69, 0x6e, 0x67, 0x12, 0x19, 0x0a, 0x08, 0x74, 0x61, 0x67, 0x5f, 0x6c, 0x69, 0x73, 0x74,
	0x18, 0x0d, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x07, 0x74, 0x61, 0x67, 0x4c, 0x69, 0x73, 0x74, 0x12,
	0x21, 0x0a, 0x0c, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x5f, 0x67, 0x75, 0x69, 0x64, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x47, 0x75,
	0x69, 0x64, 0x12, 0x30, 0x0a, 0x14, 0x69, 0x73, 0x5f, 0x61, 0x64, 0x76, 0x65, 0x6e, 0x74, 0x75,
	0x72, 0x65, 0x5f, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x12, 0x69, 0x73, 0x41, 0x64, 0x76, 0x65, 0x6e, 0x74, 0x75, 0x72, 0x65, 0x44, 0x75, 0x6e,
	0x67, 0x65, 0x6f, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x5f,
	0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f,
	0x6e, 0x49, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x73, 0x5f, 0x70, 0x73, 0x6e, 0x5f, 0x70, 0x6c,
	0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x69, 0x73,
	0x50, 0x73, 0x6e, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x12, 0x2f, 0x0a, 0x14, 0x62,
	0x61, 0x74, 0x74, 0x6c, 0x65, 0x5f, 0x6d, 0x69, 0x6e, 0x5f, 0x63, 0x6f, 0x73, 0x74, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x11, 0x62, 0x61, 0x74, 0x74, 0x6c,
	0x65, 0x4d, 0x69, 0x6e, 0x43, 0x6f, 0x73, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x34, 0x0a, 0x0e,
	0x63, 0x72, 0x65, 0x61, 0x74, 0x6f, 0x72, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x18, 0x09,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x53, 0x6f, 0x63, 0x69, 0x61, 0x6c, 0x44, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x52, 0x0d, 0x63, 0x72, 0x65, 0x61, 0x74, 0x6f, 0x72, 0x44, 0x65, 0x74, 0x61,
	0x69, 0x6c, 0x12, 0x32, 0x0a, 0x08, 0x61, 0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44, 0x75, 0x6e,
	0x67, 0x65, 0x6f, 0x6e, 0x41, 0x62, 0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x52, 0x08, 0x61, 0x62,
	0x73, 0x74, 0x72, 0x61, 0x63, 0x74, 0x12, 0x2c, 0x0a, 0x06, 0x73, 0x6f, 0x63, 0x69, 0x61, 0x6c,
	0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x44,
	0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x53, 0x6f, 0x63, 0x69, 0x61, 0x6c, 0x52, 0x06, 0x73, 0x6f,
	0x63, 0x69, 0x61, 0x6c, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x73, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x65,
	0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x69, 0x73, 0x53, 0x74, 0x6f, 0x72, 0x65,
	0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_OtherCustomDungeonBrief_proto_rawDescOnce sync.Once
	file_OtherCustomDungeonBrief_proto_rawDescData = file_OtherCustomDungeonBrief_proto_rawDesc
)

func file_OtherCustomDungeonBrief_proto_rawDescGZIP() []byte {
	file_OtherCustomDungeonBrief_proto_rawDescOnce.Do(func() {
		file_OtherCustomDungeonBrief_proto_rawDescData = protoimpl.X.CompressGZIP(file_OtherCustomDungeonBrief_proto_rawDescData)
	})
	return file_OtherCustomDungeonBrief_proto_rawDescData
}

var file_OtherCustomDungeonBrief_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_OtherCustomDungeonBrief_proto_goTypes = []interface{}{
	(*OtherCustomDungeonBrief)(nil), // 0: OtherCustomDungeonBrief
	(*CustomDungeonSetting)(nil),    // 1: CustomDungeonSetting
	(*SocialDetail)(nil),            // 2: SocialDetail
	(*CustomDungeonAbstract)(nil),   // 3: CustomDungeonAbstract
	(*CustomDungeonSocial)(nil),     // 4: CustomDungeonSocial
}
var file_OtherCustomDungeonBrief_proto_depIdxs = []int32{
	1, // 0: OtherCustomDungeonBrief.setting:type_name -> CustomDungeonSetting
	2, // 1: OtherCustomDungeonBrief.creator_detail:type_name -> SocialDetail
	3, // 2: OtherCustomDungeonBrief.abstract:type_name -> CustomDungeonAbstract
	4, // 3: OtherCustomDungeonBrief.social:type_name -> CustomDungeonSocial
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_OtherCustomDungeonBrief_proto_init() }
func file_OtherCustomDungeonBrief_proto_init() {
	if File_OtherCustomDungeonBrief_proto != nil {
		return
	}
	file_CustomDungeonSetting_proto_init()
	file_SocialDetail_proto_init()
	file_CustomDungeonAbstract_proto_init()
	file_CustomDungeonSocial_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_OtherCustomDungeonBrief_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OtherCustomDungeonBrief); i {
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
			RawDescriptor: file_OtherCustomDungeonBrief_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_OtherCustomDungeonBrief_proto_goTypes,
		DependencyIndexes: file_OtherCustomDungeonBrief_proto_depIdxs,
		MessageInfos:      file_OtherCustomDungeonBrief_proto_msgTypes,
	}.Build()
	File_OtherCustomDungeonBrief_proto = out.File
	file_OtherCustomDungeonBrief_proto_rawDesc = nil
	file_OtherCustomDungeonBrief_proto_goTypes = nil
	file_OtherCustomDungeonBrief_proto_depIdxs = nil
}
