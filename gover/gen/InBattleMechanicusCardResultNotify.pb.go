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
// source: InBattleMechanicusCardResultNotify.proto

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

type InBattleMechanicusCardResultNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GroupId                uint32                        `protobuf:"varint,10,opt,name=group_id,json=groupId,proto3" json:"group_id,omitempty"`
	CardList               []*InBattleMechanicusCardInfo `protobuf:"bytes,8,rep,name=card_list,json=cardList,proto3" json:"card_list,omitempty"`
	PlayIndex              uint32                        `protobuf:"varint,14,opt,name=play_index,json=playIndex,proto3" json:"play_index,omitempty"`
	PlayerConfirmedCardMap map[uint32]uint32             `protobuf:"bytes,9,rep,name=player_confirmed_card_map,json=playerConfirmedCardMap,proto3" json:"player_confirmed_card_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	WaitBeginTimeUs        uint64                        `protobuf:"varint,2,opt,name=wait_begin_time_us,json=waitBeginTimeUs,proto3" json:"wait_begin_time_us,omitempty"`
	WaitSeconds            uint32                        `protobuf:"varint,5,opt,name=wait_seconds,json=waitSeconds,proto3" json:"wait_seconds,omitempty"`
}

func (x *InBattleMechanicusCardResultNotify) Reset() {
	*x = InBattleMechanicusCardResultNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_InBattleMechanicusCardResultNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InBattleMechanicusCardResultNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InBattleMechanicusCardResultNotify) ProtoMessage() {}

func (x *InBattleMechanicusCardResultNotify) ProtoReflect() protoreflect.Message {
	mi := &file_InBattleMechanicusCardResultNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InBattleMechanicusCardResultNotify.ProtoReflect.Descriptor instead.
func (*InBattleMechanicusCardResultNotify) Descriptor() ([]byte, []int) {
	return file_InBattleMechanicusCardResultNotify_proto_rawDescGZIP(), []int{0}
}

func (x *InBattleMechanicusCardResultNotify) GetGroupId() uint32 {
	if x != nil {
		return x.GroupId
	}
	return 0
}

func (x *InBattleMechanicusCardResultNotify) GetCardList() []*InBattleMechanicusCardInfo {
	if x != nil {
		return x.CardList
	}
	return nil
}

func (x *InBattleMechanicusCardResultNotify) GetPlayIndex() uint32 {
	if x != nil {
		return x.PlayIndex
	}
	return 0
}

func (x *InBattleMechanicusCardResultNotify) GetPlayerConfirmedCardMap() map[uint32]uint32 {
	if x != nil {
		return x.PlayerConfirmedCardMap
	}
	return nil
}

func (x *InBattleMechanicusCardResultNotify) GetWaitBeginTimeUs() uint64 {
	if x != nil {
		return x.WaitBeginTimeUs
	}
	return 0
}

func (x *InBattleMechanicusCardResultNotify) GetWaitSeconds() uint32 {
	if x != nil {
		return x.WaitSeconds
	}
	return 0
}

var File_InBattleMechanicusCardResultNotify_proto protoreflect.FileDescriptor

var file_InBattleMechanicusCardResultNotify_proto_rawDesc = []byte{
	0x0a, 0x28, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e,
	0x69, 0x63, 0x75, 0x73, 0x43, 0x61, 0x72, 0x64, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x49, 0x6e, 0x42, 0x61,
	0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x63, 0x75, 0x73, 0x43, 0x61,
	0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xaf, 0x03, 0x0a,
	0x22, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69,
	0x63, 0x75, 0x73, 0x43, 0x61, 0x72, 0x64, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x4e, 0x6f, 0x74,
	0x69, 0x66, 0x79, 0x12, 0x19, 0x0a, 0x08, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x69, 0x64, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x64, 0x12, 0x38,
	0x0a, 0x09, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x08, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x1b, 0x2e, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68,
	0x61, 0x6e, 0x69, 0x63, 0x75, 0x73, 0x43, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x08,
	0x63, 0x61, 0x72, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x6c, 0x61, 0x79,
	0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x6c,
	0x61, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x7a, 0x0a, 0x19, 0x70, 0x6c, 0x61, 0x79, 0x65,
	0x72, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x65, 0x64, 0x5f, 0x63, 0x61, 0x72, 0x64,
	0x5f, 0x6d, 0x61, 0x70, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x3f, 0x2e, 0x49, 0x6e, 0x42,
	0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x63, 0x75, 0x73, 0x43,
	0x61, 0x72, 0x64, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e,
	0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x65, 0x64, 0x43,
	0x61, 0x72, 0x64, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x16, 0x70, 0x6c, 0x61,
	0x79, 0x65, 0x72, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x72, 0x6d, 0x65, 0x64, 0x43, 0x61, 0x72, 0x64,
	0x4d, 0x61, 0x70, 0x12, 0x2b, 0x0a, 0x12, 0x77, 0x61, 0x69, 0x74, 0x5f, 0x62, 0x65, 0x67, 0x69,
	0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x75, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x0f, 0x77, 0x61, 0x69, 0x74, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x55, 0x73,
	0x12, 0x21, 0x0a, 0x0c, 0x77, 0x61, 0x69, 0x74, 0x5f, 0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x73,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x77, 0x61, 0x69, 0x74, 0x53, 0x65, 0x63, 0x6f,
	0x6e, 0x64, 0x73, 0x1a, 0x49, 0x0a, 0x1b, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x72, 0x6d, 0x65, 0x64, 0x43, 0x61, 0x72, 0x64, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x06,
	0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_InBattleMechanicusCardResultNotify_proto_rawDescOnce sync.Once
	file_InBattleMechanicusCardResultNotify_proto_rawDescData = file_InBattleMechanicusCardResultNotify_proto_rawDesc
)

func file_InBattleMechanicusCardResultNotify_proto_rawDescGZIP() []byte {
	file_InBattleMechanicusCardResultNotify_proto_rawDescOnce.Do(func() {
		file_InBattleMechanicusCardResultNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_InBattleMechanicusCardResultNotify_proto_rawDescData)
	})
	return file_InBattleMechanicusCardResultNotify_proto_rawDescData
}

var file_InBattleMechanicusCardResultNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_InBattleMechanicusCardResultNotify_proto_goTypes = []interface{}{
	(*InBattleMechanicusCardResultNotify)(nil), // 0: InBattleMechanicusCardResultNotify
	nil,                                // 1: InBattleMechanicusCardResultNotify.PlayerConfirmedCardMapEntry
	(*InBattleMechanicusCardInfo)(nil), // 2: InBattleMechanicusCardInfo
}
var file_InBattleMechanicusCardResultNotify_proto_depIdxs = []int32{
	2, // 0: InBattleMechanicusCardResultNotify.card_list:type_name -> InBattleMechanicusCardInfo
	1, // 1: InBattleMechanicusCardResultNotify.player_confirmed_card_map:type_name -> InBattleMechanicusCardResultNotify.PlayerConfirmedCardMapEntry
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_InBattleMechanicusCardResultNotify_proto_init() }
func file_InBattleMechanicusCardResultNotify_proto_init() {
	if File_InBattleMechanicusCardResultNotify_proto != nil {
		return
	}
	file_InBattleMechanicusCardInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_InBattleMechanicusCardResultNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InBattleMechanicusCardResultNotify); i {
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
			RawDescriptor: file_InBattleMechanicusCardResultNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_InBattleMechanicusCardResultNotify_proto_goTypes,
		DependencyIndexes: file_InBattleMechanicusCardResultNotify_proto_depIdxs,
		MessageInfos:      file_InBattleMechanicusCardResultNotify_proto_msgTypes,
	}.Build()
	File_InBattleMechanicusCardResultNotify_proto = out.File
	file_InBattleMechanicusCardResultNotify_proto_rawDesc = nil
	file_InBattleMechanicusCardResultNotify_proto_goTypes = nil
	file_InBattleMechanicusCardResultNotify_proto_depIdxs = nil
}
