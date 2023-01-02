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
// source: EnterRogueDiaryDungeonReq.proto

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

type EnterRogueDiaryDungeonReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChosenCardList   []uint32            `protobuf:"varint,5,rep,packed,name=chosen_card_list,json=chosenCardList,proto3" json:"chosen_card_list,omitempty"`
	ChosenAvatarList []*RogueDiaryAvatar `protobuf:"bytes,9,rep,name=chosen_avatar_list,json=chosenAvatarList,proto3" json:"chosen_avatar_list,omitempty"`
}

func (x *EnterRogueDiaryDungeonReq) Reset() {
	*x = EnterRogueDiaryDungeonReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_EnterRogueDiaryDungeonReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnterRogueDiaryDungeonReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnterRogueDiaryDungeonReq) ProtoMessage() {}

func (x *EnterRogueDiaryDungeonReq) ProtoReflect() protoreflect.Message {
	mi := &file_EnterRogueDiaryDungeonReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnterRogueDiaryDungeonReq.ProtoReflect.Descriptor instead.
func (*EnterRogueDiaryDungeonReq) Descriptor() ([]byte, []int) {
	return file_EnterRogueDiaryDungeonReq_proto_rawDescGZIP(), []int{0}
}

func (x *EnterRogueDiaryDungeonReq) GetChosenCardList() []uint32 {
	if x != nil {
		return x.ChosenCardList
	}
	return nil
}

func (x *EnterRogueDiaryDungeonReq) GetChosenAvatarList() []*RogueDiaryAvatar {
	if x != nil {
		return x.ChosenAvatarList
	}
	return nil
}

var File_EnterRogueDiaryDungeonReq_proto protoreflect.FileDescriptor

var file_EnterRogueDiaryDungeonReq_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x52, 0x6f, 0x67, 0x75, 0x65, 0x44, 0x69, 0x61, 0x72,
	0x79, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x16, 0x52, 0x6f, 0x67, 0x75, 0x65, 0x44, 0x69, 0x61, 0x72, 0x79, 0x41, 0x76, 0x61,
	0x74, 0x61, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x86, 0x01, 0x0a, 0x19, 0x45, 0x6e,
	0x74, 0x65, 0x72, 0x52, 0x6f, 0x67, 0x75, 0x65, 0x44, 0x69, 0x61, 0x72, 0x79, 0x44, 0x75, 0x6e,
	0x67, 0x65, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x12, 0x28, 0x0a, 0x10, 0x63, 0x68, 0x6f, 0x73, 0x65,
	0x6e, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x05, 0x20, 0x03, 0x28,
	0x0d, 0x52, 0x0e, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e, 0x43, 0x61, 0x72, 0x64, 0x4c, 0x69, 0x73,
	0x74, 0x12, 0x3f, 0x0a, 0x12, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e, 0x5f, 0x61, 0x76, 0x61, 0x74,
	0x61, 0x72, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e,
	0x52, 0x6f, 0x67, 0x75, 0x65, 0x44, 0x69, 0x61, 0x72, 0x79, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72,
	0x52, 0x10, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x4c, 0x69,
	0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_EnterRogueDiaryDungeonReq_proto_rawDescOnce sync.Once
	file_EnterRogueDiaryDungeonReq_proto_rawDescData = file_EnterRogueDiaryDungeonReq_proto_rawDesc
)

func file_EnterRogueDiaryDungeonReq_proto_rawDescGZIP() []byte {
	file_EnterRogueDiaryDungeonReq_proto_rawDescOnce.Do(func() {
		file_EnterRogueDiaryDungeonReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_EnterRogueDiaryDungeonReq_proto_rawDescData)
	})
	return file_EnterRogueDiaryDungeonReq_proto_rawDescData
}

var file_EnterRogueDiaryDungeonReq_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_EnterRogueDiaryDungeonReq_proto_goTypes = []interface{}{
	(*EnterRogueDiaryDungeonReq)(nil), // 0: EnterRogueDiaryDungeonReq
	(*RogueDiaryAvatar)(nil),          // 1: RogueDiaryAvatar
}
var file_EnterRogueDiaryDungeonReq_proto_depIdxs = []int32{
	1, // 0: EnterRogueDiaryDungeonReq.chosen_avatar_list:type_name -> RogueDiaryAvatar
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_EnterRogueDiaryDungeonReq_proto_init() }
func file_EnterRogueDiaryDungeonReq_proto_init() {
	if File_EnterRogueDiaryDungeonReq_proto != nil {
		return
	}
	file_RogueDiaryAvatar_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_EnterRogueDiaryDungeonReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnterRogueDiaryDungeonReq); i {
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
			RawDescriptor: file_EnterRogueDiaryDungeonReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_EnterRogueDiaryDungeonReq_proto_goTypes,
		DependencyIndexes: file_EnterRogueDiaryDungeonReq_proto_depIdxs,
		MessageInfos:      file_EnterRogueDiaryDungeonReq_proto_msgTypes,
	}.Build()
	File_EnterRogueDiaryDungeonReq_proto = out.File
	file_EnterRogueDiaryDungeonReq_proto_rawDesc = nil
	file_EnterRogueDiaryDungeonReq_proto_goTypes = nil
	file_EnterRogueDiaryDungeonReq_proto_depIdxs = nil
}
