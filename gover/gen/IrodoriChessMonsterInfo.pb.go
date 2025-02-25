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
// source: IrodoriChessMonsterInfo.proto

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

// Obf: BNNFFFNKHLO
type IrodoriChessMonsterInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MonsterId   uint32   `protobuf:"varint,7,opt,name=monster_id,json=monsterId,proto3" json:"monster_id,omitempty"`
	AffixList   []uint32 `protobuf:"varint,6,rep,packed,name=affix_list,json=affixList,proto3" json:"affix_list,omitempty"`
	Level       uint32   `protobuf:"varint,9,opt,name=level,proto3" json:"level,omitempty"`
	GrantPoints uint32   `protobuf:"varint,13,opt,name=grant_points,json=grantPoints,proto3" json:"grant_points,omitempty"`
}

func (x *IrodoriChessMonsterInfo) Reset() {
	*x = IrodoriChessMonsterInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_IrodoriChessMonsterInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IrodoriChessMonsterInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IrodoriChessMonsterInfo) ProtoMessage() {}

func (x *IrodoriChessMonsterInfo) ProtoReflect() protoreflect.Message {
	mi := &file_IrodoriChessMonsterInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IrodoriChessMonsterInfo.ProtoReflect.Descriptor instead.
func (*IrodoriChessMonsterInfo) Descriptor() ([]byte, []int) {
	return file_IrodoriChessMonsterInfo_proto_rawDescGZIP(), []int{0}
}

func (x *IrodoriChessMonsterInfo) GetMonsterId() uint32 {
	if x != nil {
		return x.MonsterId
	}
	return 0
}

func (x *IrodoriChessMonsterInfo) GetAffixList() []uint32 {
	if x != nil {
		return x.AffixList
	}
	return nil
}

func (x *IrodoriChessMonsterInfo) GetLevel() uint32 {
	if x != nil {
		return x.Level
	}
	return 0
}

func (x *IrodoriChessMonsterInfo) GetGrantPoints() uint32 {
	if x != nil {
		return x.GrantPoints
	}
	return 0
}

var File_IrodoriChessMonsterInfo_proto protoreflect.FileDescriptor

var file_IrodoriChessMonsterInfo_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73, 0x4d, 0x6f,
	0x6e, 0x73, 0x74, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x90, 0x01, 0x0a, 0x17, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73,
	0x4d, 0x6f, 0x6e, 0x73, 0x74, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1d, 0x0a, 0x0a, 0x6d,
	0x6f, 0x6e, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x09, 0x6d, 0x6f, 0x6e, 0x73, 0x74, 0x65, 0x72, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x61, 0x66,
	0x66, 0x69, 0x78, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x09,
	0x61, 0x66, 0x66, 0x69, 0x78, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x12,
	0x21, 0x0a, 0x0c, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x67, 0x72, 0x61, 0x6e, 0x74, 0x50, 0x6f, 0x69, 0x6e,
	0x74, 0x73, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_IrodoriChessMonsterInfo_proto_rawDescOnce sync.Once
	file_IrodoriChessMonsterInfo_proto_rawDescData = file_IrodoriChessMonsterInfo_proto_rawDesc
)

func file_IrodoriChessMonsterInfo_proto_rawDescGZIP() []byte {
	file_IrodoriChessMonsterInfo_proto_rawDescOnce.Do(func() {
		file_IrodoriChessMonsterInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_IrodoriChessMonsterInfo_proto_rawDescData)
	})
	return file_IrodoriChessMonsterInfo_proto_rawDescData
}

var file_IrodoriChessMonsterInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_IrodoriChessMonsterInfo_proto_goTypes = []interface{}{
	(*IrodoriChessMonsterInfo)(nil), // 0: IrodoriChessMonsterInfo
}
var file_IrodoriChessMonsterInfo_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_IrodoriChessMonsterInfo_proto_init() }
func file_IrodoriChessMonsterInfo_proto_init() {
	if File_IrodoriChessMonsterInfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_IrodoriChessMonsterInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IrodoriChessMonsterInfo); i {
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
			RawDescriptor: file_IrodoriChessMonsterInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_IrodoriChessMonsterInfo_proto_goTypes,
		DependencyIndexes: file_IrodoriChessMonsterInfo_proto_depIdxs,
		MessageInfos:      file_IrodoriChessMonsterInfo_proto_msgTypes,
	}.Build()
	File_IrodoriChessMonsterInfo_proto = out.File
	file_IrodoriChessMonsterInfo_proto_rawDesc = nil
	file_IrodoriChessMonsterInfo_proto_goTypes = nil
	file_IrodoriChessMonsterInfo_proto_depIdxs = nil
}
