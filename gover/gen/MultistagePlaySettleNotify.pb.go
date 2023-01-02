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
// source: MultistagePlaySettleNotify.proto

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

type MultistagePlaySettleNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GroupId   uint32 `protobuf:"varint,3,opt,name=group_id,json=groupId,proto3" json:"group_id,omitempty"`
	PlayIndex uint32 `protobuf:"varint,9,opt,name=play_index,json=playIndex,proto3" json:"play_index,omitempty"`
	// Types that are assignable to Detail:
	//
	//	*MultistagePlaySettleNotify_MechanicusSettleInfo
	//	*MultistagePlaySettleNotify_ChessSettleInfo
	//	*MultistagePlaySettleNotify_IrodoriChessSettleInfo
	Detail isMultistagePlaySettleNotify_Detail `protobuf_oneof:"detail"`
}

func (x *MultistagePlaySettleNotify) Reset() {
	*x = MultistagePlaySettleNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_MultistagePlaySettleNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MultistagePlaySettleNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MultistagePlaySettleNotify) ProtoMessage() {}

func (x *MultistagePlaySettleNotify) ProtoReflect() protoreflect.Message {
	mi := &file_MultistagePlaySettleNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MultistagePlaySettleNotify.ProtoReflect.Descriptor instead.
func (*MultistagePlaySettleNotify) Descriptor() ([]byte, []int) {
	return file_MultistagePlaySettleNotify_proto_rawDescGZIP(), []int{0}
}

func (x *MultistagePlaySettleNotify) GetGroupId() uint32 {
	if x != nil {
		return x.GroupId
	}
	return 0
}

func (x *MultistagePlaySettleNotify) GetPlayIndex() uint32 {
	if x != nil {
		return x.PlayIndex
	}
	return 0
}

func (m *MultistagePlaySettleNotify) GetDetail() isMultistagePlaySettleNotify_Detail {
	if m != nil {
		return m.Detail
	}
	return nil
}

func (x *MultistagePlaySettleNotify) GetMechanicusSettleInfo() *InBattleMechanicusSettleInfo {
	if x, ok := x.GetDetail().(*MultistagePlaySettleNotify_MechanicusSettleInfo); ok {
		return x.MechanicusSettleInfo
	}
	return nil
}

func (x *MultistagePlaySettleNotify) GetChessSettleInfo() *InBattleChessSettleInfo {
	if x, ok := x.GetDetail().(*MultistagePlaySettleNotify_ChessSettleInfo); ok {
		return x.ChessSettleInfo
	}
	return nil
}

func (x *MultistagePlaySettleNotify) GetIrodoriChessSettleInfo() *InBattleIrodoriChessSettleInfo {
	if x, ok := x.GetDetail().(*MultistagePlaySettleNotify_IrodoriChessSettleInfo); ok {
		return x.IrodoriChessSettleInfo
	}
	return nil
}

type isMultistagePlaySettleNotify_Detail interface {
	isMultistagePlaySettleNotify_Detail()
}

type MultistagePlaySettleNotify_MechanicusSettleInfo struct {
	MechanicusSettleInfo *InBattleMechanicusSettleInfo `protobuf:"bytes,649,opt,name=mechanicus_settle_info,json=mechanicusSettleInfo,proto3,oneof"`
}

type MultistagePlaySettleNotify_ChessSettleInfo struct {
	ChessSettleInfo *InBattleChessSettleInfo `protobuf:"bytes,512,opt,name=chess_settle_info,json=chessSettleInfo,proto3,oneof"`
}

type MultistagePlaySettleNotify_IrodoriChessSettleInfo struct {
	IrodoriChessSettleInfo *InBattleIrodoriChessSettleInfo `protobuf:"bytes,520,opt,name=irodori_chess_settle_info,json=irodoriChessSettleInfo,proto3,oneof"`
}

func (*MultistagePlaySettleNotify_MechanicusSettleInfo) isMultistagePlaySettleNotify_Detail() {}

func (*MultistagePlaySettleNotify_ChessSettleInfo) isMultistagePlaySettleNotify_Detail() {}

func (*MultistagePlaySettleNotify_IrodoriChessSettleInfo) isMultistagePlaySettleNotify_Detail() {}

var File_MultistagePlaySettleNotify_proto protoreflect.FileDescriptor

var file_MultistagePlaySettleNotify_proto_rawDesc = []byte{
	0x0a, 0x20, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x73, 0x74, 0x61, 0x67, 0x65, 0x50, 0x6c, 0x61, 0x79,
	0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x1d, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x43, 0x68, 0x65, 0x73,
	0x73, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x24, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x72, 0x6f, 0x64, 0x6f,
	0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66,
	0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x22, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c,
	0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x63, 0x75, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe0, 0x02, 0x0a, 0x1a,
	0x4d, 0x75, 0x6c, 0x74, 0x69, 0x73, 0x74, 0x61, 0x67, 0x65, 0x50, 0x6c, 0x61, 0x79, 0x53, 0x65,
	0x74, 0x74, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x19, 0x0a, 0x08, 0x67, 0x72,
	0x6f, 0x75, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x67, 0x72,
	0x6f, 0x75, 0x70, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x69, 0x6e,
	0x64, 0x65, 0x78, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x6c, 0x61, 0x79, 0x49,
	0x6e, 0x64, 0x65, 0x78, 0x12, 0x56, 0x0a, 0x16, 0x6d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x63,
	0x75, 0x73, 0x5f, 0x73, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x89,
	0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65,
	0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x63, 0x75, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65,
	0x49, 0x6e, 0x66, 0x6f, 0x48, 0x00, 0x52, 0x14, 0x6d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x63,
	0x75, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x47, 0x0a, 0x11,
	0x63, 0x68, 0x65, 0x73, 0x73, 0x5f, 0x73, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x5f, 0x69, 0x6e, 0x66,
	0x6f, 0x18, 0x80, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x49, 0x6e, 0x42, 0x61, 0x74,
	0x74, 0x6c, 0x65, 0x43, 0x68, 0x65, 0x73, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e,
	0x66, 0x6f, 0x48, 0x00, 0x52, 0x0f, 0x63, 0x68, 0x65, 0x73, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x5d, 0x0a, 0x19, 0x69, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69,
	0x5f, 0x63, 0x68, 0x65, 0x73, 0x73, 0x5f, 0x73, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x5f, 0x69, 0x6e,
	0x66, 0x6f, 0x18, 0x88, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x49, 0x6e, 0x42, 0x61,
	0x74, 0x74, 0x6c, 0x65, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73,
	0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x48, 0x00, 0x52, 0x16, 0x69, 0x72,
	0x6f, 0x64, 0x6f, 0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65,
	0x49, 0x6e, 0x66, 0x6f, 0x42, 0x08, 0x0a, 0x06, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x42, 0x06,
	0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_MultistagePlaySettleNotify_proto_rawDescOnce sync.Once
	file_MultistagePlaySettleNotify_proto_rawDescData = file_MultistagePlaySettleNotify_proto_rawDesc
)

func file_MultistagePlaySettleNotify_proto_rawDescGZIP() []byte {
	file_MultistagePlaySettleNotify_proto_rawDescOnce.Do(func() {
		file_MultistagePlaySettleNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_MultistagePlaySettleNotify_proto_rawDescData)
	})
	return file_MultistagePlaySettleNotify_proto_rawDescData
}

var file_MultistagePlaySettleNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_MultistagePlaySettleNotify_proto_goTypes = []interface{}{
	(*MultistagePlaySettleNotify)(nil),     // 0: MultistagePlaySettleNotify
	(*InBattleMechanicusSettleInfo)(nil),   // 1: InBattleMechanicusSettleInfo
	(*InBattleChessSettleInfo)(nil),        // 2: InBattleChessSettleInfo
	(*InBattleIrodoriChessSettleInfo)(nil), // 3: InBattleIrodoriChessSettleInfo
}
var file_MultistagePlaySettleNotify_proto_depIdxs = []int32{
	1, // 0: MultistagePlaySettleNotify.mechanicus_settle_info:type_name -> InBattleMechanicusSettleInfo
	2, // 1: MultistagePlaySettleNotify.chess_settle_info:type_name -> InBattleChessSettleInfo
	3, // 2: MultistagePlaySettleNotify.irodori_chess_settle_info:type_name -> InBattleIrodoriChessSettleInfo
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_MultistagePlaySettleNotify_proto_init() }
func file_MultistagePlaySettleNotify_proto_init() {
	if File_MultistagePlaySettleNotify_proto != nil {
		return
	}
	file_InBattleChessSettleInfo_proto_init()
	file_InBattleIrodoriChessSettleInfo_proto_init()
	file_InBattleMechanicusSettleInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_MultistagePlaySettleNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MultistagePlaySettleNotify); i {
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
	file_MultistagePlaySettleNotify_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*MultistagePlaySettleNotify_MechanicusSettleInfo)(nil),
		(*MultistagePlaySettleNotify_ChessSettleInfo)(nil),
		(*MultistagePlaySettleNotify_IrodoriChessSettleInfo)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_MultistagePlaySettleNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_MultistagePlaySettleNotify_proto_goTypes,
		DependencyIndexes: file_MultistagePlaySettleNotify_proto_depIdxs,
		MessageInfos:      file_MultistagePlaySettleNotify_proto_msgTypes,
	}.Build()
	File_MultistagePlaySettleNotify_proto = out.File
	file_MultistagePlaySettleNotify_proto_rawDesc = nil
	file_MultistagePlaySettleNotify_proto_goTypes = nil
	file_MultistagePlaySettleNotify_proto_depIdxs = nil
}
