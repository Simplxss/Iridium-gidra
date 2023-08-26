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
// source: WinterCampStageInfoChangeNotify.proto

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

// CmdId: 28290
// Obf: PIAIMFNGJKI
type WinterCampStageInfoChangeNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BattleInfo  *WinterCampStageInfo `protobuf:"bytes,11,opt,name=battle_info,json=battleInfo,proto3" json:"battle_info,omitempty"`
	ExploreInfo *WinterCampStageInfo `protobuf:"bytes,9,opt,name=explore_info,json=exploreInfo,proto3" json:"explore_info,omitempty"`
}

func (x *WinterCampStageInfoChangeNotify) Reset() {
	*x = WinterCampStageInfoChangeNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_WinterCampStageInfoChangeNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *WinterCampStageInfoChangeNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WinterCampStageInfoChangeNotify) ProtoMessage() {}

func (x *WinterCampStageInfoChangeNotify) ProtoReflect() protoreflect.Message {
	mi := &file_WinterCampStageInfoChangeNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WinterCampStageInfoChangeNotify.ProtoReflect.Descriptor instead.
func (*WinterCampStageInfoChangeNotify) Descriptor() ([]byte, []int) {
	return file_WinterCampStageInfoChangeNotify_proto_rawDescGZIP(), []int{0}
}

func (x *WinterCampStageInfoChangeNotify) GetBattleInfo() *WinterCampStageInfo {
	if x != nil {
		return x.BattleInfo
	}
	return nil
}

func (x *WinterCampStageInfoChangeNotify) GetExploreInfo() *WinterCampStageInfo {
	if x != nil {
		return x.ExploreInfo
	}
	return nil
}

var File_WinterCampStageInfoChangeNotify_proto protoreflect.FileDescriptor

var file_WinterCampStageInfoChangeNotify_proto_rawDesc = []byte{
	0x0a, 0x25, 0x57, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x61, 0x6d, 0x70, 0x53, 0x74, 0x61, 0x67,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x57, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43,
	0x61, 0x6d, 0x70, 0x53, 0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x91, 0x01, 0x0a, 0x1f, 0x57, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x61, 0x6d,
	0x70, 0x53, 0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65,
	0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x35, 0x0a, 0x0b, 0x62, 0x61, 0x74, 0x74, 0x6c, 0x65,
	0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x57, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x43, 0x61, 0x6d, 0x70, 0x53, 0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66,
	0x6f, 0x52, 0x0a, 0x62, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x37, 0x0a,
	0x0c, 0x65, 0x78, 0x70, 0x6c, 0x6f, 0x72, 0x65, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x57, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x61, 0x6d, 0x70,
	0x53, 0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0b, 0x65, 0x78, 0x70, 0x6c, 0x6f,
	0x72, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_WinterCampStageInfoChangeNotify_proto_rawDescOnce sync.Once
	file_WinterCampStageInfoChangeNotify_proto_rawDescData = file_WinterCampStageInfoChangeNotify_proto_rawDesc
)

func file_WinterCampStageInfoChangeNotify_proto_rawDescGZIP() []byte {
	file_WinterCampStageInfoChangeNotify_proto_rawDescOnce.Do(func() {
		file_WinterCampStageInfoChangeNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_WinterCampStageInfoChangeNotify_proto_rawDescData)
	})
	return file_WinterCampStageInfoChangeNotify_proto_rawDescData
}

var file_WinterCampStageInfoChangeNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_WinterCampStageInfoChangeNotify_proto_goTypes = []interface{}{
	(*WinterCampStageInfoChangeNotify)(nil), // 0: WinterCampStageInfoChangeNotify
	(*WinterCampStageInfo)(nil),             // 1: WinterCampStageInfo
}
var file_WinterCampStageInfoChangeNotify_proto_depIdxs = []int32{
	1, // 0: WinterCampStageInfoChangeNotify.battle_info:type_name -> WinterCampStageInfo
	1, // 1: WinterCampStageInfoChangeNotify.explore_info:type_name -> WinterCampStageInfo
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_WinterCampStageInfoChangeNotify_proto_init() }
func file_WinterCampStageInfoChangeNotify_proto_init() {
	if File_WinterCampStageInfoChangeNotify_proto != nil {
		return
	}
	file_WinterCampStageInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_WinterCampStageInfoChangeNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*WinterCampStageInfoChangeNotify); i {
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
			RawDescriptor: file_WinterCampStageInfoChangeNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_WinterCampStageInfoChangeNotify_proto_goTypes,
		DependencyIndexes: file_WinterCampStageInfoChangeNotify_proto_depIdxs,
		MessageInfos:      file_WinterCampStageInfoChangeNotify_proto_msgTypes,
	}.Build()
	File_WinterCampStageInfoChangeNotify_proto = out.File
	file_WinterCampStageInfoChangeNotify_proto_rawDesc = nil
	file_WinterCampStageInfoChangeNotify_proto_goTypes = nil
	file_WinterCampStageInfoChangeNotify_proto_depIdxs = nil
}
