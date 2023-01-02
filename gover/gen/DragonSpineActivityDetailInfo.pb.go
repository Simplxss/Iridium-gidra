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
// source: DragonSpineActivityDetailInfo.proto

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

type DragonSpineActivityDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsContentClosed     bool                      `protobuf:"varint,9,opt,name=is_content_closed,json=isContentClosed,proto3" json:"is_content_closed,omitempty"`
	Unk3300_FOHJDGCAKEK uint32                    `protobuf:"varint,3,opt,name=Unk3300_FOHJDGCAKEK,json=Unk3300FOHJDGCAKEK,proto3" json:"Unk3300_FOHJDGCAKEK,omitempty"`
	Unk3300_PPABOFMIGNM uint32                    `protobuf:"varint,10,opt,name=Unk3300_PPABOFMIGNM,json=Unk3300PPABOFMIGNM,proto3" json:"Unk3300_PPABOFMIGNM,omitempty"`
	ChapterInfoList     []*DragonSpineChapterInfo `protobuf:"bytes,7,rep,name=chapter_info_list,json=chapterInfoList,proto3" json:"chapter_info_list,omitempty"`
	Unk3300_NEOCMGJCEOJ uint32                    `protobuf:"varint,4,opt,name=Unk3300_NEOCMGJCEOJ,json=Unk3300NEOCMGJCEOJ,proto3" json:"Unk3300_NEOCMGJCEOJ,omitempty"`
	Unk3300_IMLKIJAOADF uint32                    `protobuf:"varint,12,opt,name=Unk3300_IMLKIJAOADF,json=Unk3300IMLKIJAOADF,proto3" json:"Unk3300_IMLKIJAOADF,omitempty"`
	WeaponEnhanceLevel  uint32                    `protobuf:"varint,8,opt,name=weapon_enhance_level,json=weaponEnhanceLevel,proto3" json:"weapon_enhance_level,omitempty"`
}

func (x *DragonSpineActivityDetailInfo) Reset() {
	*x = DragonSpineActivityDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_DragonSpineActivityDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DragonSpineActivityDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DragonSpineActivityDetailInfo) ProtoMessage() {}

func (x *DragonSpineActivityDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_DragonSpineActivityDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DragonSpineActivityDetailInfo.ProtoReflect.Descriptor instead.
func (*DragonSpineActivityDetailInfo) Descriptor() ([]byte, []int) {
	return file_DragonSpineActivityDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *DragonSpineActivityDetailInfo) GetIsContentClosed() bool {
	if x != nil {
		return x.IsContentClosed
	}
	return false
}

func (x *DragonSpineActivityDetailInfo) GetUnk3300_FOHJDGCAKEK() uint32 {
	if x != nil {
		return x.Unk3300_FOHJDGCAKEK
	}
	return 0
}

func (x *DragonSpineActivityDetailInfo) GetUnk3300_PPABOFMIGNM() uint32 {
	if x != nil {
		return x.Unk3300_PPABOFMIGNM
	}
	return 0
}

func (x *DragonSpineActivityDetailInfo) GetChapterInfoList() []*DragonSpineChapterInfo {
	if x != nil {
		return x.ChapterInfoList
	}
	return nil
}

func (x *DragonSpineActivityDetailInfo) GetUnk3300_NEOCMGJCEOJ() uint32 {
	if x != nil {
		return x.Unk3300_NEOCMGJCEOJ
	}
	return 0
}

func (x *DragonSpineActivityDetailInfo) GetUnk3300_IMLKIJAOADF() uint32 {
	if x != nil {
		return x.Unk3300_IMLKIJAOADF
	}
	return 0
}

func (x *DragonSpineActivityDetailInfo) GetWeaponEnhanceLevel() uint32 {
	if x != nil {
		return x.WeaponEnhanceLevel
	}
	return 0
}

var File_DragonSpineActivityDetailInfo_proto protoreflect.FileDescriptor

var file_DragonSpineActivityDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x23, 0x44, 0x72, 0x61, 0x67, 0x6f, 0x6e, 0x53, 0x70, 0x69, 0x6e, 0x65, 0x41, 0x63, 0x74,
	0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x44, 0x72, 0x61, 0x67, 0x6f, 0x6e, 0x53, 0x70, 0x69,
	0x6e, 0x65, 0x43, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x86, 0x03, 0x0a, 0x1d, 0x44, 0x72, 0x61, 0x67, 0x6f, 0x6e, 0x53, 0x70,
	0x69, 0x6e, 0x65, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69,
	0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2a, 0x0a, 0x11, 0x69, 0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x74,
	0x65, 0x6e, 0x74, 0x5f, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x0f, 0x69, 0x73, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x43, 0x6c, 0x6f, 0x73, 0x65,
	0x64, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x5f, 0x46, 0x4f, 0x48,
	0x4a, 0x44, 0x47, 0x43, 0x41, 0x4b, 0x45, 0x4b, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12,
	0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x46, 0x4f, 0x48, 0x4a, 0x44, 0x47, 0x43, 0x41, 0x4b,
	0x45, 0x4b, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x5f, 0x50, 0x50,
	0x41, 0x42, 0x4f, 0x46, 0x4d, 0x49, 0x47, 0x4e, 0x4d, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x12, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x50, 0x50, 0x41, 0x42, 0x4f, 0x46, 0x4d, 0x49,
	0x47, 0x4e, 0x4d, 0x12, 0x43, 0x0a, 0x11, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x5f, 0x69,
	0x6e, 0x66, 0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x44, 0x72, 0x61, 0x67, 0x6f, 0x6e, 0x53, 0x70, 0x69, 0x6e, 0x65, 0x43, 0x68, 0x61, 0x70,
	0x74, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0f, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72,
	0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e, 0x6b, 0x33,
	0x33, 0x30, 0x30, 0x5f, 0x4e, 0x45, 0x4f, 0x43, 0x4d, 0x47, 0x4a, 0x43, 0x45, 0x4f, 0x4a, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x4e, 0x45,
	0x4f, 0x43, 0x4d, 0x47, 0x4a, 0x43, 0x45, 0x4f, 0x4a, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e, 0x6b,
	0x33, 0x33, 0x30, 0x30, 0x5f, 0x49, 0x4d, 0x4c, 0x4b, 0x49, 0x4a, 0x41, 0x4f, 0x41, 0x44, 0x46,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x49,
	0x4d, 0x4c, 0x4b, 0x49, 0x4a, 0x41, 0x4f, 0x41, 0x44, 0x46, 0x12, 0x30, 0x0a, 0x14, 0x77, 0x65,
	0x61, 0x70, 0x6f, 0x6e, 0x5f, 0x65, 0x6e, 0x68, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x77, 0x65, 0x61, 0x70, 0x6f, 0x6e,
	0x45, 0x6e, 0x68, 0x61, 0x6e, 0x63, 0x65, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x42, 0x06, 0x5a, 0x04,
	0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_DragonSpineActivityDetailInfo_proto_rawDescOnce sync.Once
	file_DragonSpineActivityDetailInfo_proto_rawDescData = file_DragonSpineActivityDetailInfo_proto_rawDesc
)

func file_DragonSpineActivityDetailInfo_proto_rawDescGZIP() []byte {
	file_DragonSpineActivityDetailInfo_proto_rawDescOnce.Do(func() {
		file_DragonSpineActivityDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_DragonSpineActivityDetailInfo_proto_rawDescData)
	})
	return file_DragonSpineActivityDetailInfo_proto_rawDescData
}

var file_DragonSpineActivityDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_DragonSpineActivityDetailInfo_proto_goTypes = []interface{}{
	(*DragonSpineActivityDetailInfo)(nil), // 0: DragonSpineActivityDetailInfo
	(*DragonSpineChapterInfo)(nil),        // 1: DragonSpineChapterInfo
}
var file_DragonSpineActivityDetailInfo_proto_depIdxs = []int32{
	1, // 0: DragonSpineActivityDetailInfo.chapter_info_list:type_name -> DragonSpineChapterInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_DragonSpineActivityDetailInfo_proto_init() }
func file_DragonSpineActivityDetailInfo_proto_init() {
	if File_DragonSpineActivityDetailInfo_proto != nil {
		return
	}
	file_DragonSpineChapterInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_DragonSpineActivityDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DragonSpineActivityDetailInfo); i {
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
			RawDescriptor: file_DragonSpineActivityDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DragonSpineActivityDetailInfo_proto_goTypes,
		DependencyIndexes: file_DragonSpineActivityDetailInfo_proto_depIdxs,
		MessageInfos:      file_DragonSpineActivityDetailInfo_proto_msgTypes,
	}.Build()
	File_DragonSpineActivityDetailInfo_proto = out.File
	file_DragonSpineActivityDetailInfo_proto_rawDesc = nil
	file_DragonSpineActivityDetailInfo_proto_goTypes = nil
	file_DragonSpineActivityDetailInfo_proto_depIdxs = nil
}
