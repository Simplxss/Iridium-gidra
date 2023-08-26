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
// source: PlayerCookRsp.proto

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

// CmdId: 1250
// Obf: GDCGPFPELAO
type PlayerCookRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Retcode        int32           `protobuf:"varint,9,opt,name=retcode,proto3" json:"retcode,omitempty"`
	CookCount      uint32          `protobuf:"varint,8,opt,name=cook_count,json=cookCount,proto3" json:"cook_count,omitempty"`
	RecipeData     *CookRecipeData `protobuf:"bytes,5,opt,name=recipe_data,json=recipeData,proto3" json:"recipe_data,omitempty"`
	QteQuality     uint32          `protobuf:"varint,6,opt,name=qte_quality,json=qteQuality,proto3" json:"qte_quality,omitempty"`
	ItemList       []*ItemParam    `protobuf:"bytes,10,rep,name=item_list,json=itemList,proto3" json:"item_list,omitempty"`
	ExtralItemList []*ItemParam    `protobuf:"bytes,15,rep,name=extral_item_list,json=extralItemList,proto3" json:"extral_item_list,omitempty"`
}

func (x *PlayerCookRsp) Reset() {
	*x = PlayerCookRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_PlayerCookRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PlayerCookRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PlayerCookRsp) ProtoMessage() {}

func (x *PlayerCookRsp) ProtoReflect() protoreflect.Message {
	mi := &file_PlayerCookRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PlayerCookRsp.ProtoReflect.Descriptor instead.
func (*PlayerCookRsp) Descriptor() ([]byte, []int) {
	return file_PlayerCookRsp_proto_rawDescGZIP(), []int{0}
}

func (x *PlayerCookRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *PlayerCookRsp) GetCookCount() uint32 {
	if x != nil {
		return x.CookCount
	}
	return 0
}

func (x *PlayerCookRsp) GetRecipeData() *CookRecipeData {
	if x != nil {
		return x.RecipeData
	}
	return nil
}

func (x *PlayerCookRsp) GetQteQuality() uint32 {
	if x != nil {
		return x.QteQuality
	}
	return 0
}

func (x *PlayerCookRsp) GetItemList() []*ItemParam {
	if x != nil {
		return x.ItemList
	}
	return nil
}

func (x *PlayerCookRsp) GetExtralItemList() []*ItemParam {
	if x != nil {
		return x.ExtralItemList
	}
	return nil
}

var File_PlayerCookRsp_proto protoreflect.FileDescriptor

var file_PlayerCookRsp_proto_rawDesc = []byte{
	0x0a, 0x13, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x43, 0x6f, 0x6f, 0x6b, 0x52, 0x73, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x43, 0x6f, 0x6f, 0x6b, 0x52, 0x65, 0x63, 0x69, 0x70,
	0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x49, 0x74, 0x65,
	0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xfa, 0x01, 0x0a,
	0x0d, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x43, 0x6f, 0x6f, 0x6b, 0x52, 0x73, 0x70, 0x12, 0x18,
	0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x6f, 0x6f, 0x6b,
	0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x63, 0x6f,
	0x6f, 0x6b, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x30, 0x0a, 0x0b, 0x72, 0x65, 0x63, 0x69, 0x70,
	0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x43,
	0x6f, 0x6f, 0x6b, 0x52, 0x65, 0x63, 0x69, 0x70, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x0a, 0x72,
	0x65, 0x63, 0x69, 0x70, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x1f, 0x0a, 0x0b, 0x71, 0x74, 0x65,
	0x5f, 0x71, 0x75, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a,
	0x71, 0x74, 0x65, 0x51, 0x75, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x12, 0x27, 0x0a, 0x09, 0x69, 0x74,
	0x65, 0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e,
	0x49, 0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x52, 0x08, 0x69, 0x74, 0x65, 0x6d, 0x4c,
	0x69, 0x73, 0x74, 0x12, 0x34, 0x0a, 0x10, 0x65, 0x78, 0x74, 0x72, 0x61, 0x6c, 0x5f, 0x69, 0x74,
	0x65, 0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0f, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e,
	0x49, 0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x52, 0x0e, 0x65, 0x78, 0x74, 0x72, 0x61,
	0x6c, 0x49, 0x74, 0x65, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_PlayerCookRsp_proto_rawDescOnce sync.Once
	file_PlayerCookRsp_proto_rawDescData = file_PlayerCookRsp_proto_rawDesc
)

func file_PlayerCookRsp_proto_rawDescGZIP() []byte {
	file_PlayerCookRsp_proto_rawDescOnce.Do(func() {
		file_PlayerCookRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_PlayerCookRsp_proto_rawDescData)
	})
	return file_PlayerCookRsp_proto_rawDescData
}

var file_PlayerCookRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_PlayerCookRsp_proto_goTypes = []interface{}{
	(*PlayerCookRsp)(nil),  // 0: PlayerCookRsp
	(*CookRecipeData)(nil), // 1: CookRecipeData
	(*ItemParam)(nil),      // 2: ItemParam
}
var file_PlayerCookRsp_proto_depIdxs = []int32{
	1, // 0: PlayerCookRsp.recipe_data:type_name -> CookRecipeData
	2, // 1: PlayerCookRsp.item_list:type_name -> ItemParam
	2, // 2: PlayerCookRsp.extral_item_list:type_name -> ItemParam
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_PlayerCookRsp_proto_init() }
func file_PlayerCookRsp_proto_init() {
	if File_PlayerCookRsp_proto != nil {
		return
	}
	file_CookRecipeData_proto_init()
	file_ItemParam_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_PlayerCookRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PlayerCookRsp); i {
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
			RawDescriptor: file_PlayerCookRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PlayerCookRsp_proto_goTypes,
		DependencyIndexes: file_PlayerCookRsp_proto_depIdxs,
		MessageInfos:      file_PlayerCookRsp_proto_msgTypes,
	}.Build()
	File_PlayerCookRsp_proto = out.File
	file_PlayerCookRsp_proto_rawDesc = nil
	file_PlayerCookRsp_proto_goTypes = nil
	file_PlayerCookRsp_proto_depIdxs = nil
}
