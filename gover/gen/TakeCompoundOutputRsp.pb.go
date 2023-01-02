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
// source: TakeCompoundOutputRsp.proto

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

type TakeCompoundOutputRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ItemList []*ItemParam `protobuf:"bytes,14,rep,name=item_list,json=itemList,proto3" json:"item_list,omitempty"`
	Retcode  int32        `protobuf:"varint,1,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *TakeCompoundOutputRsp) Reset() {
	*x = TakeCompoundOutputRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_TakeCompoundOutputRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TakeCompoundOutputRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TakeCompoundOutputRsp) ProtoMessage() {}

func (x *TakeCompoundOutputRsp) ProtoReflect() protoreflect.Message {
	mi := &file_TakeCompoundOutputRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TakeCompoundOutputRsp.ProtoReflect.Descriptor instead.
func (*TakeCompoundOutputRsp) Descriptor() ([]byte, []int) {
	return file_TakeCompoundOutputRsp_proto_rawDescGZIP(), []int{0}
}

func (x *TakeCompoundOutputRsp) GetItemList() []*ItemParam {
	if x != nil {
		return x.ItemList
	}
	return nil
}

func (x *TakeCompoundOutputRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

var File_TakeCompoundOutputRsp_proto protoreflect.FileDescriptor

var file_TakeCompoundOutputRsp_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x54, 0x61, 0x6b, 0x65, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x75, 0x6e, 0x64, 0x4f, 0x75,
	0x74, 0x70, 0x75, 0x74, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x49,
	0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5a,
	0x0a, 0x15, 0x54, 0x61, 0x6b, 0x65, 0x43, 0x6f, 0x6d, 0x70, 0x6f, 0x75, 0x6e, 0x64, 0x4f, 0x75,
	0x74, 0x70, 0x75, 0x74, 0x52, 0x73, 0x70, 0x12, 0x27, 0x0a, 0x09, 0x69, 0x74, 0x65, 0x6d, 0x5f,
	0x6c, 0x69, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x49, 0x74, 0x65,
	0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x52, 0x08, 0x69, 0x74, 0x65, 0x6d, 0x4c, 0x69, 0x73, 0x74,
	0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_TakeCompoundOutputRsp_proto_rawDescOnce sync.Once
	file_TakeCompoundOutputRsp_proto_rawDescData = file_TakeCompoundOutputRsp_proto_rawDesc
)

func file_TakeCompoundOutputRsp_proto_rawDescGZIP() []byte {
	file_TakeCompoundOutputRsp_proto_rawDescOnce.Do(func() {
		file_TakeCompoundOutputRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_TakeCompoundOutputRsp_proto_rawDescData)
	})
	return file_TakeCompoundOutputRsp_proto_rawDescData
}

var file_TakeCompoundOutputRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_TakeCompoundOutputRsp_proto_goTypes = []interface{}{
	(*TakeCompoundOutputRsp)(nil), // 0: TakeCompoundOutputRsp
	(*ItemParam)(nil),             // 1: ItemParam
}
var file_TakeCompoundOutputRsp_proto_depIdxs = []int32{
	1, // 0: TakeCompoundOutputRsp.item_list:type_name -> ItemParam
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_TakeCompoundOutputRsp_proto_init() }
func file_TakeCompoundOutputRsp_proto_init() {
	if File_TakeCompoundOutputRsp_proto != nil {
		return
	}
	file_ItemParam_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_TakeCompoundOutputRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TakeCompoundOutputRsp); i {
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
			RawDescriptor: file_TakeCompoundOutputRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_TakeCompoundOutputRsp_proto_goTypes,
		DependencyIndexes: file_TakeCompoundOutputRsp_proto_depIdxs,
		MessageInfos:      file_TakeCompoundOutputRsp_proto_msgTypes,
	}.Build()
	File_TakeCompoundOutputRsp_proto = out.File
	file_TakeCompoundOutputRsp_proto_rawDesc = nil
	file_TakeCompoundOutputRsp_proto_goTypes = nil
	file_TakeCompoundOutputRsp_proto_depIdxs = nil
}
