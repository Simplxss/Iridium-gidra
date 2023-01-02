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
// source: ForgeQueueManipulateRsp.proto

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

type ForgeQueueManipulateRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ExtraOutputItemList []*ItemParam             `protobuf:"bytes,3,rep,name=extra_output_item_list,json=extraOutputItemList,proto3" json:"extra_output_item_list,omitempty"`
	ManipulateType      ForgeQueueManipulateType `protobuf:"varint,12,opt,name=manipulate_type,json=manipulateType,proto3,enum=ForgeQueueManipulateType" json:"manipulate_type,omitempty"`
	ReturnItemList      []*ItemParam             `protobuf:"bytes,4,rep,name=return_item_list,json=returnItemList,proto3" json:"return_item_list,omitempty"`
	OutputItemList      []*ItemParam             `protobuf:"bytes,14,rep,name=output_item_list,json=outputItemList,proto3" json:"output_item_list,omitempty"`
	Retcode             int32                    `protobuf:"varint,11,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *ForgeQueueManipulateRsp) Reset() {
	*x = ForgeQueueManipulateRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ForgeQueueManipulateRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ForgeQueueManipulateRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ForgeQueueManipulateRsp) ProtoMessage() {}

func (x *ForgeQueueManipulateRsp) ProtoReflect() protoreflect.Message {
	mi := &file_ForgeQueueManipulateRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ForgeQueueManipulateRsp.ProtoReflect.Descriptor instead.
func (*ForgeQueueManipulateRsp) Descriptor() ([]byte, []int) {
	return file_ForgeQueueManipulateRsp_proto_rawDescGZIP(), []int{0}
}

func (x *ForgeQueueManipulateRsp) GetExtraOutputItemList() []*ItemParam {
	if x != nil {
		return x.ExtraOutputItemList
	}
	return nil
}

func (x *ForgeQueueManipulateRsp) GetManipulateType() ForgeQueueManipulateType {
	if x != nil {
		return x.ManipulateType
	}
	return ForgeQueueManipulateType_FORGE_QUEUE_MANIPULATE_TYPE_RECEIVE_OUTPUT
}

func (x *ForgeQueueManipulateRsp) GetReturnItemList() []*ItemParam {
	if x != nil {
		return x.ReturnItemList
	}
	return nil
}

func (x *ForgeQueueManipulateRsp) GetOutputItemList() []*ItemParam {
	if x != nil {
		return x.OutputItemList
	}
	return nil
}

func (x *ForgeQueueManipulateRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

var File_ForgeQueueManipulateRsp_proto protoreflect.FileDescriptor

var file_ForgeQueueManipulateRsp_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x46, 0x6f, 0x72, 0x67, 0x65, 0x51, 0x75, 0x65, 0x75, 0x65, 0x4d, 0x61, 0x6e, 0x69,
	0x70, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x1e, 0x46, 0x6f, 0x72, 0x67, 0x65, 0x51, 0x75, 0x65, 0x75, 0x65, 0x4d, 0x61, 0x6e, 0x69, 0x70,
	0x75, 0x6c, 0x61, 0x74, 0x65, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x0f, 0x49, 0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xa4, 0x02, 0x0a, 0x17, 0x46, 0x6f, 0x72, 0x67, 0x65, 0x51, 0x75, 0x65, 0x75, 0x65, 0x4d,
	0x61, 0x6e, 0x69, 0x70, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x52, 0x73, 0x70, 0x12, 0x3f, 0x0a, 0x16,
	0x65, 0x78, 0x74, 0x72, 0x61, 0x5f, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x5f, 0x69, 0x74, 0x65,
	0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x49,
	0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x52, 0x13, 0x65, 0x78, 0x74, 0x72, 0x61, 0x4f,
	0x75, 0x74, 0x70, 0x75, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x42, 0x0a,
	0x0f, 0x6d, 0x61, 0x6e, 0x69, 0x70, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x46, 0x6f, 0x72, 0x67, 0x65, 0x51, 0x75,
	0x65, 0x75, 0x65, 0x4d, 0x61, 0x6e, 0x69, 0x70, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x54, 0x79, 0x70,
	0x65, 0x52, 0x0e, 0x6d, 0x61, 0x6e, 0x69, 0x70, 0x75, 0x6c, 0x61, 0x74, 0x65, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x34, 0x0a, 0x10, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x5f, 0x69, 0x74, 0x65, 0x6d,
	0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x49, 0x74,
	0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x52, 0x0e, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x49,
	0x74, 0x65, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x34, 0x0a, 0x10, 0x6f, 0x75, 0x74, 0x70, 0x75,
	0x74, 0x5f, 0x69, 0x74, 0x65, 0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x0a, 0x2e, 0x49, 0x74, 0x65, 0x6d, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x52, 0x0e, 0x6f,
	0x75, 0x74, 0x70, 0x75, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x18, 0x0a,
	0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07,
	0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ForgeQueueManipulateRsp_proto_rawDescOnce sync.Once
	file_ForgeQueueManipulateRsp_proto_rawDescData = file_ForgeQueueManipulateRsp_proto_rawDesc
)

func file_ForgeQueueManipulateRsp_proto_rawDescGZIP() []byte {
	file_ForgeQueueManipulateRsp_proto_rawDescOnce.Do(func() {
		file_ForgeQueueManipulateRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_ForgeQueueManipulateRsp_proto_rawDescData)
	})
	return file_ForgeQueueManipulateRsp_proto_rawDescData
}

var file_ForgeQueueManipulateRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ForgeQueueManipulateRsp_proto_goTypes = []interface{}{
	(*ForgeQueueManipulateRsp)(nil), // 0: ForgeQueueManipulateRsp
	(*ItemParam)(nil),               // 1: ItemParam
	(ForgeQueueManipulateType)(0),   // 2: ForgeQueueManipulateType
}
var file_ForgeQueueManipulateRsp_proto_depIdxs = []int32{
	1, // 0: ForgeQueueManipulateRsp.extra_output_item_list:type_name -> ItemParam
	2, // 1: ForgeQueueManipulateRsp.manipulate_type:type_name -> ForgeQueueManipulateType
	1, // 2: ForgeQueueManipulateRsp.return_item_list:type_name -> ItemParam
	1, // 3: ForgeQueueManipulateRsp.output_item_list:type_name -> ItemParam
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_ForgeQueueManipulateRsp_proto_init() }
func file_ForgeQueueManipulateRsp_proto_init() {
	if File_ForgeQueueManipulateRsp_proto != nil {
		return
	}
	file_ForgeQueueManipulateType_proto_init()
	file_ItemParam_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ForgeQueueManipulateRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ForgeQueueManipulateRsp); i {
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
			RawDescriptor: file_ForgeQueueManipulateRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ForgeQueueManipulateRsp_proto_goTypes,
		DependencyIndexes: file_ForgeQueueManipulateRsp_proto_depIdxs,
		MessageInfos:      file_ForgeQueueManipulateRsp_proto_msgTypes,
	}.Build()
	File_ForgeQueueManipulateRsp_proto = out.File
	file_ForgeQueueManipulateRsp_proto_rawDesc = nil
	file_ForgeQueueManipulateRsp_proto_goTypes = nil
	file_ForgeQueueManipulateRsp_proto_depIdxs = nil
}
