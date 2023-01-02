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
// source: ForgeGetQueueDataRsp.proto

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

type ForgeGetQueueDataRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MaxQueueNum   uint32                     `protobuf:"varint,4,opt,name=max_queue_num,json=maxQueueNum,proto3" json:"max_queue_num,omitempty"`
	ForgeQueueMap map[uint32]*ForgeQueueData `protobuf:"bytes,9,rep,name=forge_queue_map,json=forgeQueueMap,proto3" json:"forge_queue_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Retcode       int32                      `protobuf:"varint,15,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *ForgeGetQueueDataRsp) Reset() {
	*x = ForgeGetQueueDataRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ForgeGetQueueDataRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ForgeGetQueueDataRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ForgeGetQueueDataRsp) ProtoMessage() {}

func (x *ForgeGetQueueDataRsp) ProtoReflect() protoreflect.Message {
	mi := &file_ForgeGetQueueDataRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ForgeGetQueueDataRsp.ProtoReflect.Descriptor instead.
func (*ForgeGetQueueDataRsp) Descriptor() ([]byte, []int) {
	return file_ForgeGetQueueDataRsp_proto_rawDescGZIP(), []int{0}
}

func (x *ForgeGetQueueDataRsp) GetMaxQueueNum() uint32 {
	if x != nil {
		return x.MaxQueueNum
	}
	return 0
}

func (x *ForgeGetQueueDataRsp) GetForgeQueueMap() map[uint32]*ForgeQueueData {
	if x != nil {
		return x.ForgeQueueMap
	}
	return nil
}

func (x *ForgeGetQueueDataRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

var File_ForgeGetQueueDataRsp_proto protoreflect.FileDescriptor

var file_ForgeGetQueueDataRsp_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x46, 0x6f, 0x72, 0x67, 0x65, 0x47, 0x65, 0x74, 0x51, 0x75, 0x65, 0x75, 0x65, 0x44,
	0x61, 0x74, 0x61, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x46, 0x6f,
	0x72, 0x67, 0x65, 0x51, 0x75, 0x65, 0x75, 0x65, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xf9, 0x01, 0x0a, 0x14, 0x46, 0x6f, 0x72, 0x67, 0x65, 0x47, 0x65, 0x74, 0x51,
	0x75, 0x65, 0x75, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x73, 0x70, 0x12, 0x22, 0x0a, 0x0d, 0x6d,
	0x61, 0x78, 0x5f, 0x71, 0x75, 0x65, 0x75, 0x65, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x6d, 0x61, 0x78, 0x51, 0x75, 0x65, 0x75, 0x65, 0x4e, 0x75, 0x6d, 0x12,
	0x50, 0x0a, 0x0f, 0x66, 0x6f, 0x72, 0x67, 0x65, 0x5f, 0x71, 0x75, 0x65, 0x75, 0x65, 0x5f, 0x6d,
	0x61, 0x70, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x46, 0x6f, 0x72, 0x67, 0x65,
	0x47, 0x65, 0x74, 0x51, 0x75, 0x65, 0x75, 0x65, 0x44, 0x61, 0x74, 0x61, 0x52, 0x73, 0x70, 0x2e,
	0x46, 0x6f, 0x72, 0x67, 0x65, 0x51, 0x75, 0x65, 0x75, 0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x0d, 0x66, 0x6f, 0x72, 0x67, 0x65, 0x51, 0x75, 0x65, 0x75, 0x65, 0x4d, 0x61,
	0x70, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x0f, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x1a, 0x51, 0x0a, 0x12, 0x46,
	0x6f, 0x72, 0x67, 0x65, 0x51, 0x75, 0x65, 0x75, 0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03,
	0x6b, 0x65, 0x79, 0x12, 0x25, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x46, 0x6f, 0x72, 0x67, 0x65, 0x51, 0x75, 0x65, 0x75, 0x65, 0x44,
	0x61, 0x74, 0x61, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x06,
	0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ForgeGetQueueDataRsp_proto_rawDescOnce sync.Once
	file_ForgeGetQueueDataRsp_proto_rawDescData = file_ForgeGetQueueDataRsp_proto_rawDesc
)

func file_ForgeGetQueueDataRsp_proto_rawDescGZIP() []byte {
	file_ForgeGetQueueDataRsp_proto_rawDescOnce.Do(func() {
		file_ForgeGetQueueDataRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_ForgeGetQueueDataRsp_proto_rawDescData)
	})
	return file_ForgeGetQueueDataRsp_proto_rawDescData
}

var file_ForgeGetQueueDataRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_ForgeGetQueueDataRsp_proto_goTypes = []interface{}{
	(*ForgeGetQueueDataRsp)(nil), // 0: ForgeGetQueueDataRsp
	nil,                          // 1: ForgeGetQueueDataRsp.ForgeQueueMapEntry
	(*ForgeQueueData)(nil),       // 2: ForgeQueueData
}
var file_ForgeGetQueueDataRsp_proto_depIdxs = []int32{
	1, // 0: ForgeGetQueueDataRsp.forge_queue_map:type_name -> ForgeGetQueueDataRsp.ForgeQueueMapEntry
	2, // 1: ForgeGetQueueDataRsp.ForgeQueueMapEntry.value:type_name -> ForgeQueueData
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_ForgeGetQueueDataRsp_proto_init() }
func file_ForgeGetQueueDataRsp_proto_init() {
	if File_ForgeGetQueueDataRsp_proto != nil {
		return
	}
	file_ForgeQueueData_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ForgeGetQueueDataRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ForgeGetQueueDataRsp); i {
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
			RawDescriptor: file_ForgeGetQueueDataRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ForgeGetQueueDataRsp_proto_goTypes,
		DependencyIndexes: file_ForgeGetQueueDataRsp_proto_depIdxs,
		MessageInfos:      file_ForgeGetQueueDataRsp_proto_msgTypes,
	}.Build()
	File_ForgeGetQueueDataRsp_proto = out.File
	file_ForgeGetQueueDataRsp_proto_rawDesc = nil
	file_ForgeGetQueueDataRsp_proto_goTypes = nil
	file_ForgeGetQueueDataRsp_proto_depIdxs = nil
}
