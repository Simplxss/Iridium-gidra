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
// source: UpdateRedPointNotify.proto

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

// CmdId: 21359
// Obf: KKKFCINHKNO
type UpdateRedPointNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RedPointList []*RedPointData `protobuf:"bytes,2,rep,name=red_point_list,json=redPointList,proto3" json:"red_point_list,omitempty"`
}

func (x *UpdateRedPointNotify) Reset() {
	*x = UpdateRedPointNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_UpdateRedPointNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateRedPointNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateRedPointNotify) ProtoMessage() {}

func (x *UpdateRedPointNotify) ProtoReflect() protoreflect.Message {
	mi := &file_UpdateRedPointNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateRedPointNotify.ProtoReflect.Descriptor instead.
func (*UpdateRedPointNotify) Descriptor() ([]byte, []int) {
	return file_UpdateRedPointNotify_proto_rawDescGZIP(), []int{0}
}

func (x *UpdateRedPointNotify) GetRedPointList() []*RedPointData {
	if x != nil {
		return x.RedPointList
	}
	return nil
}

var File_UpdateRedPointNotify_proto protoreflect.FileDescriptor

var file_UpdateRedPointNotify_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x64, 0x50, 0x6f, 0x69, 0x6e, 0x74,
	0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x52, 0x65,
	0x64, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x4b, 0x0a, 0x14, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x52, 0x65, 0x64, 0x50, 0x6f, 0x69,
	0x6e, 0x74, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x33, 0x0a, 0x0e, 0x72, 0x65, 0x64, 0x5f,
	0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x0d, 0x2e, 0x52, 0x65, 0x64, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x44, 0x61, 0x74, 0x61, 0x52,
	0x0c, 0x72, 0x65, 0x64, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a,
	0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_UpdateRedPointNotify_proto_rawDescOnce sync.Once
	file_UpdateRedPointNotify_proto_rawDescData = file_UpdateRedPointNotify_proto_rawDesc
)

func file_UpdateRedPointNotify_proto_rawDescGZIP() []byte {
	file_UpdateRedPointNotify_proto_rawDescOnce.Do(func() {
		file_UpdateRedPointNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_UpdateRedPointNotify_proto_rawDescData)
	})
	return file_UpdateRedPointNotify_proto_rawDescData
}

var file_UpdateRedPointNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_UpdateRedPointNotify_proto_goTypes = []interface{}{
	(*UpdateRedPointNotify)(nil), // 0: UpdateRedPointNotify
	(*RedPointData)(nil),         // 1: RedPointData
}
var file_UpdateRedPointNotify_proto_depIdxs = []int32{
	1, // 0: UpdateRedPointNotify.red_point_list:type_name -> RedPointData
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_UpdateRedPointNotify_proto_init() }
func file_UpdateRedPointNotify_proto_init() {
	if File_UpdateRedPointNotify_proto != nil {
		return
	}
	file_RedPointData_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_UpdateRedPointNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateRedPointNotify); i {
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
			RawDescriptor: file_UpdateRedPointNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_UpdateRedPointNotify_proto_goTypes,
		DependencyIndexes: file_UpdateRedPointNotify_proto_depIdxs,
		MessageInfos:      file_UpdateRedPointNotify_proto_msgTypes,
	}.Build()
	File_UpdateRedPointNotify_proto = out.File
	file_UpdateRedPointNotify_proto_rawDesc = nil
	file_UpdateRedPointNotify_proto_goTypes = nil
	file_UpdateRedPointNotify_proto_depIdxs = nil
}
