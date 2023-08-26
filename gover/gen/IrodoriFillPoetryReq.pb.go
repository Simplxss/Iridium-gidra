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
// source: IrodoriFillPoetryReq.proto

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

// CmdId: 20277
// Obf: BPMHNEIEFHH
type IrodoriFillPoetryReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AJONPJMNANN uint32 `protobuf:"varint,9,opt,name=AJONPJMNANN,proto3" json:"AJONPJMNANN,omitempty"`
	EMLHNOHEBLA uint32 `protobuf:"varint,3,opt,name=EMLHNOHEBLA,proto3" json:"EMLHNOHEBLA,omitempty"`
}

func (x *IrodoriFillPoetryReq) Reset() {
	*x = IrodoriFillPoetryReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_IrodoriFillPoetryReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IrodoriFillPoetryReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IrodoriFillPoetryReq) ProtoMessage() {}

func (x *IrodoriFillPoetryReq) ProtoReflect() protoreflect.Message {
	mi := &file_IrodoriFillPoetryReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IrodoriFillPoetryReq.ProtoReflect.Descriptor instead.
func (*IrodoriFillPoetryReq) Descriptor() ([]byte, []int) {
	return file_IrodoriFillPoetryReq_proto_rawDescGZIP(), []int{0}
}

func (x *IrodoriFillPoetryReq) GetAJONPJMNANN() uint32 {
	if x != nil {
		return x.AJONPJMNANN
	}
	return 0
}

func (x *IrodoriFillPoetryReq) GetEMLHNOHEBLA() uint32 {
	if x != nil {
		return x.EMLHNOHEBLA
	}
	return 0
}

var File_IrodoriFillPoetryReq_proto protoreflect.FileDescriptor

var file_IrodoriFillPoetryReq_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x46, 0x69, 0x6c, 0x6c, 0x50, 0x6f, 0x65,
	0x74, 0x72, 0x79, 0x52, 0x65, 0x71, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5a, 0x0a, 0x14,
	0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x46, 0x69, 0x6c, 0x6c, 0x50, 0x6f, 0x65, 0x74, 0x72,
	0x79, 0x52, 0x65, 0x71, 0x12, 0x20, 0x0a, 0x0b, 0x41, 0x4a, 0x4f, 0x4e, 0x50, 0x4a, 0x4d, 0x4e,
	0x41, 0x4e, 0x4e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x41, 0x4a, 0x4f, 0x4e, 0x50,
	0x4a, 0x4d, 0x4e, 0x41, 0x4e, 0x4e, 0x12, 0x20, 0x0a, 0x0b, 0x45, 0x4d, 0x4c, 0x48, 0x4e, 0x4f,
	0x48, 0x45, 0x42, 0x4c, 0x41, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x45, 0x4d, 0x4c,
	0x48, 0x4e, 0x4f, 0x48, 0x45, 0x42, 0x4c, 0x41, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_IrodoriFillPoetryReq_proto_rawDescOnce sync.Once
	file_IrodoriFillPoetryReq_proto_rawDescData = file_IrodoriFillPoetryReq_proto_rawDesc
)

func file_IrodoriFillPoetryReq_proto_rawDescGZIP() []byte {
	file_IrodoriFillPoetryReq_proto_rawDescOnce.Do(func() {
		file_IrodoriFillPoetryReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_IrodoriFillPoetryReq_proto_rawDescData)
	})
	return file_IrodoriFillPoetryReq_proto_rawDescData
}

var file_IrodoriFillPoetryReq_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_IrodoriFillPoetryReq_proto_goTypes = []interface{}{
	(*IrodoriFillPoetryReq)(nil), // 0: IrodoriFillPoetryReq
}
var file_IrodoriFillPoetryReq_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_IrodoriFillPoetryReq_proto_init() }
func file_IrodoriFillPoetryReq_proto_init() {
	if File_IrodoriFillPoetryReq_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_IrodoriFillPoetryReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IrodoriFillPoetryReq); i {
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
			RawDescriptor: file_IrodoriFillPoetryReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_IrodoriFillPoetryReq_proto_goTypes,
		DependencyIndexes: file_IrodoriFillPoetryReq_proto_depIdxs,
		MessageInfos:      file_IrodoriFillPoetryReq_proto_msgTypes,
	}.Build()
	File_IrodoriFillPoetryReq_proto = out.File
	file_IrodoriFillPoetryReq_proto_rawDesc = nil
	file_IrodoriFillPoetryReq_proto_goTypes = nil
	file_IrodoriFillPoetryReq_proto_depIdxs = nil
}
