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
// source: DNEOEKMJMCD.proto

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

// CmdId: 22983
type DNEOEKMJMCD struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LIKPJDFKCNL *EKNAGCJENKA `protobuf:"bytes,3,opt,name=LIKPJDFKCNL,proto3" json:"LIKPJDFKCNL,omitempty"`
	JKMHAAFINEL bool         `protobuf:"varint,8,opt,name=JKMHAAFINEL,proto3" json:"JKMHAAFINEL,omitempty"`
}

func (x *DNEOEKMJMCD) Reset() {
	*x = DNEOEKMJMCD{}
	if protoimpl.UnsafeEnabled {
		mi := &file_DNEOEKMJMCD_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DNEOEKMJMCD) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DNEOEKMJMCD) ProtoMessage() {}

func (x *DNEOEKMJMCD) ProtoReflect() protoreflect.Message {
	mi := &file_DNEOEKMJMCD_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DNEOEKMJMCD.ProtoReflect.Descriptor instead.
func (*DNEOEKMJMCD) Descriptor() ([]byte, []int) {
	return file_DNEOEKMJMCD_proto_rawDescGZIP(), []int{0}
}

func (x *DNEOEKMJMCD) GetLIKPJDFKCNL() *EKNAGCJENKA {
	if x != nil {
		return x.LIKPJDFKCNL
	}
	return nil
}

func (x *DNEOEKMJMCD) GetJKMHAAFINEL() bool {
	if x != nil {
		return x.JKMHAAFINEL
	}
	return false
}

var File_DNEOEKMJMCD_proto protoreflect.FileDescriptor

var file_DNEOEKMJMCD_proto_rawDesc = []byte{
	0x0a, 0x11, 0x44, 0x4e, 0x45, 0x4f, 0x45, 0x4b, 0x4d, 0x4a, 0x4d, 0x43, 0x44, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x45, 0x4b, 0x4e, 0x41, 0x47, 0x43, 0x4a, 0x45, 0x4e, 0x4b, 0x41,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5f, 0x0a, 0x0b, 0x44, 0x4e, 0x45, 0x4f, 0x45, 0x4b,
	0x4d, 0x4a, 0x4d, 0x43, 0x44, 0x12, 0x2e, 0x0a, 0x0b, 0x4c, 0x49, 0x4b, 0x50, 0x4a, 0x44, 0x46,
	0x4b, 0x43, 0x4e, 0x4c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x45, 0x4b, 0x4e,
	0x41, 0x47, 0x43, 0x4a, 0x45, 0x4e, 0x4b, 0x41, 0x52, 0x0b, 0x4c, 0x49, 0x4b, 0x50, 0x4a, 0x44,
	0x46, 0x4b, 0x43, 0x4e, 0x4c, 0x12, 0x20, 0x0a, 0x0b, 0x4a, 0x4b, 0x4d, 0x48, 0x41, 0x41, 0x46,
	0x49, 0x4e, 0x45, 0x4c, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x4a, 0x4b, 0x4d, 0x48,
	0x41, 0x41, 0x46, 0x49, 0x4e, 0x45, 0x4c, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_DNEOEKMJMCD_proto_rawDescOnce sync.Once
	file_DNEOEKMJMCD_proto_rawDescData = file_DNEOEKMJMCD_proto_rawDesc
)

func file_DNEOEKMJMCD_proto_rawDescGZIP() []byte {
	file_DNEOEKMJMCD_proto_rawDescOnce.Do(func() {
		file_DNEOEKMJMCD_proto_rawDescData = protoimpl.X.CompressGZIP(file_DNEOEKMJMCD_proto_rawDescData)
	})
	return file_DNEOEKMJMCD_proto_rawDescData
}

var file_DNEOEKMJMCD_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_DNEOEKMJMCD_proto_goTypes = []interface{}{
	(*DNEOEKMJMCD)(nil), // 0: DNEOEKMJMCD
	(*EKNAGCJENKA)(nil), // 1: EKNAGCJENKA
}
var file_DNEOEKMJMCD_proto_depIdxs = []int32{
	1, // 0: DNEOEKMJMCD.LIKPJDFKCNL:type_name -> EKNAGCJENKA
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_DNEOEKMJMCD_proto_init() }
func file_DNEOEKMJMCD_proto_init() {
	if File_DNEOEKMJMCD_proto != nil {
		return
	}
	file_EKNAGCJENKA_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_DNEOEKMJMCD_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DNEOEKMJMCD); i {
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
			RawDescriptor: file_DNEOEKMJMCD_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DNEOEKMJMCD_proto_goTypes,
		DependencyIndexes: file_DNEOEKMJMCD_proto_depIdxs,
		MessageInfos:      file_DNEOEKMJMCD_proto_msgTypes,
	}.Build()
	File_DNEOEKMJMCD_proto = out.File
	file_DNEOEKMJMCD_proto_rawDesc = nil
	file_DNEOEKMJMCD_proto_goTypes = nil
	file_DNEOEKMJMCD_proto_depIdxs = nil
}
