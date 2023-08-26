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
// source: ArenaSettle.proto

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

// Obf: OLBHJJAIFOL
type ArenaSettle struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EKNOBJNNAFA uint32 `protobuf:"varint,11,opt,name=EKNOBJNNAFA,proto3" json:"EKNOBJNNAFA,omitempty"`
	JMHMBMEGDIH uint32 `protobuf:"varint,1,opt,name=JMHMBMEGDIH,proto3" json:"JMHMBMEGDIH,omitempty"`
}

func (x *ArenaSettle) Reset() {
	*x = ArenaSettle{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ArenaSettle_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ArenaSettle) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ArenaSettle) ProtoMessage() {}

func (x *ArenaSettle) ProtoReflect() protoreflect.Message {
	mi := &file_ArenaSettle_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ArenaSettle.ProtoReflect.Descriptor instead.
func (*ArenaSettle) Descriptor() ([]byte, []int) {
	return file_ArenaSettle_proto_rawDescGZIP(), []int{0}
}

func (x *ArenaSettle) GetEKNOBJNNAFA() uint32 {
	if x != nil {
		return x.EKNOBJNNAFA
	}
	return 0
}

func (x *ArenaSettle) GetJMHMBMEGDIH() uint32 {
	if x != nil {
		return x.JMHMBMEGDIH
	}
	return 0
}

var File_ArenaSettle_proto protoreflect.FileDescriptor

var file_ArenaSettle_proto_rawDesc = []byte{
	0x0a, 0x11, 0x41, 0x72, 0x65, 0x6e, 0x61, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x51, 0x0a, 0x0b, 0x41, 0x72, 0x65, 0x6e, 0x61, 0x53, 0x65, 0x74, 0x74,
	0x6c, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x45, 0x4b, 0x4e, 0x4f, 0x42, 0x4a, 0x4e, 0x4e, 0x41, 0x46,
	0x41, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x45, 0x4b, 0x4e, 0x4f, 0x42, 0x4a, 0x4e,
	0x4e, 0x41, 0x46, 0x41, 0x12, 0x20, 0x0a, 0x0b, 0x4a, 0x4d, 0x48, 0x4d, 0x42, 0x4d, 0x45, 0x47,
	0x44, 0x49, 0x48, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4a, 0x4d, 0x48, 0x4d, 0x42,
	0x4d, 0x45, 0x47, 0x44, 0x49, 0x48, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ArenaSettle_proto_rawDescOnce sync.Once
	file_ArenaSettle_proto_rawDescData = file_ArenaSettle_proto_rawDesc
)

func file_ArenaSettle_proto_rawDescGZIP() []byte {
	file_ArenaSettle_proto_rawDescOnce.Do(func() {
		file_ArenaSettle_proto_rawDescData = protoimpl.X.CompressGZIP(file_ArenaSettle_proto_rawDescData)
	})
	return file_ArenaSettle_proto_rawDescData
}

var file_ArenaSettle_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ArenaSettle_proto_goTypes = []interface{}{
	(*ArenaSettle)(nil), // 0: ArenaSettle
}
var file_ArenaSettle_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ArenaSettle_proto_init() }
func file_ArenaSettle_proto_init() {
	if File_ArenaSettle_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ArenaSettle_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ArenaSettle); i {
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
			RawDescriptor: file_ArenaSettle_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ArenaSettle_proto_goTypes,
		DependencyIndexes: file_ArenaSettle_proto_depIdxs,
		MessageInfos:      file_ArenaSettle_proto_msgTypes,
	}.Build()
	File_ArenaSettle_proto = out.File
	file_ArenaSettle_proto_rawDesc = nil
	file_ArenaSettle_proto_goTypes = nil
	file_ArenaSettle_proto_depIdxs = nil
}
