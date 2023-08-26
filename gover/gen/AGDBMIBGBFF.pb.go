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
// source: AGDBMIBGBFF.proto

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

// CmdId: 20407
type AGDBMIBGBFF struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HJMAPBBEKMD bool `protobuf:"varint,4,opt,name=HJMAPBBEKMD,proto3" json:"HJMAPBBEKMD,omitempty"`
	IHGOBANMPLI bool `protobuf:"varint,7,opt,name=IHGOBANMPLI,proto3" json:"IHGOBANMPLI,omitempty"`
}

func (x *AGDBMIBGBFF) Reset() {
	*x = AGDBMIBGBFF{}
	if protoimpl.UnsafeEnabled {
		mi := &file_AGDBMIBGBFF_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AGDBMIBGBFF) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AGDBMIBGBFF) ProtoMessage() {}

func (x *AGDBMIBGBFF) ProtoReflect() protoreflect.Message {
	mi := &file_AGDBMIBGBFF_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AGDBMIBGBFF.ProtoReflect.Descriptor instead.
func (*AGDBMIBGBFF) Descriptor() ([]byte, []int) {
	return file_AGDBMIBGBFF_proto_rawDescGZIP(), []int{0}
}

func (x *AGDBMIBGBFF) GetHJMAPBBEKMD() bool {
	if x != nil {
		return x.HJMAPBBEKMD
	}
	return false
}

func (x *AGDBMIBGBFF) GetIHGOBANMPLI() bool {
	if x != nil {
		return x.IHGOBANMPLI
	}
	return false
}

var File_AGDBMIBGBFF_proto protoreflect.FileDescriptor

var file_AGDBMIBGBFF_proto_rawDesc = []byte{
	0x0a, 0x11, 0x41, 0x47, 0x44, 0x42, 0x4d, 0x49, 0x42, 0x47, 0x42, 0x46, 0x46, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x51, 0x0a, 0x0b, 0x41, 0x47, 0x44, 0x42, 0x4d, 0x49, 0x42, 0x47, 0x42,
	0x46, 0x46, 0x12, 0x20, 0x0a, 0x0b, 0x48, 0x4a, 0x4d, 0x41, 0x50, 0x42, 0x42, 0x45, 0x4b, 0x4d,
	0x44, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x48, 0x4a, 0x4d, 0x41, 0x50, 0x42, 0x42,
	0x45, 0x4b, 0x4d, 0x44, 0x12, 0x20, 0x0a, 0x0b, 0x49, 0x48, 0x47, 0x4f, 0x42, 0x41, 0x4e, 0x4d,
	0x50, 0x4c, 0x49, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x49, 0x48, 0x47, 0x4f, 0x42,
	0x41, 0x4e, 0x4d, 0x50, 0x4c, 0x49, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_AGDBMIBGBFF_proto_rawDescOnce sync.Once
	file_AGDBMIBGBFF_proto_rawDescData = file_AGDBMIBGBFF_proto_rawDesc
)

func file_AGDBMIBGBFF_proto_rawDescGZIP() []byte {
	file_AGDBMIBGBFF_proto_rawDescOnce.Do(func() {
		file_AGDBMIBGBFF_proto_rawDescData = protoimpl.X.CompressGZIP(file_AGDBMIBGBFF_proto_rawDescData)
	})
	return file_AGDBMIBGBFF_proto_rawDescData
}

var file_AGDBMIBGBFF_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_AGDBMIBGBFF_proto_goTypes = []interface{}{
	(*AGDBMIBGBFF)(nil), // 0: AGDBMIBGBFF
}
var file_AGDBMIBGBFF_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_AGDBMIBGBFF_proto_init() }
func file_AGDBMIBGBFF_proto_init() {
	if File_AGDBMIBGBFF_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_AGDBMIBGBFF_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AGDBMIBGBFF); i {
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
			RawDescriptor: file_AGDBMIBGBFF_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_AGDBMIBGBFF_proto_goTypes,
		DependencyIndexes: file_AGDBMIBGBFF_proto_depIdxs,
		MessageInfos:      file_AGDBMIBGBFF_proto_msgTypes,
	}.Build()
	File_AGDBMIBGBFF_proto = out.File
	file_AGDBMIBGBFF_proto_rawDesc = nil
	file_AGDBMIBGBFF_proto_goTypes = nil
	file_AGDBMIBGBFF_proto_depIdxs = nil
}
