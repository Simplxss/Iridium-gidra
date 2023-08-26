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
// source: CPBCJBADPPD.proto

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

// CmdId: 6196
type CPBCJBADPPD struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DNHAMFJMLJB []int32        `protobuf:"varint,9,rep,packed,name=DNHAMFJMLJB,proto3" json:"DNHAMFJMLJB,omitempty"`
	Nodes       []*JNNOKDHCAMP `protobuf:"bytes,7,rep,name=nodes,proto3" json:"nodes,omitempty"`
	Retcode     int32          `protobuf:"varint,8,opt,name=retcode,proto3" json:"retcode,omitempty"`
}

func (x *CPBCJBADPPD) Reset() {
	*x = CPBCJBADPPD{}
	if protoimpl.UnsafeEnabled {
		mi := &file_CPBCJBADPPD_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CPBCJBADPPD) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CPBCJBADPPD) ProtoMessage() {}

func (x *CPBCJBADPPD) ProtoReflect() protoreflect.Message {
	mi := &file_CPBCJBADPPD_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CPBCJBADPPD.ProtoReflect.Descriptor instead.
func (*CPBCJBADPPD) Descriptor() ([]byte, []int) {
	return file_CPBCJBADPPD_proto_rawDescGZIP(), []int{0}
}

func (x *CPBCJBADPPD) GetDNHAMFJMLJB() []int32 {
	if x != nil {
		return x.DNHAMFJMLJB
	}
	return nil
}

func (x *CPBCJBADPPD) GetNodes() []*JNNOKDHCAMP {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *CPBCJBADPPD) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

var File_CPBCJBADPPD_proto protoreflect.FileDescriptor

var file_CPBCJBADPPD_proto_rawDesc = []byte{
	0x0a, 0x11, 0x43, 0x50, 0x42, 0x43, 0x4a, 0x42, 0x41, 0x44, 0x50, 0x50, 0x44, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x4a, 0x4e, 0x4e, 0x4f, 0x4b, 0x44, 0x48, 0x43, 0x41, 0x4d, 0x50,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x6d, 0x0a, 0x0b, 0x43, 0x50, 0x42, 0x43, 0x4a, 0x42,
	0x41, 0x44, 0x50, 0x50, 0x44, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x4e, 0x48, 0x41, 0x4d, 0x46, 0x4a,
	0x4d, 0x4c, 0x4a, 0x42, 0x18, 0x09, 0x20, 0x03, 0x28, 0x05, 0x52, 0x0b, 0x44, 0x4e, 0x48, 0x41,
	0x4d, 0x46, 0x4a, 0x4d, 0x4c, 0x4a, 0x42, 0x12, 0x22, 0x0a, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73,
	0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x4a, 0x4e, 0x4e, 0x4f, 0x4b, 0x44, 0x48,
	0x43, 0x41, 0x4d, 0x50, 0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x72,
	0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07, 0x72, 0x65,
	0x74, 0x63, 0x6f, 0x64, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_CPBCJBADPPD_proto_rawDescOnce sync.Once
	file_CPBCJBADPPD_proto_rawDescData = file_CPBCJBADPPD_proto_rawDesc
)

func file_CPBCJBADPPD_proto_rawDescGZIP() []byte {
	file_CPBCJBADPPD_proto_rawDescOnce.Do(func() {
		file_CPBCJBADPPD_proto_rawDescData = protoimpl.X.CompressGZIP(file_CPBCJBADPPD_proto_rawDescData)
	})
	return file_CPBCJBADPPD_proto_rawDescData
}

var file_CPBCJBADPPD_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_CPBCJBADPPD_proto_goTypes = []interface{}{
	(*CPBCJBADPPD)(nil), // 0: CPBCJBADPPD
	(*JNNOKDHCAMP)(nil), // 1: JNNOKDHCAMP
}
var file_CPBCJBADPPD_proto_depIdxs = []int32{
	1, // 0: CPBCJBADPPD.nodes:type_name -> JNNOKDHCAMP
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_CPBCJBADPPD_proto_init() }
func file_CPBCJBADPPD_proto_init() {
	if File_CPBCJBADPPD_proto != nil {
		return
	}
	file_JNNOKDHCAMP_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_CPBCJBADPPD_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CPBCJBADPPD); i {
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
			RawDescriptor: file_CPBCJBADPPD_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_CPBCJBADPPD_proto_goTypes,
		DependencyIndexes: file_CPBCJBADPPD_proto_depIdxs,
		MessageInfos:      file_CPBCJBADPPD_proto_msgTypes,
	}.Build()
	File_CPBCJBADPPD_proto = out.File
	file_CPBCJBADPPD_proto_rawDesc = nil
	file_CPBCJBADPPD_proto_goTypes = nil
	file_CPBCJBADPPD_proto_depIdxs = nil
}
