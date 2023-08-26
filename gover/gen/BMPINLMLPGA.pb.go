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
// source: BMPINLMLPGA.proto

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

type BMPINLMLPGA struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	APCFHCPFONE []uint32 `protobuf:"varint,15,rep,packed,name=APCFHCPFONE,proto3" json:"APCFHCPFONE,omitempty"`
	JLMBMDACMEN bool     `protobuf:"varint,3,opt,name=JLMBMDACMEN,proto3" json:"JLMBMDACMEN,omitempty"`
	Name        string   `protobuf:"bytes,6,opt,name=name,proto3" json:"name,omitempty"`
	CardList    []uint32 `protobuf:"varint,5,rep,packed,name=card_list,json=cardList,proto3" json:"card_list,omitempty"`
}

func (x *BMPINLMLPGA) Reset() {
	*x = BMPINLMLPGA{}
	if protoimpl.UnsafeEnabled {
		mi := &file_BMPINLMLPGA_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BMPINLMLPGA) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BMPINLMLPGA) ProtoMessage() {}

func (x *BMPINLMLPGA) ProtoReflect() protoreflect.Message {
	mi := &file_BMPINLMLPGA_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BMPINLMLPGA.ProtoReflect.Descriptor instead.
func (*BMPINLMLPGA) Descriptor() ([]byte, []int) {
	return file_BMPINLMLPGA_proto_rawDescGZIP(), []int{0}
}

func (x *BMPINLMLPGA) GetAPCFHCPFONE() []uint32 {
	if x != nil {
		return x.APCFHCPFONE
	}
	return nil
}

func (x *BMPINLMLPGA) GetJLMBMDACMEN() bool {
	if x != nil {
		return x.JLMBMDACMEN
	}
	return false
}

func (x *BMPINLMLPGA) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *BMPINLMLPGA) GetCardList() []uint32 {
	if x != nil {
		return x.CardList
	}
	return nil
}

var File_BMPINLMLPGA_proto protoreflect.FileDescriptor

var file_BMPINLMLPGA_proto_rawDesc = []byte{
	0x0a, 0x11, 0x42, 0x4d, 0x50, 0x49, 0x4e, 0x4c, 0x4d, 0x4c, 0x50, 0x47, 0x41, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x82, 0x01, 0x0a, 0x0b, 0x42, 0x4d, 0x50, 0x49, 0x4e, 0x4c, 0x4d, 0x4c,
	0x50, 0x47, 0x41, 0x12, 0x20, 0x0a, 0x0b, 0x41, 0x50, 0x43, 0x46, 0x48, 0x43, 0x50, 0x46, 0x4f,
	0x4e, 0x45, 0x18, 0x0f, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b, 0x41, 0x50, 0x43, 0x46, 0x48, 0x43,
	0x50, 0x46, 0x4f, 0x4e, 0x45, 0x12, 0x20, 0x0a, 0x0b, 0x4a, 0x4c, 0x4d, 0x42, 0x4d, 0x44, 0x41,
	0x43, 0x4d, 0x45, 0x4e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x4a, 0x4c, 0x4d, 0x42,
	0x4d, 0x44, 0x41, 0x43, 0x4d, 0x45, 0x4e, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x63,
	0x61, 0x72, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x08,
	0x63, 0x61, 0x72, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_BMPINLMLPGA_proto_rawDescOnce sync.Once
	file_BMPINLMLPGA_proto_rawDescData = file_BMPINLMLPGA_proto_rawDesc
)

func file_BMPINLMLPGA_proto_rawDescGZIP() []byte {
	file_BMPINLMLPGA_proto_rawDescOnce.Do(func() {
		file_BMPINLMLPGA_proto_rawDescData = protoimpl.X.CompressGZIP(file_BMPINLMLPGA_proto_rawDescData)
	})
	return file_BMPINLMLPGA_proto_rawDescData
}

var file_BMPINLMLPGA_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_BMPINLMLPGA_proto_goTypes = []interface{}{
	(*BMPINLMLPGA)(nil), // 0: BMPINLMLPGA
}
var file_BMPINLMLPGA_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_BMPINLMLPGA_proto_init() }
func file_BMPINLMLPGA_proto_init() {
	if File_BMPINLMLPGA_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_BMPINLMLPGA_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BMPINLMLPGA); i {
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
			RawDescriptor: file_BMPINLMLPGA_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_BMPINLMLPGA_proto_goTypes,
		DependencyIndexes: file_BMPINLMLPGA_proto_depIdxs,
		MessageInfos:      file_BMPINLMLPGA_proto_msgTypes,
	}.Build()
	File_BMPINLMLPGA_proto = out.File
	file_BMPINLMLPGA_proto_rawDesc = nil
	file_BMPINLMLPGA_proto_goTypes = nil
	file_BMPINLMLPGA_proto_depIdxs = nil
}
