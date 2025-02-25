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
// source: NLKOBHJEMJD.proto

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

type NLKOBHJEMJD struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JPEOGIEOGKE []*MDEBKDGFKOM `protobuf:"bytes,2,rep,name=JPEOGIEOGKE,proto3" json:"JPEOGIEOGKE,omitempty"`
	DLAJODFOCMG []uint32       `protobuf:"varint,10,rep,packed,name=DLAJODFOCMG,proto3" json:"DLAJODFOCMG,omitempty"`
	KAJLKLICGBN uint32         `protobuf:"varint,14,opt,name=KAJLKLICGBN,proto3" json:"KAJLKLICGBN,omitempty"`
}

func (x *NLKOBHJEMJD) Reset() {
	*x = NLKOBHJEMJD{}
	if protoimpl.UnsafeEnabled {
		mi := &file_NLKOBHJEMJD_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NLKOBHJEMJD) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NLKOBHJEMJD) ProtoMessage() {}

func (x *NLKOBHJEMJD) ProtoReflect() protoreflect.Message {
	mi := &file_NLKOBHJEMJD_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NLKOBHJEMJD.ProtoReflect.Descriptor instead.
func (*NLKOBHJEMJD) Descriptor() ([]byte, []int) {
	return file_NLKOBHJEMJD_proto_rawDescGZIP(), []int{0}
}

func (x *NLKOBHJEMJD) GetJPEOGIEOGKE() []*MDEBKDGFKOM {
	if x != nil {
		return x.JPEOGIEOGKE
	}
	return nil
}

func (x *NLKOBHJEMJD) GetDLAJODFOCMG() []uint32 {
	if x != nil {
		return x.DLAJODFOCMG
	}
	return nil
}

func (x *NLKOBHJEMJD) GetKAJLKLICGBN() uint32 {
	if x != nil {
		return x.KAJLKLICGBN
	}
	return 0
}

var File_NLKOBHJEMJD_proto protoreflect.FileDescriptor

var file_NLKOBHJEMJD_proto_rawDesc = []byte{
	0x0a, 0x11, 0x4e, 0x4c, 0x4b, 0x4f, 0x42, 0x48, 0x4a, 0x45, 0x4d, 0x4a, 0x44, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x4d, 0x44, 0x45, 0x42, 0x4b, 0x44, 0x47, 0x46, 0x4b, 0x4f, 0x4d,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x81, 0x01, 0x0a, 0x0b, 0x4e, 0x4c, 0x4b, 0x4f, 0x42,
	0x48, 0x4a, 0x45, 0x4d, 0x4a, 0x44, 0x12, 0x2e, 0x0a, 0x0b, 0x4a, 0x50, 0x45, 0x4f, 0x47, 0x49,
	0x45, 0x4f, 0x47, 0x4b, 0x45, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x4d, 0x44,
	0x45, 0x42, 0x4b, 0x44, 0x47, 0x46, 0x4b, 0x4f, 0x4d, 0x52, 0x0b, 0x4a, 0x50, 0x45, 0x4f, 0x47,
	0x49, 0x45, 0x4f, 0x47, 0x4b, 0x45, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x4c, 0x41, 0x4a, 0x4f, 0x44,
	0x46, 0x4f, 0x43, 0x4d, 0x47, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b, 0x44, 0x4c, 0x41,
	0x4a, 0x4f, 0x44, 0x46, 0x4f, 0x43, 0x4d, 0x47, 0x12, 0x20, 0x0a, 0x0b, 0x4b, 0x41, 0x4a, 0x4c,
	0x4b, 0x4c, 0x49, 0x43, 0x47, 0x42, 0x4e, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4b,
	0x41, 0x4a, 0x4c, 0x4b, 0x4c, 0x49, 0x43, 0x47, 0x42, 0x4e, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_NLKOBHJEMJD_proto_rawDescOnce sync.Once
	file_NLKOBHJEMJD_proto_rawDescData = file_NLKOBHJEMJD_proto_rawDesc
)

func file_NLKOBHJEMJD_proto_rawDescGZIP() []byte {
	file_NLKOBHJEMJD_proto_rawDescOnce.Do(func() {
		file_NLKOBHJEMJD_proto_rawDescData = protoimpl.X.CompressGZIP(file_NLKOBHJEMJD_proto_rawDescData)
	})
	return file_NLKOBHJEMJD_proto_rawDescData
}

var file_NLKOBHJEMJD_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_NLKOBHJEMJD_proto_goTypes = []interface{}{
	(*NLKOBHJEMJD)(nil), // 0: NLKOBHJEMJD
	(*MDEBKDGFKOM)(nil), // 1: MDEBKDGFKOM
}
var file_NLKOBHJEMJD_proto_depIdxs = []int32{
	1, // 0: NLKOBHJEMJD.JPEOGIEOGKE:type_name -> MDEBKDGFKOM
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_NLKOBHJEMJD_proto_init() }
func file_NLKOBHJEMJD_proto_init() {
	if File_NLKOBHJEMJD_proto != nil {
		return
	}
	file_MDEBKDGFKOM_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_NLKOBHJEMJD_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NLKOBHJEMJD); i {
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
			RawDescriptor: file_NLKOBHJEMJD_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_NLKOBHJEMJD_proto_goTypes,
		DependencyIndexes: file_NLKOBHJEMJD_proto_depIdxs,
		MessageInfos:      file_NLKOBHJEMJD_proto_msgTypes,
	}.Build()
	File_NLKOBHJEMJD_proto = out.File
	file_NLKOBHJEMJD_proto_rawDesc = nil
	file_NLKOBHJEMJD_proto_goTypes = nil
	file_NLKOBHJEMJD_proto_depIdxs = nil
}
