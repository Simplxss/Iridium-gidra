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
// source: GOICCJMDKKD.proto

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

type GOICCJMDKKD struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FMLLDLAGMEL []*JEOEFGBOPIE `protobuf:"bytes,4,rep,name=FMLLDLAGMEL,proto3" json:"FMLLDLAGMEL,omitempty"`
	CostTime    uint32         `protobuf:"varint,11,opt,name=cost_time,json=costTime,proto3" json:"cost_time,omitempty"`
	Timestamp   uint32         `protobuf:"varint,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
}

func (x *GOICCJMDKKD) Reset() {
	*x = GOICCJMDKKD{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GOICCJMDKKD_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GOICCJMDKKD) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GOICCJMDKKD) ProtoMessage() {}

func (x *GOICCJMDKKD) ProtoReflect() protoreflect.Message {
	mi := &file_GOICCJMDKKD_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GOICCJMDKKD.ProtoReflect.Descriptor instead.
func (*GOICCJMDKKD) Descriptor() ([]byte, []int) {
	return file_GOICCJMDKKD_proto_rawDescGZIP(), []int{0}
}

func (x *GOICCJMDKKD) GetFMLLDLAGMEL() []*JEOEFGBOPIE {
	if x != nil {
		return x.FMLLDLAGMEL
	}
	return nil
}

func (x *GOICCJMDKKD) GetCostTime() uint32 {
	if x != nil {
		return x.CostTime
	}
	return 0
}

func (x *GOICCJMDKKD) GetTimestamp() uint32 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

var File_GOICCJMDKKD_proto protoreflect.FileDescriptor

var file_GOICCJMDKKD_proto_rawDesc = []byte{
	0x0a, 0x11, 0x47, 0x4f, 0x49, 0x43, 0x43, 0x4a, 0x4d, 0x44, 0x4b, 0x4b, 0x44, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x4a, 0x45, 0x4f, 0x45, 0x46, 0x47, 0x42, 0x4f, 0x50, 0x49, 0x45,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x78, 0x0a, 0x0b, 0x47, 0x4f, 0x49, 0x43, 0x43, 0x4a,
	0x4d, 0x44, 0x4b, 0x4b, 0x44, 0x12, 0x2e, 0x0a, 0x0b, 0x46, 0x4d, 0x4c, 0x4c, 0x44, 0x4c, 0x41,
	0x47, 0x4d, 0x45, 0x4c, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x4a, 0x45, 0x4f,
	0x45, 0x46, 0x47, 0x42, 0x4f, 0x50, 0x49, 0x45, 0x52, 0x0b, 0x46, 0x4d, 0x4c, 0x4c, 0x44, 0x4c,
	0x41, 0x47, 0x4d, 0x45, 0x4c, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6f, 0x73, 0x74, 0x5f, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x63, 0x6f, 0x73, 0x74, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GOICCJMDKKD_proto_rawDescOnce sync.Once
	file_GOICCJMDKKD_proto_rawDescData = file_GOICCJMDKKD_proto_rawDesc
)

func file_GOICCJMDKKD_proto_rawDescGZIP() []byte {
	file_GOICCJMDKKD_proto_rawDescOnce.Do(func() {
		file_GOICCJMDKKD_proto_rawDescData = protoimpl.X.CompressGZIP(file_GOICCJMDKKD_proto_rawDescData)
	})
	return file_GOICCJMDKKD_proto_rawDescData
}

var file_GOICCJMDKKD_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GOICCJMDKKD_proto_goTypes = []interface{}{
	(*GOICCJMDKKD)(nil), // 0: GOICCJMDKKD
	(*JEOEFGBOPIE)(nil), // 1: JEOEFGBOPIE
}
var file_GOICCJMDKKD_proto_depIdxs = []int32{
	1, // 0: GOICCJMDKKD.FMLLDLAGMEL:type_name -> JEOEFGBOPIE
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GOICCJMDKKD_proto_init() }
func file_GOICCJMDKKD_proto_init() {
	if File_GOICCJMDKKD_proto != nil {
		return
	}
	file_JEOEFGBOPIE_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GOICCJMDKKD_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GOICCJMDKKD); i {
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
			RawDescriptor: file_GOICCJMDKKD_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GOICCJMDKKD_proto_goTypes,
		DependencyIndexes: file_GOICCJMDKKD_proto_depIdxs,
		MessageInfos:      file_GOICCJMDKKD_proto_msgTypes,
	}.Build()
	File_GOICCJMDKKD_proto = out.File
	file_GOICCJMDKKD_proto_rawDesc = nil
	file_GOICCJMDKKD_proto_goTypes = nil
	file_GOICCJMDKKD_proto_depIdxs = nil
}
