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
// source: GDABJFALFDK.proto

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

// CmdId: 6125
type GDABJFALFDK struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Center *Vector `protobuf:"bytes,2,opt,name=center,proto3" json:"center,omitempty"`
	Extent *Vector `protobuf:"bytes,9,opt,name=extent,proto3" json:"extent,omitempty"`
	Uid    int32   `protobuf:"varint,1,opt,name=uid,proto3" json:"uid,omitempty"`
}

func (x *GDABJFALFDK) Reset() {
	*x = GDABJFALFDK{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GDABJFALFDK_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GDABJFALFDK) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GDABJFALFDK) ProtoMessage() {}

func (x *GDABJFALFDK) ProtoReflect() protoreflect.Message {
	mi := &file_GDABJFALFDK_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GDABJFALFDK.ProtoReflect.Descriptor instead.
func (*GDABJFALFDK) Descriptor() ([]byte, []int) {
	return file_GDABJFALFDK_proto_rawDescGZIP(), []int{0}
}

func (x *GDABJFALFDK) GetCenter() *Vector {
	if x != nil {
		return x.Center
	}
	return nil
}

func (x *GDABJFALFDK) GetExtent() *Vector {
	if x != nil {
		return x.Extent
	}
	return nil
}

func (x *GDABJFALFDK) GetUid() int32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

var File_GDABJFALFDK_proto protoreflect.FileDescriptor

var file_GDABJFALFDK_proto_rawDesc = []byte{
	0x0a, 0x11, 0x47, 0x44, 0x41, 0x42, 0x4a, 0x46, 0x41, 0x4c, 0x46, 0x44, 0x4b, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x61, 0x0a, 0x0b, 0x47, 0x44, 0x41, 0x42, 0x4a, 0x46, 0x41, 0x4c, 0x46, 0x44, 0x4b,
	0x12, 0x1f, 0x0a, 0x06, 0x63, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x06, 0x63, 0x65, 0x6e, 0x74, 0x65,
	0x72, 0x12, 0x1f, 0x0a, 0x06, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x06, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x03, 0x75, 0x69, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GDABJFALFDK_proto_rawDescOnce sync.Once
	file_GDABJFALFDK_proto_rawDescData = file_GDABJFALFDK_proto_rawDesc
)

func file_GDABJFALFDK_proto_rawDescGZIP() []byte {
	file_GDABJFALFDK_proto_rawDescOnce.Do(func() {
		file_GDABJFALFDK_proto_rawDescData = protoimpl.X.CompressGZIP(file_GDABJFALFDK_proto_rawDescData)
	})
	return file_GDABJFALFDK_proto_rawDescData
}

var file_GDABJFALFDK_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GDABJFALFDK_proto_goTypes = []interface{}{
	(*GDABJFALFDK)(nil), // 0: GDABJFALFDK
	(*Vector)(nil),      // 1: Vector
}
var file_GDABJFALFDK_proto_depIdxs = []int32{
	1, // 0: GDABJFALFDK.center:type_name -> Vector
	1, // 1: GDABJFALFDK.extent:type_name -> Vector
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_GDABJFALFDK_proto_init() }
func file_GDABJFALFDK_proto_init() {
	if File_GDABJFALFDK_proto != nil {
		return
	}
	file_Vector_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GDABJFALFDK_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GDABJFALFDK); i {
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
			RawDescriptor: file_GDABJFALFDK_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GDABJFALFDK_proto_goTypes,
		DependencyIndexes: file_GDABJFALFDK_proto_depIdxs,
		MessageInfos:      file_GDABJFALFDK_proto_msgTypes,
	}.Build()
	File_GDABJFALFDK_proto = out.File
	file_GDABJFALFDK_proto_rawDesc = nil
	file_GDABJFALFDK_proto_goTypes = nil
	file_GDABJFALFDK_proto_depIdxs = nil
}
