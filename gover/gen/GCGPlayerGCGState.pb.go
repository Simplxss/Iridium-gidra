// Sorapointa - A server software re-implementation for a certain anime game, and avoid sorapointa.
// Copyright (C) 2022  Sorapointa Team
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
// 	protoc        v3.11.3
// source: GCGPlayerGCGState.proto

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

type GCGPlayerGCGState struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uid                 uint32 `protobuf:"varint,14,opt,name=uid,proto3" json:"uid,omitempty"`
	Unk3300_GIKOMFNNAAA bool   `protobuf:"varint,11,opt,name=Unk3300_GIKOMFNNAAA,json=Unk3300GIKOMFNNAAA,proto3" json:"Unk3300_GIKOMFNNAAA,omitempty"`
	Unk3300_DEKGMKCCGEG bool   `protobuf:"varint,4,opt,name=Unk3300_DEKGMKCCGEG,json=Unk3300DEKGMKCCGEG,proto3" json:"Unk3300_DEKGMKCCGEG,omitempty"`
}

func (x *GCGPlayerGCGState) Reset() {
	*x = GCGPlayerGCGState{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGPlayerGCGState_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGPlayerGCGState) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGPlayerGCGState) ProtoMessage() {}

func (x *GCGPlayerGCGState) ProtoReflect() protoreflect.Message {
	mi := &file_GCGPlayerGCGState_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGPlayerGCGState.ProtoReflect.Descriptor instead.
func (*GCGPlayerGCGState) Descriptor() ([]byte, []int) {
	return file_GCGPlayerGCGState_proto_rawDescGZIP(), []int{0}
}

func (x *GCGPlayerGCGState) GetUid() uint32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

func (x *GCGPlayerGCGState) GetUnk3300_GIKOMFNNAAA() bool {
	if x != nil {
		return x.Unk3300_GIKOMFNNAAA
	}
	return false
}

func (x *GCGPlayerGCGState) GetUnk3300_DEKGMKCCGEG() bool {
	if x != nil {
		return x.Unk3300_DEKGMKCCGEG
	}
	return false
}

var File_GCGPlayerGCGState_proto protoreflect.FileDescriptor

var file_GCGPlayerGCGState_proto_rawDesc = []byte{
	0x0a, 0x17, 0x47, 0x43, 0x47, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x47, 0x43, 0x47, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x87, 0x01, 0x0a, 0x11, 0x47, 0x43,
	0x47, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x47, 0x43, 0x47, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12,
	0x10, 0x0a, 0x03, 0x75, 0x69, 0x64, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x75, 0x69,
	0x64, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x5f, 0x47, 0x49, 0x4b,
	0x4f, 0x4d, 0x46, 0x4e, 0x4e, 0x41, 0x41, 0x41, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x12,
	0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x47, 0x49, 0x4b, 0x4f, 0x4d, 0x46, 0x4e, 0x4e, 0x41,
	0x41, 0x41, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x5f, 0x44, 0x45,
	0x4b, 0x47, 0x4d, 0x4b, 0x43, 0x43, 0x47, 0x45, 0x47, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x12, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x44, 0x45, 0x4b, 0x47, 0x4d, 0x4b, 0x43, 0x43,
	0x47, 0x45, 0x47, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_GCGPlayerGCGState_proto_rawDescOnce sync.Once
	file_GCGPlayerGCGState_proto_rawDescData = file_GCGPlayerGCGState_proto_rawDesc
)

func file_GCGPlayerGCGState_proto_rawDescGZIP() []byte {
	file_GCGPlayerGCGState_proto_rawDescOnce.Do(func() {
		file_GCGPlayerGCGState_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGPlayerGCGState_proto_rawDescData)
	})
	return file_GCGPlayerGCGState_proto_rawDescData
}

var file_GCGPlayerGCGState_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGPlayerGCGState_proto_goTypes = []interface{}{
	(*GCGPlayerGCGState)(nil), // 0: GCGPlayerGCGState
}
var file_GCGPlayerGCGState_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GCGPlayerGCGState_proto_init() }
func file_GCGPlayerGCGState_proto_init() {
	if File_GCGPlayerGCGState_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_GCGPlayerGCGState_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGPlayerGCGState); i {
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
			RawDescriptor: file_GCGPlayerGCGState_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGPlayerGCGState_proto_goTypes,
		DependencyIndexes: file_GCGPlayerGCGState_proto_depIdxs,
		MessageInfos:      file_GCGPlayerGCGState_proto_msgTypes,
	}.Build()
	File_GCGPlayerGCGState_proto = out.File
	file_GCGPlayerGCGState_proto_rawDesc = nil
	file_GCGPlayerGCGState_proto_goTypes = nil
	file_GCGPlayerGCGState_proto_depIdxs = nil
}
