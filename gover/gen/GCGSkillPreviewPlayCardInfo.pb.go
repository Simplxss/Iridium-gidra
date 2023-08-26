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
// source: GCGSkillPreviewPlayCardInfo.proto

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

// Obf: ICPJOFEGFJA
type GCGSkillPreviewPlayCardInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OLIGHPNIHNG  uint32               `protobuf:"varint,15,opt,name=OLIGHPNIHNG,proto3" json:"OLIGHPNIHNG,omitempty"`
	CNKPKHNGILK  uint32               `protobuf:"varint,1,opt,name=CNKPKHNGILK,proto3" json:"CNKPKHNGILK,omitempty"`
	PlayCardInfo *GCGSkillPreviewInfo `protobuf:"bytes,9,opt,name=play_card_info,json=playCardInfo,proto3" json:"play_card_info,omitempty"`
}

func (x *GCGSkillPreviewPlayCardInfo) Reset() {
	*x = GCGSkillPreviewPlayCardInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGSkillPreviewPlayCardInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGSkillPreviewPlayCardInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGSkillPreviewPlayCardInfo) ProtoMessage() {}

func (x *GCGSkillPreviewPlayCardInfo) ProtoReflect() protoreflect.Message {
	mi := &file_GCGSkillPreviewPlayCardInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGSkillPreviewPlayCardInfo.ProtoReflect.Descriptor instead.
func (*GCGSkillPreviewPlayCardInfo) Descriptor() ([]byte, []int) {
	return file_GCGSkillPreviewPlayCardInfo_proto_rawDescGZIP(), []int{0}
}

func (x *GCGSkillPreviewPlayCardInfo) GetOLIGHPNIHNG() uint32 {
	if x != nil {
		return x.OLIGHPNIHNG
	}
	return 0
}

func (x *GCGSkillPreviewPlayCardInfo) GetCNKPKHNGILK() uint32 {
	if x != nil {
		return x.CNKPKHNGILK
	}
	return 0
}

func (x *GCGSkillPreviewPlayCardInfo) GetPlayCardInfo() *GCGSkillPreviewInfo {
	if x != nil {
		return x.PlayCardInfo
	}
	return nil
}

var File_GCGSkillPreviewPlayCardInfo_proto protoreflect.FileDescriptor

var file_GCGSkillPreviewPlayCardInfo_proto_rawDesc = []byte{
	0x0a, 0x21, 0x47, 0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x50, 0x6c, 0x61, 0x79, 0x43, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x47, 0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65,
	0x76, 0x69, 0x65, 0x77, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9d,
	0x01, 0x0a, 0x1b, 0x47, 0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69,
	0x65, 0x77, 0x50, 0x6c, 0x61, 0x79, 0x43, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x20,
	0x0a, 0x0b, 0x4f, 0x4c, 0x49, 0x47, 0x48, 0x50, 0x4e, 0x49, 0x48, 0x4e, 0x47, 0x18, 0x0f, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4f, 0x4c, 0x49, 0x47, 0x48, 0x50, 0x4e, 0x49, 0x48, 0x4e, 0x47,
	0x12, 0x20, 0x0a, 0x0b, 0x43, 0x4e, 0x4b, 0x50, 0x4b, 0x48, 0x4e, 0x47, 0x49, 0x4c, 0x4b, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x43, 0x4e, 0x4b, 0x50, 0x4b, 0x48, 0x4e, 0x47, 0x49,
	0x4c, 0x4b, 0x12, 0x3a, 0x0a, 0x0e, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f,
	0x69, 0x6e, 0x66, 0x6f, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x47, 0x43, 0x47,
	0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x49, 0x6e, 0x66, 0x6f,
	0x52, 0x0c, 0x70, 0x6c, 0x61, 0x79, 0x43, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x42, 0x06,
	0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGSkillPreviewPlayCardInfo_proto_rawDescOnce sync.Once
	file_GCGSkillPreviewPlayCardInfo_proto_rawDescData = file_GCGSkillPreviewPlayCardInfo_proto_rawDesc
)

func file_GCGSkillPreviewPlayCardInfo_proto_rawDescGZIP() []byte {
	file_GCGSkillPreviewPlayCardInfo_proto_rawDescOnce.Do(func() {
		file_GCGSkillPreviewPlayCardInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGSkillPreviewPlayCardInfo_proto_rawDescData)
	})
	return file_GCGSkillPreviewPlayCardInfo_proto_rawDescData
}

var file_GCGSkillPreviewPlayCardInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGSkillPreviewPlayCardInfo_proto_goTypes = []interface{}{
	(*GCGSkillPreviewPlayCardInfo)(nil), // 0: GCGSkillPreviewPlayCardInfo
	(*GCGSkillPreviewInfo)(nil),         // 1: GCGSkillPreviewInfo
}
var file_GCGSkillPreviewPlayCardInfo_proto_depIdxs = []int32{
	1, // 0: GCGSkillPreviewPlayCardInfo.play_card_info:type_name -> GCGSkillPreviewInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GCGSkillPreviewPlayCardInfo_proto_init() }
func file_GCGSkillPreviewPlayCardInfo_proto_init() {
	if File_GCGSkillPreviewPlayCardInfo_proto != nil {
		return
	}
	file_GCGSkillPreviewInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GCGSkillPreviewPlayCardInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGSkillPreviewPlayCardInfo); i {
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
			RawDescriptor: file_GCGSkillPreviewPlayCardInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGSkillPreviewPlayCardInfo_proto_goTypes,
		DependencyIndexes: file_GCGSkillPreviewPlayCardInfo_proto_depIdxs,
		MessageInfos:      file_GCGSkillPreviewPlayCardInfo_proto_msgTypes,
	}.Build()
	File_GCGSkillPreviewPlayCardInfo_proto = out.File
	file_GCGSkillPreviewPlayCardInfo_proto_rawDesc = nil
	file_GCGSkillPreviewPlayCardInfo_proto_goTypes = nil
	file_GCGSkillPreviewPlayCardInfo_proto_depIdxs = nil
}
