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
// source: GCGTCTavernInfoNotify.proto

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

// CmdId: 22639
// Obf: KLMPBEENMNG
type GCGTCTavernInfoNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CharacterId uint32 `protobuf:"varint,11,opt,name=character_id,json=characterId,proto3" json:"character_id,omitempty"`
	AvatarId    uint32 `protobuf:"varint,7,opt,name=avatar_id,json=avatarId,proto3" json:"avatar_id,omitempty"`
	KPBIEOPHOHC bool   `protobuf:"varint,4,opt,name=KPBIEOPHOHC,proto3" json:"KPBIEOPHOHC,omitempty"`
	LevelId     uint32 `protobuf:"varint,13,opt,name=level_id,json=levelId,proto3" json:"level_id,omitempty"`
	ElementType uint32 `protobuf:"varint,5,opt,name=element_type,json=elementType,proto3" json:"element_type,omitempty"`
	PointId     uint32 `protobuf:"varint,6,opt,name=point_id,json=pointId,proto3" json:"point_id,omitempty"`
	EKEOEIDDHCN bool   `protobuf:"varint,3,opt,name=EKEOEIDDHCN,proto3" json:"EKEOEIDDHCN,omitempty"`
}

func (x *GCGTCTavernInfoNotify) Reset() {
	*x = GCGTCTavernInfoNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGTCTavernInfoNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGTCTavernInfoNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGTCTavernInfoNotify) ProtoMessage() {}

func (x *GCGTCTavernInfoNotify) ProtoReflect() protoreflect.Message {
	mi := &file_GCGTCTavernInfoNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGTCTavernInfoNotify.ProtoReflect.Descriptor instead.
func (*GCGTCTavernInfoNotify) Descriptor() ([]byte, []int) {
	return file_GCGTCTavernInfoNotify_proto_rawDescGZIP(), []int{0}
}

func (x *GCGTCTavernInfoNotify) GetCharacterId() uint32 {
	if x != nil {
		return x.CharacterId
	}
	return 0
}

func (x *GCGTCTavernInfoNotify) GetAvatarId() uint32 {
	if x != nil {
		return x.AvatarId
	}
	return 0
}

func (x *GCGTCTavernInfoNotify) GetKPBIEOPHOHC() bool {
	if x != nil {
		return x.KPBIEOPHOHC
	}
	return false
}

func (x *GCGTCTavernInfoNotify) GetLevelId() uint32 {
	if x != nil {
		return x.LevelId
	}
	return 0
}

func (x *GCGTCTavernInfoNotify) GetElementType() uint32 {
	if x != nil {
		return x.ElementType
	}
	return 0
}

func (x *GCGTCTavernInfoNotify) GetPointId() uint32 {
	if x != nil {
		return x.PointId
	}
	return 0
}

func (x *GCGTCTavernInfoNotify) GetEKEOEIDDHCN() bool {
	if x != nil {
		return x.EKEOEIDDHCN
	}
	return false
}

var File_GCGTCTavernInfoNotify_proto protoreflect.FileDescriptor

var file_GCGTCTavernInfoNotify_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x47, 0x43, 0x47, 0x54, 0x43, 0x54, 0x61, 0x76, 0x65, 0x72, 0x6e, 0x49, 0x6e, 0x66,
	0x6f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf4, 0x01,
	0x0a, 0x15, 0x47, 0x43, 0x47, 0x54, 0x43, 0x54, 0x61, 0x76, 0x65, 0x72, 0x6e, 0x49, 0x6e, 0x66,
	0x6f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x68, 0x61, 0x72, 0x61,
	0x63, 0x74, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x63,
	0x68, 0x61, 0x72, 0x61, 0x63, 0x74, 0x65, 0x72, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x61, 0x76,
	0x61, 0x74, 0x61, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x61,
	0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x4b, 0x50, 0x42, 0x49, 0x45,
	0x4f, 0x50, 0x48, 0x4f, 0x48, 0x43, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x4b, 0x50,
	0x42, 0x49, 0x45, 0x4f, 0x50, 0x48, 0x4f, 0x48, 0x43, 0x12, 0x19, 0x0a, 0x08, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x49, 0x64, 0x12, 0x21, 0x0a, 0x0c, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x5f,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x65, 0x6c, 0x65, 0x6d,
	0x65, 0x6e, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x49, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x45, 0x4b, 0x45, 0x4f, 0x45, 0x49, 0x44, 0x44, 0x48, 0x43,
	0x4e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x45, 0x4b, 0x45, 0x4f, 0x45, 0x49, 0x44,
	0x44, 0x48, 0x43, 0x4e, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGTCTavernInfoNotify_proto_rawDescOnce sync.Once
	file_GCGTCTavernInfoNotify_proto_rawDescData = file_GCGTCTavernInfoNotify_proto_rawDesc
)

func file_GCGTCTavernInfoNotify_proto_rawDescGZIP() []byte {
	file_GCGTCTavernInfoNotify_proto_rawDescOnce.Do(func() {
		file_GCGTCTavernInfoNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGTCTavernInfoNotify_proto_rawDescData)
	})
	return file_GCGTCTavernInfoNotify_proto_rawDescData
}

var file_GCGTCTavernInfoNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGTCTavernInfoNotify_proto_goTypes = []interface{}{
	(*GCGTCTavernInfoNotify)(nil), // 0: GCGTCTavernInfoNotify
}
var file_GCGTCTavernInfoNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GCGTCTavernInfoNotify_proto_init() }
func file_GCGTCTavernInfoNotify_proto_init() {
	if File_GCGTCTavernInfoNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_GCGTCTavernInfoNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGTCTavernInfoNotify); i {
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
			RawDescriptor: file_GCGTCTavernInfoNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGTCTavernInfoNotify_proto_goTypes,
		DependencyIndexes: file_GCGTCTavernInfoNotify_proto_depIdxs,
		MessageInfos:      file_GCGTCTavernInfoNotify_proto_msgTypes,
	}.Build()
	File_GCGTCTavernInfoNotify_proto = out.File
	file_GCGTCTavernInfoNotify_proto_rawDesc = nil
	file_GCGTCTavernInfoNotify_proto_goTypes = nil
	file_GCGTCTavernInfoNotify_proto_depIdxs = nil
}
