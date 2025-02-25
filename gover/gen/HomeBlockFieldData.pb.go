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
// source: HomeBlockFieldData.proto

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

// Obf: ONEIGKNNOGN
type HomeBlockFieldData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SubFieldList []*HomeBlockSubFieldData `protobuf:"bytes,10,rep,name=sub_field_list,json=subFieldList,proto3" json:"sub_field_list,omitempty"`
	FurnitureId  uint32                   `protobuf:"varint,1,opt,name=furniture_id,json=furnitureId,proto3" json:"furniture_id,omitempty"`
	Rot          *Vector                  `protobuf:"bytes,8,opt,name=rot,proto3" json:"rot,omitempty"`
	Pos          *Vector                  `protobuf:"bytes,15,opt,name=pos,proto3" json:"pos,omitempty"`
	Guid         uint32                   `protobuf:"varint,13,opt,name=guid,proto3" json:"guid,omitempty"`
}

func (x *HomeBlockFieldData) Reset() {
	*x = HomeBlockFieldData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_HomeBlockFieldData_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HomeBlockFieldData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HomeBlockFieldData) ProtoMessage() {}

func (x *HomeBlockFieldData) ProtoReflect() protoreflect.Message {
	mi := &file_HomeBlockFieldData_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HomeBlockFieldData.ProtoReflect.Descriptor instead.
func (*HomeBlockFieldData) Descriptor() ([]byte, []int) {
	return file_HomeBlockFieldData_proto_rawDescGZIP(), []int{0}
}

func (x *HomeBlockFieldData) GetSubFieldList() []*HomeBlockSubFieldData {
	if x != nil {
		return x.SubFieldList
	}
	return nil
}

func (x *HomeBlockFieldData) GetFurnitureId() uint32 {
	if x != nil {
		return x.FurnitureId
	}
	return 0
}

func (x *HomeBlockFieldData) GetRot() *Vector {
	if x != nil {
		return x.Rot
	}
	return nil
}

func (x *HomeBlockFieldData) GetPos() *Vector {
	if x != nil {
		return x.Pos
	}
	return nil
}

func (x *HomeBlockFieldData) GetGuid() uint32 {
	if x != nil {
		return x.Guid
	}
	return 0
}

var File_HomeBlockFieldData_proto protoreflect.FileDescriptor

var file_HomeBlockFieldData_proto_rawDesc = []byte{
	0x0a, 0x18, 0x48, 0x6f, 0x6d, 0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x46, 0x69, 0x65, 0x6c, 0x64,
	0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x48, 0x6f, 0x6d, 0x65,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x53, 0x75, 0x62, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x44, 0x61, 0x74,
	0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xbf, 0x01, 0x0a, 0x12, 0x48, 0x6f, 0x6d, 0x65, 0x42, 0x6c,
	0x6f, 0x63, 0x6b, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x44, 0x61, 0x74, 0x61, 0x12, 0x3c, 0x0a, 0x0e,
	0x73, 0x75, 0x62, 0x5f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0a,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x48, 0x6f, 0x6d, 0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x53, 0x75, 0x62, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x44, 0x61, 0x74, 0x61, 0x52, 0x0c, 0x73, 0x75,
	0x62, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x66, 0x75,
	0x72, 0x6e, 0x69, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0b, 0x66, 0x75, 0x72, 0x6e, 0x69, 0x74, 0x75, 0x72, 0x65, 0x49, 0x64, 0x12, 0x19, 0x0a,
	0x03, 0x72, 0x6f, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63,
	0x74, 0x6f, 0x72, 0x52, 0x03, 0x72, 0x6f, 0x74, 0x12, 0x19, 0x0a, 0x03, 0x70, 0x6f, 0x73, 0x18,
	0x0f, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x03,
	0x70, 0x6f, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x67, 0x75, 0x69, 0x64, 0x18, 0x0d, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x04, 0x67, 0x75, 0x69, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_HomeBlockFieldData_proto_rawDescOnce sync.Once
	file_HomeBlockFieldData_proto_rawDescData = file_HomeBlockFieldData_proto_rawDesc
)

func file_HomeBlockFieldData_proto_rawDescGZIP() []byte {
	file_HomeBlockFieldData_proto_rawDescOnce.Do(func() {
		file_HomeBlockFieldData_proto_rawDescData = protoimpl.X.CompressGZIP(file_HomeBlockFieldData_proto_rawDescData)
	})
	return file_HomeBlockFieldData_proto_rawDescData
}

var file_HomeBlockFieldData_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_HomeBlockFieldData_proto_goTypes = []interface{}{
	(*HomeBlockFieldData)(nil),    // 0: HomeBlockFieldData
	(*HomeBlockSubFieldData)(nil), // 1: HomeBlockSubFieldData
	(*Vector)(nil),                // 2: Vector
}
var file_HomeBlockFieldData_proto_depIdxs = []int32{
	1, // 0: HomeBlockFieldData.sub_field_list:type_name -> HomeBlockSubFieldData
	2, // 1: HomeBlockFieldData.rot:type_name -> Vector
	2, // 2: HomeBlockFieldData.pos:type_name -> Vector
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_HomeBlockFieldData_proto_init() }
func file_HomeBlockFieldData_proto_init() {
	if File_HomeBlockFieldData_proto != nil {
		return
	}
	file_HomeBlockSubFieldData_proto_init()
	file_Vector_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_HomeBlockFieldData_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HomeBlockFieldData); i {
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
			RawDescriptor: file_HomeBlockFieldData_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_HomeBlockFieldData_proto_goTypes,
		DependencyIndexes: file_HomeBlockFieldData_proto_depIdxs,
		MessageInfos:      file_HomeBlockFieldData_proto_msgTypes,
	}.Build()
	File_HomeBlockFieldData_proto = out.File
	file_HomeBlockFieldData_proto_rawDesc = nil
	file_HomeBlockFieldData_proto_goTypes = nil
	file_HomeBlockFieldData_proto_depIdxs = nil
}
