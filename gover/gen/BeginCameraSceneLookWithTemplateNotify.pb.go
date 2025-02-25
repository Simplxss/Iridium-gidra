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
// source: BeginCameraSceneLookWithTemplateNotify.proto

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

// Obf: DOFPPPPIJON
type BeginCameraSceneLookWithTemplateNotify_FollowType int32

const (
	BeginCameraSceneLookWithTemplateNotify_FOLLOW_TYPE_INIT_FOLLOW_POS    BeginCameraSceneLookWithTemplateNotify_FollowType = 0
	BeginCameraSceneLookWithTemplateNotify_FOLLOW_TYPE_SET_FOLLOW_POS     BeginCameraSceneLookWithTemplateNotify_FollowType = 1
	BeginCameraSceneLookWithTemplateNotify_FOLLOW_TYPE_SET_ABS_FOLLOW_POS BeginCameraSceneLookWithTemplateNotify_FollowType = 2
)

// Enum value maps for BeginCameraSceneLookWithTemplateNotify_FollowType.
var (
	BeginCameraSceneLookWithTemplateNotify_FollowType_name = map[int32]string{
		0: "FOLLOW_TYPE_INIT_FOLLOW_POS",
		1: "FOLLOW_TYPE_SET_FOLLOW_POS",
		2: "FOLLOW_TYPE_SET_ABS_FOLLOW_POS",
	}
	BeginCameraSceneLookWithTemplateNotify_FollowType_value = map[string]int32{
		"FOLLOW_TYPE_INIT_FOLLOW_POS":    0,
		"FOLLOW_TYPE_SET_FOLLOW_POS":     1,
		"FOLLOW_TYPE_SET_ABS_FOLLOW_POS": 2,
	}
)

func (x BeginCameraSceneLookWithTemplateNotify_FollowType) Enum() *BeginCameraSceneLookWithTemplateNotify_FollowType {
	p := new(BeginCameraSceneLookWithTemplateNotify_FollowType)
	*p = x
	return p
}

func (x BeginCameraSceneLookWithTemplateNotify_FollowType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (BeginCameraSceneLookWithTemplateNotify_FollowType) Descriptor() protoreflect.EnumDescriptor {
	return file_BeginCameraSceneLookWithTemplateNotify_proto_enumTypes[0].Descriptor()
}

func (BeginCameraSceneLookWithTemplateNotify_FollowType) Type() protoreflect.EnumType {
	return &file_BeginCameraSceneLookWithTemplateNotify_proto_enumTypes[0]
}

func (x BeginCameraSceneLookWithTemplateNotify_FollowType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use BeginCameraSceneLookWithTemplateNotify_FollowType.Descriptor instead.
func (BeginCameraSceneLookWithTemplateNotify_FollowType) EnumDescriptor() ([]byte, []int) {
	return file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescGZIP(), []int{0, 0}
}

// CmdId: 8774
// Obf: EJGAPPPIDGA
type BeginCameraSceneLookWithTemplateNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LKGGBPLCEJI *Vector                                           `protobuf:"bytes,2,opt,name=LKGGBPLCEJI,proto3" json:"LKGGBPLCEJI,omitempty"`
	EntityId    uint32                                            `protobuf:"varint,13,opt,name=entity_id,json=entityId,proto3" json:"entity_id,omitempty"`
	TemplateId  uint32                                            `protobuf:"varint,12,opt,name=template_id,json=templateId,proto3" json:"template_id,omitempty"`
	FollowType  BeginCameraSceneLookWithTemplateNotify_FollowType `protobuf:"varint,9,opt,name=follow_type,json=followType,proto3,enum=BeginCameraSceneLookWithTemplateNotify_FollowType" json:"follow_type,omitempty"`
	OtherParams []string                                          `protobuf:"bytes,5,rep,name=other_params,json=otherParams,proto3" json:"other_params,omitempty"`
	MMOMOKPCOJK *Vector                                           `protobuf:"bytes,7,opt,name=MMOMOKPCOJK,proto3" json:"MMOMOKPCOJK,omitempty"`
}

func (x *BeginCameraSceneLookWithTemplateNotify) Reset() {
	*x = BeginCameraSceneLookWithTemplateNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_BeginCameraSceneLookWithTemplateNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BeginCameraSceneLookWithTemplateNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BeginCameraSceneLookWithTemplateNotify) ProtoMessage() {}

func (x *BeginCameraSceneLookWithTemplateNotify) ProtoReflect() protoreflect.Message {
	mi := &file_BeginCameraSceneLookWithTemplateNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BeginCameraSceneLookWithTemplateNotify.ProtoReflect.Descriptor instead.
func (*BeginCameraSceneLookWithTemplateNotify) Descriptor() ([]byte, []int) {
	return file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescGZIP(), []int{0}
}

func (x *BeginCameraSceneLookWithTemplateNotify) GetLKGGBPLCEJI() *Vector {
	if x != nil {
		return x.LKGGBPLCEJI
	}
	return nil
}

func (x *BeginCameraSceneLookWithTemplateNotify) GetEntityId() uint32 {
	if x != nil {
		return x.EntityId
	}
	return 0
}

func (x *BeginCameraSceneLookWithTemplateNotify) GetTemplateId() uint32 {
	if x != nil {
		return x.TemplateId
	}
	return 0
}

func (x *BeginCameraSceneLookWithTemplateNotify) GetFollowType() BeginCameraSceneLookWithTemplateNotify_FollowType {
	if x != nil {
		return x.FollowType
	}
	return BeginCameraSceneLookWithTemplateNotify_FOLLOW_TYPE_INIT_FOLLOW_POS
}

func (x *BeginCameraSceneLookWithTemplateNotify) GetOtherParams() []string {
	if x != nil {
		return x.OtherParams
	}
	return nil
}

func (x *BeginCameraSceneLookWithTemplateNotify) GetMMOMOKPCOJK() *Vector {
	if x != nil {
		return x.MMOMOKPCOJK
	}
	return nil
}

var File_BeginCameraSceneLookWithTemplateNotify_proto protoreflect.FileDescriptor

var file_BeginCameraSceneLookWithTemplateNotify_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x43, 0x61, 0x6d, 0x65, 0x72, 0x61, 0x53, 0x63, 0x65,
	0x6e, 0x65, 0x4c, 0x6f, 0x6f, 0x6b, 0x57, 0x69, 0x74, 0x68, 0x54, 0x65, 0x6d, 0x70, 0x6c, 0x61,
	0x74, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c,
	0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa7, 0x03, 0x0a,
	0x26, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x43, 0x61, 0x6d, 0x65, 0x72, 0x61, 0x53, 0x63, 0x65, 0x6e,
	0x65, 0x4c, 0x6f, 0x6f, 0x6b, 0x57, 0x69, 0x74, 0x68, 0x54, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74,
	0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x29, 0x0a, 0x0b, 0x4c, 0x4b, 0x47, 0x47, 0x42,
	0x50, 0x4c, 0x43, 0x45, 0x4a, 0x49, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56,
	0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x0b, 0x4c, 0x4b, 0x47, 0x47, 0x42, 0x50, 0x4c, 0x43, 0x45,
	0x4a, 0x49, 0x12, 0x1b, 0x0a, 0x09, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x64, 0x12,
	0x1f, 0x0a, 0x0b, 0x74, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x0c,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x74, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x49, 0x64,
	0x12, 0x53, 0x0a, 0x0b, 0x66, 0x6f, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x09, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x32, 0x2e, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x43, 0x61, 0x6d,
	0x65, 0x72, 0x61, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x4c, 0x6f, 0x6f, 0x6b, 0x57, 0x69, 0x74, 0x68,
	0x54, 0x65, 0x6d, 0x70, 0x6c, 0x61, 0x74, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x46,
	0x6f, 0x6c, 0x6c, 0x6f, 0x77, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0a, 0x66, 0x6f, 0x6c, 0x6c, 0x6f,
	0x77, 0x54, 0x79, 0x70, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x5f, 0x70,
	0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x6f, 0x74, 0x68,
	0x65, 0x72, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12, 0x29, 0x0a, 0x0b, 0x4d, 0x4d, 0x4f, 0x4d,
	0x4f, 0x4b, 0x50, 0x43, 0x4f, 0x4a, 0x4b, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e,
	0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x52, 0x0b, 0x4d, 0x4d, 0x4f, 0x4d, 0x4f, 0x4b, 0x50, 0x43,
	0x4f, 0x4a, 0x4b, 0x22, 0x71, 0x0a, 0x0a, 0x46, 0x6f, 0x6c, 0x6c, 0x6f, 0x77, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x1f, 0x0a, 0x1b, 0x46, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x5f, 0x54, 0x59, 0x50, 0x45,
	0x5f, 0x49, 0x4e, 0x49, 0x54, 0x5f, 0x46, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x5f, 0x50, 0x4f, 0x53,
	0x10, 0x00, 0x12, 0x1e, 0x0a, 0x1a, 0x46, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x5f, 0x54, 0x59, 0x50,
	0x45, 0x5f, 0x53, 0x45, 0x54, 0x5f, 0x46, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x5f, 0x50, 0x4f, 0x53,
	0x10, 0x01, 0x12, 0x22, 0x0a, 0x1e, 0x46, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x5f, 0x54, 0x59, 0x50,
	0x45, 0x5f, 0x53, 0x45, 0x54, 0x5f, 0x41, 0x42, 0x53, 0x5f, 0x46, 0x4f, 0x4c, 0x4c, 0x4f, 0x57,
	0x5f, 0x50, 0x4f, 0x53, 0x10, 0x02, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescOnce sync.Once
	file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescData = file_BeginCameraSceneLookWithTemplateNotify_proto_rawDesc
)

func file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescGZIP() []byte {
	file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescOnce.Do(func() {
		file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescData)
	})
	return file_BeginCameraSceneLookWithTemplateNotify_proto_rawDescData
}

var file_BeginCameraSceneLookWithTemplateNotify_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_BeginCameraSceneLookWithTemplateNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_BeginCameraSceneLookWithTemplateNotify_proto_goTypes = []interface{}{
	(BeginCameraSceneLookWithTemplateNotify_FollowType)(0), // 0: BeginCameraSceneLookWithTemplateNotify.FollowType
	(*BeginCameraSceneLookWithTemplateNotify)(nil),         // 1: BeginCameraSceneLookWithTemplateNotify
	(*Vector)(nil), // 2: Vector
}
var file_BeginCameraSceneLookWithTemplateNotify_proto_depIdxs = []int32{
	2, // 0: BeginCameraSceneLookWithTemplateNotify.LKGGBPLCEJI:type_name -> Vector
	0, // 1: BeginCameraSceneLookWithTemplateNotify.follow_type:type_name -> BeginCameraSceneLookWithTemplateNotify.FollowType
	2, // 2: BeginCameraSceneLookWithTemplateNotify.MMOMOKPCOJK:type_name -> Vector
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_BeginCameraSceneLookWithTemplateNotify_proto_init() }
func file_BeginCameraSceneLookWithTemplateNotify_proto_init() {
	if File_BeginCameraSceneLookWithTemplateNotify_proto != nil {
		return
	}
	file_Vector_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_BeginCameraSceneLookWithTemplateNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BeginCameraSceneLookWithTemplateNotify); i {
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
			RawDescriptor: file_BeginCameraSceneLookWithTemplateNotify_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_BeginCameraSceneLookWithTemplateNotify_proto_goTypes,
		DependencyIndexes: file_BeginCameraSceneLookWithTemplateNotify_proto_depIdxs,
		EnumInfos:         file_BeginCameraSceneLookWithTemplateNotify_proto_enumTypes,
		MessageInfos:      file_BeginCameraSceneLookWithTemplateNotify_proto_msgTypes,
	}.Build()
	File_BeginCameraSceneLookWithTemplateNotify_proto = out.File
	file_BeginCameraSceneLookWithTemplateNotify_proto_rawDesc = nil
	file_BeginCameraSceneLookWithTemplateNotify_proto_goTypes = nil
	file_BeginCameraSceneLookWithTemplateNotify_proto_depIdxs = nil
}
