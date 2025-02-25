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
// source: GCGSkillPreviewNotify.proto

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

// CmdId: 23522
// Obf: GNFJLAAJCHF
type GCGSkillPreviewNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SkillPreviewList         []*GCGSkillPreviewInfo         `protobuf:"bytes,7,rep,name=skill_preview_list,json=skillPreviewList,proto3" json:"skill_preview_list,omitempty"`
	EOKDJJAKKPJ              uint32                         `protobuf:"varint,11,opt,name=EOKDJJAKKPJ,proto3" json:"EOKDJJAKKPJ,omitempty"`
	PlayCardList             []*GCGSkillPreviewPlayCardInfo `protobuf:"bytes,14,rep,name=play_card_list,json=playCardList,proto3" json:"play_card_list,omitempty"`
	ChangeOnstagePreviewList []*GCGChangeOnstageInfo        `protobuf:"bytes,13,rep,name=change_onstage_preview_list,json=changeOnstagePreviewList,proto3" json:"change_onstage_preview_list,omitempty"`
	ControllerId             uint32                         `protobuf:"varint,10,opt,name=controller_id,json=controllerId,proto3" json:"controller_id,omitempty"`
}

func (x *GCGSkillPreviewNotify) Reset() {
	*x = GCGSkillPreviewNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGSkillPreviewNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGSkillPreviewNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGSkillPreviewNotify) ProtoMessage() {}

func (x *GCGSkillPreviewNotify) ProtoReflect() protoreflect.Message {
	mi := &file_GCGSkillPreviewNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGSkillPreviewNotify.ProtoReflect.Descriptor instead.
func (*GCGSkillPreviewNotify) Descriptor() ([]byte, []int) {
	return file_GCGSkillPreviewNotify_proto_rawDescGZIP(), []int{0}
}

func (x *GCGSkillPreviewNotify) GetSkillPreviewList() []*GCGSkillPreviewInfo {
	if x != nil {
		return x.SkillPreviewList
	}
	return nil
}

func (x *GCGSkillPreviewNotify) GetEOKDJJAKKPJ() uint32 {
	if x != nil {
		return x.EOKDJJAKKPJ
	}
	return 0
}

func (x *GCGSkillPreviewNotify) GetPlayCardList() []*GCGSkillPreviewPlayCardInfo {
	if x != nil {
		return x.PlayCardList
	}
	return nil
}

func (x *GCGSkillPreviewNotify) GetChangeOnstagePreviewList() []*GCGChangeOnstageInfo {
	if x != nil {
		return x.ChangeOnstagePreviewList
	}
	return nil
}

func (x *GCGSkillPreviewNotify) GetControllerId() uint32 {
	if x != nil {
		return x.ControllerId
	}
	return 0
}

var File_GCGSkillPreviewNotify_proto protoreflect.FileDescriptor

var file_GCGSkillPreviewNotify_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x47, 0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x47,
	0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x49, 0x6e,
	0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x47, 0x43, 0x47, 0x53, 0x6b, 0x69,
	0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x50, 0x6c, 0x61, 0x79, 0x43, 0x61, 0x72,
	0x64, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x47, 0x43, 0x47,
	0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4f, 0x6e, 0x73, 0x74, 0x61, 0x67, 0x65, 0x49, 0x6e, 0x66,
	0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xbc, 0x02, 0x0a, 0x15, 0x47, 0x43, 0x47, 0x53,
	0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x4e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x12, 0x42, 0x0a, 0x12, 0x73, 0x6b, 0x69, 0x6c, 0x6c, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69,
	0x65, 0x77, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x47, 0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x10, 0x73, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x45, 0x4f, 0x4b, 0x44, 0x4a, 0x4a, 0x41,
	0x4b, 0x4b, 0x50, 0x4a, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x45, 0x4f, 0x4b, 0x44,
	0x4a, 0x4a, 0x41, 0x4b, 0x4b, 0x50, 0x4a, 0x12, 0x42, 0x0a, 0x0e, 0x70, 0x6c, 0x61, 0x79, 0x5f,
	0x63, 0x61, 0x72, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x47, 0x43, 0x47, 0x53, 0x6b, 0x69, 0x6c, 0x6c, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65,
	0x77, 0x50, 0x6c, 0x61, 0x79, 0x43, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0c, 0x70,
	0x6c, 0x61, 0x79, 0x43, 0x61, 0x72, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x54, 0x0a, 0x1b, 0x63,
	0x68, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x70, 0x72,
	0x65, 0x76, 0x69, 0x65, 0x77, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x15, 0x2e, 0x47, 0x43, 0x47, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4f, 0x6e, 0x73, 0x74,
	0x61, 0x67, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x18, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4f,
	0x6e, 0x73, 0x74, 0x61, 0x67, 0x65, 0x50, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77, 0x4c, 0x69, 0x73,
	0x74, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x5f,
	0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f,
	0x6c, 0x6c, 0x65, 0x72, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGSkillPreviewNotify_proto_rawDescOnce sync.Once
	file_GCGSkillPreviewNotify_proto_rawDescData = file_GCGSkillPreviewNotify_proto_rawDesc
)

func file_GCGSkillPreviewNotify_proto_rawDescGZIP() []byte {
	file_GCGSkillPreviewNotify_proto_rawDescOnce.Do(func() {
		file_GCGSkillPreviewNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGSkillPreviewNotify_proto_rawDescData)
	})
	return file_GCGSkillPreviewNotify_proto_rawDescData
}

var file_GCGSkillPreviewNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGSkillPreviewNotify_proto_goTypes = []interface{}{
	(*GCGSkillPreviewNotify)(nil),       // 0: GCGSkillPreviewNotify
	(*GCGSkillPreviewInfo)(nil),         // 1: GCGSkillPreviewInfo
	(*GCGSkillPreviewPlayCardInfo)(nil), // 2: GCGSkillPreviewPlayCardInfo
	(*GCGChangeOnstageInfo)(nil),        // 3: GCGChangeOnstageInfo
}
var file_GCGSkillPreviewNotify_proto_depIdxs = []int32{
	1, // 0: GCGSkillPreviewNotify.skill_preview_list:type_name -> GCGSkillPreviewInfo
	2, // 1: GCGSkillPreviewNotify.play_card_list:type_name -> GCGSkillPreviewPlayCardInfo
	3, // 2: GCGSkillPreviewNotify.change_onstage_preview_list:type_name -> GCGChangeOnstageInfo
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_GCGSkillPreviewNotify_proto_init() }
func file_GCGSkillPreviewNotify_proto_init() {
	if File_GCGSkillPreviewNotify_proto != nil {
		return
	}
	file_GCGSkillPreviewInfo_proto_init()
	file_GCGSkillPreviewPlayCardInfo_proto_init()
	file_GCGChangeOnstageInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GCGSkillPreviewNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGSkillPreviewNotify); i {
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
			RawDescriptor: file_GCGSkillPreviewNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGSkillPreviewNotify_proto_goTypes,
		DependencyIndexes: file_GCGSkillPreviewNotify_proto_depIdxs,
		MessageInfos:      file_GCGSkillPreviewNotify_proto_msgTypes,
	}.Build()
	File_GCGSkillPreviewNotify_proto = out.File
	file_GCGSkillPreviewNotify_proto_rawDesc = nil
	file_GCGSkillPreviewNotify_proto_goTypes = nil
	file_GCGSkillPreviewNotify_proto_depIdxs = nil
}
