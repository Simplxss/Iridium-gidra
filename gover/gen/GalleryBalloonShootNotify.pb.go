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
// source: GalleryBalloonShootNotify.proto

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

// CmdId: 20139
// Obf: EOKGCKKIJBE
type GalleryBalloonShootNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GalleryId        uint32 `protobuf:"varint,15,opt,name=gallery_id,json=galleryId,proto3" json:"gallery_id,omitempty"`
	CurScore         uint32 `protobuf:"varint,1,opt,name=cur_score,json=curScore,proto3" json:"cur_score,omitempty"`
	Combo            uint32 `protobuf:"varint,2,opt,name=combo,proto3" json:"combo,omitempty"`
	ComboDisableTime uint64 `protobuf:"varint,11,opt,name=combo_disable_time,json=comboDisableTime,proto3" json:"combo_disable_time,omitempty"`
	AddScore         int32  `protobuf:"varint,14,opt,name=add_score,json=addScore,proto3" json:"add_score,omitempty"`
	TriggerEntityId  uint32 `protobuf:"varint,6,opt,name=trigger_entity_id,json=triggerEntityId,proto3" json:"trigger_entity_id,omitempty"`
}

func (x *GalleryBalloonShootNotify) Reset() {
	*x = GalleryBalloonShootNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GalleryBalloonShootNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GalleryBalloonShootNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GalleryBalloonShootNotify) ProtoMessage() {}

func (x *GalleryBalloonShootNotify) ProtoReflect() protoreflect.Message {
	mi := &file_GalleryBalloonShootNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GalleryBalloonShootNotify.ProtoReflect.Descriptor instead.
func (*GalleryBalloonShootNotify) Descriptor() ([]byte, []int) {
	return file_GalleryBalloonShootNotify_proto_rawDescGZIP(), []int{0}
}

func (x *GalleryBalloonShootNotify) GetGalleryId() uint32 {
	if x != nil {
		return x.GalleryId
	}
	return 0
}

func (x *GalleryBalloonShootNotify) GetCurScore() uint32 {
	if x != nil {
		return x.CurScore
	}
	return 0
}

func (x *GalleryBalloonShootNotify) GetCombo() uint32 {
	if x != nil {
		return x.Combo
	}
	return 0
}

func (x *GalleryBalloonShootNotify) GetComboDisableTime() uint64 {
	if x != nil {
		return x.ComboDisableTime
	}
	return 0
}

func (x *GalleryBalloonShootNotify) GetAddScore() int32 {
	if x != nil {
		return x.AddScore
	}
	return 0
}

func (x *GalleryBalloonShootNotify) GetTriggerEntityId() uint32 {
	if x != nil {
		return x.TriggerEntityId
	}
	return 0
}

var File_GalleryBalloonShootNotify_proto protoreflect.FileDescriptor

var file_GalleryBalloonShootNotify_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x42, 0x61, 0x6c, 0x6c, 0x6f, 0x6f, 0x6e,
	0x53, 0x68, 0x6f, 0x6f, 0x74, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0xe4, 0x01, 0x0a, 0x19, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x42, 0x61, 0x6c,
	0x6c, 0x6f, 0x6f, 0x6e, 0x53, 0x68, 0x6f, 0x6f, 0x74, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12,
	0x1d, 0x0a, 0x0a, 0x67, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x0f, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x09, 0x67, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x49, 0x64, 0x12, 0x1b,
	0x0a, 0x09, 0x63, 0x75, 0x72, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x08, 0x63, 0x75, 0x72, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x63,
	0x6f, 0x6d, 0x62, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x63, 0x6f, 0x6d, 0x62,
	0x6f, 0x12, 0x2c, 0x0a, 0x12, 0x63, 0x6f, 0x6d, 0x62, 0x6f, 0x5f, 0x64, 0x69, 0x73, 0x61, 0x62,
	0x6c, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x04, 0x52, 0x10, 0x63,
	0x6f, 0x6d, 0x62, 0x6f, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12,
	0x1b, 0x0a, 0x09, 0x61, 0x64, 0x64, 0x5f, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x0e, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x08, 0x61, 0x64, 0x64, 0x53, 0x63, 0x6f, 0x72, 0x65, 0x12, 0x2a, 0x0a, 0x11,
	0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x69,
	0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72,
	0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GalleryBalloonShootNotify_proto_rawDescOnce sync.Once
	file_GalleryBalloonShootNotify_proto_rawDescData = file_GalleryBalloonShootNotify_proto_rawDesc
)

func file_GalleryBalloonShootNotify_proto_rawDescGZIP() []byte {
	file_GalleryBalloonShootNotify_proto_rawDescOnce.Do(func() {
		file_GalleryBalloonShootNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_GalleryBalloonShootNotify_proto_rawDescData)
	})
	return file_GalleryBalloonShootNotify_proto_rawDescData
}

var file_GalleryBalloonShootNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GalleryBalloonShootNotify_proto_goTypes = []interface{}{
	(*GalleryBalloonShootNotify)(nil), // 0: GalleryBalloonShootNotify
}
var file_GalleryBalloonShootNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GalleryBalloonShootNotify_proto_init() }
func file_GalleryBalloonShootNotify_proto_init() {
	if File_GalleryBalloonShootNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_GalleryBalloonShootNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GalleryBalloonShootNotify); i {
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
			RawDescriptor: file_GalleryBalloonShootNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GalleryBalloonShootNotify_proto_goTypes,
		DependencyIndexes: file_GalleryBalloonShootNotify_proto_depIdxs,
		MessageInfos:      file_GalleryBalloonShootNotify_proto_msgTypes,
	}.Build()
	File_GalleryBalloonShootNotify_proto = out.File
	file_GalleryBalloonShootNotify_proto_rawDesc = nil
	file_GalleryBalloonShootNotify_proto_goTypes = nil
	file_GalleryBalloonShootNotify_proto_depIdxs = nil
}
