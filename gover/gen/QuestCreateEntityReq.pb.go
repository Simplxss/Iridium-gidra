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
// source: QuestCreateEntityReq.proto

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

type QuestCreateEntityReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ParentQuestId uint32            `protobuf:"varint,14,opt,name=parent_quest_id,json=parentQuestId,proto3" json:"parent_quest_id,omitempty"`
	Entity        *CreateEntityInfo `protobuf:"bytes,3,opt,name=entity,proto3" json:"entity,omitempty"`
	QuestId       uint32            `protobuf:"varint,5,opt,name=quest_id,json=questId,proto3" json:"quest_id,omitempty"`
	IsRewind      bool              `protobuf:"varint,11,opt,name=is_rewind,json=isRewind,proto3" json:"is_rewind,omitempty"`
}

func (x *QuestCreateEntityReq) Reset() {
	*x = QuestCreateEntityReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_QuestCreateEntityReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *QuestCreateEntityReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*QuestCreateEntityReq) ProtoMessage() {}

func (x *QuestCreateEntityReq) ProtoReflect() protoreflect.Message {
	mi := &file_QuestCreateEntityReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use QuestCreateEntityReq.ProtoReflect.Descriptor instead.
func (*QuestCreateEntityReq) Descriptor() ([]byte, []int) {
	return file_QuestCreateEntityReq_proto_rawDescGZIP(), []int{0}
}

func (x *QuestCreateEntityReq) GetParentQuestId() uint32 {
	if x != nil {
		return x.ParentQuestId
	}
	return 0
}

func (x *QuestCreateEntityReq) GetEntity() *CreateEntityInfo {
	if x != nil {
		return x.Entity
	}
	return nil
}

func (x *QuestCreateEntityReq) GetQuestId() uint32 {
	if x != nil {
		return x.QuestId
	}
	return 0
}

func (x *QuestCreateEntityReq) GetIsRewind() bool {
	if x != nil {
		return x.IsRewind
	}
	return false
}

var File_QuestCreateEntityReq_proto protoreflect.FileDescriptor

var file_QuestCreateEntityReq_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x51, 0x75, 0x65, 0x73, 0x74, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x45, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x43, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa1, 0x01, 0x0a, 0x14, 0x51, 0x75, 0x65, 0x73, 0x74, 0x43, 0x72,
	0x65, 0x61, 0x74, 0x65, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x12, 0x26, 0x0a,
	0x0f, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64,
	0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x51, 0x75,
	0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x29, 0x0a, 0x06, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x45, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x06, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x12, 0x19, 0x0a, 0x08, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x07, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x69,
	0x73, 0x5f, 0x72, 0x65, 0x77, 0x69, 0x6e, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08,
	0x69, 0x73, 0x52, 0x65, 0x77, 0x69, 0x6e, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_QuestCreateEntityReq_proto_rawDescOnce sync.Once
	file_QuestCreateEntityReq_proto_rawDescData = file_QuestCreateEntityReq_proto_rawDesc
)

func file_QuestCreateEntityReq_proto_rawDescGZIP() []byte {
	file_QuestCreateEntityReq_proto_rawDescOnce.Do(func() {
		file_QuestCreateEntityReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_QuestCreateEntityReq_proto_rawDescData)
	})
	return file_QuestCreateEntityReq_proto_rawDescData
}

var file_QuestCreateEntityReq_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_QuestCreateEntityReq_proto_goTypes = []interface{}{
	(*QuestCreateEntityReq)(nil), // 0: QuestCreateEntityReq
	(*CreateEntityInfo)(nil),     // 1: CreateEntityInfo
}
var file_QuestCreateEntityReq_proto_depIdxs = []int32{
	1, // 0: QuestCreateEntityReq.entity:type_name -> CreateEntityInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_QuestCreateEntityReq_proto_init() }
func file_QuestCreateEntityReq_proto_init() {
	if File_QuestCreateEntityReq_proto != nil {
		return
	}
	file_CreateEntityInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_QuestCreateEntityReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*QuestCreateEntityReq); i {
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
			RawDescriptor: file_QuestCreateEntityReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_QuestCreateEntityReq_proto_goTypes,
		DependencyIndexes: file_QuestCreateEntityReq_proto_depIdxs,
		MessageInfos:      file_QuestCreateEntityReq_proto_msgTypes,
	}.Build()
	File_QuestCreateEntityReq_proto = out.File
	file_QuestCreateEntityReq_proto_rawDesc = nil
	file_QuestCreateEntityReq_proto_goTypes = nil
	file_QuestCreateEntityReq_proto_depIdxs = nil
}
