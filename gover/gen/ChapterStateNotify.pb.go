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
// source: ChapterStateNotify.proto

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

// CmdId: 21508
// Obf: MCCCGABFHBK
type ChapterStateNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	NeedBeginTime   *ChapterStateNotify_NeedBeginTime   `protobuf:"bytes,10,opt,name=need_begin_time,json=needBeginTime,proto3" json:"need_begin_time,omitempty"`
	NeedPlayerLevel *ChapterStateNotify_NeedPlayerLevel `protobuf:"bytes,3,opt,name=need_player_level,json=needPlayerLevel,proto3" json:"need_player_level,omitempty"`
	ChapterState    ChapterState                        `protobuf:"varint,7,opt,name=chapter_state,json=chapterState,proto3,enum=ChapterState" json:"chapter_state,omitempty"`
	ChapterId       uint32                              `protobuf:"varint,4,opt,name=chapter_id,json=chapterId,proto3" json:"chapter_id,omitempty"`
}

func (x *ChapterStateNotify) Reset() {
	*x = ChapterStateNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ChapterStateNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChapterStateNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChapterStateNotify) ProtoMessage() {}

func (x *ChapterStateNotify) ProtoReflect() protoreflect.Message {
	mi := &file_ChapterStateNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChapterStateNotify.ProtoReflect.Descriptor instead.
func (*ChapterStateNotify) Descriptor() ([]byte, []int) {
	return file_ChapterStateNotify_proto_rawDescGZIP(), []int{0}
}

func (x *ChapterStateNotify) GetNeedBeginTime() *ChapterStateNotify_NeedBeginTime {
	if x != nil {
		return x.NeedBeginTime
	}
	return nil
}

func (x *ChapterStateNotify) GetNeedPlayerLevel() *ChapterStateNotify_NeedPlayerLevel {
	if x != nil {
		return x.NeedPlayerLevel
	}
	return nil
}

func (x *ChapterStateNotify) GetChapterState() ChapterState {
	if x != nil {
		return x.ChapterState
	}
	return ChapterState_CHAPTER_STATE_INVALID
}

func (x *ChapterStateNotify) GetChapterId() uint32 {
	if x != nil {
		return x.ChapterId
	}
	return 0
}

// Obf: MOEEEKPMIAO
type ChapterStateNotify_NeedPlayerLevel struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsLimit               bool   `protobuf:"varint,1,opt,name=is_limit,json=isLimit,proto3" json:"is_limit,omitempty"`
	ConfigNeedPlayerLevel uint32 `protobuf:"varint,11,opt,name=configNeedPlayerLevel,proto3" json:"configNeedPlayerLevel,omitempty"`
}

func (x *ChapterStateNotify_NeedPlayerLevel) Reset() {
	*x = ChapterStateNotify_NeedPlayerLevel{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ChapterStateNotify_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChapterStateNotify_NeedPlayerLevel) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChapterStateNotify_NeedPlayerLevel) ProtoMessage() {}

func (x *ChapterStateNotify_NeedPlayerLevel) ProtoReflect() protoreflect.Message {
	mi := &file_ChapterStateNotify_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChapterStateNotify_NeedPlayerLevel.ProtoReflect.Descriptor instead.
func (*ChapterStateNotify_NeedPlayerLevel) Descriptor() ([]byte, []int) {
	return file_ChapterStateNotify_proto_rawDescGZIP(), []int{0, 0}
}

func (x *ChapterStateNotify_NeedPlayerLevel) GetIsLimit() bool {
	if x != nil {
		return x.IsLimit
	}
	return false
}

func (x *ChapterStateNotify_NeedPlayerLevel) GetConfigNeedPlayerLevel() uint32 {
	if x != nil {
		return x.ConfigNeedPlayerLevel
	}
	return 0
}

// Obf: GEFDHMJCBLD
type ChapterStateNotify_NeedBeginTime struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ConfigNeedBeginTime uint32 `protobuf:"varint,5,opt,name=configNeedBeginTime,proto3" json:"configNeedBeginTime,omitempty"`
	IsLimit             bool   `protobuf:"varint,1,opt,name=is_limit,json=isLimit,proto3" json:"is_limit,omitempty"`
}

func (x *ChapterStateNotify_NeedBeginTime) Reset() {
	*x = ChapterStateNotify_NeedBeginTime{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ChapterStateNotify_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChapterStateNotify_NeedBeginTime) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChapterStateNotify_NeedBeginTime) ProtoMessage() {}

func (x *ChapterStateNotify_NeedBeginTime) ProtoReflect() protoreflect.Message {
	mi := &file_ChapterStateNotify_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChapterStateNotify_NeedBeginTime.ProtoReflect.Descriptor instead.
func (*ChapterStateNotify_NeedBeginTime) Descriptor() ([]byte, []int) {
	return file_ChapterStateNotify_proto_rawDescGZIP(), []int{0, 1}
}

func (x *ChapterStateNotify_NeedBeginTime) GetConfigNeedBeginTime() uint32 {
	if x != nil {
		return x.ConfigNeedBeginTime
	}
	return 0
}

func (x *ChapterStateNotify_NeedBeginTime) GetIsLimit() bool {
	if x != nil {
		return x.IsLimit
	}
	return false
}

var File_ChapterStateNotify_proto protoreflect.FileDescriptor

var file_ChapterStateNotify_proto_rawDesc = []byte{
	0x0a, 0x18, 0x43, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x4e, 0x6f,
	0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x43, 0x68, 0x61, 0x70,
	0x74, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc5,
	0x03, 0x0a, 0x12, 0x43, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x4e,
	0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x49, 0x0a, 0x0f, 0x6e, 0x65, 0x65, 0x64, 0x5f, 0x62, 0x65,
	0x67, 0x69, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x21,
	0x2e, 0x43, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x4e, 0x6f, 0x74,
	0x69, 0x66, 0x79, 0x2e, 0x4e, 0x65, 0x65, 0x64, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d,
	0x65, 0x52, 0x0d, 0x6e, 0x65, 0x65, 0x64, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x4f, 0x0a, 0x11, 0x6e, 0x65, 0x65, 0x64, 0x5f, 0x70, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x5f,
	0x6c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x43, 0x68,
	0x61, 0x70, 0x74, 0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79,
	0x2e, 0x4e, 0x65, 0x65, 0x64, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c,
	0x52, 0x0f, 0x6e, 0x65, 0x65, 0x64, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65,
	0x6c, 0x12, 0x32, 0x0a, 0x0d, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72, 0x5f, 0x73, 0x74, 0x61,
	0x74, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0d, 0x2e, 0x43, 0x68, 0x61, 0x70, 0x74,
	0x65, 0x72, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x0c, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x68, 0x61, 0x70, 0x74, 0x65, 0x72,
	0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x63, 0x68, 0x61, 0x70, 0x74,
	0x65, 0x72, 0x49, 0x64, 0x1a, 0x62, 0x0a, 0x0f, 0x4e, 0x65, 0x65, 0x64, 0x50, 0x6c, 0x61, 0x79,
	0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x19, 0x0a, 0x08, 0x69, 0x73, 0x5f, 0x6c, 0x69,
	0x6d, 0x69, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x69, 0x73, 0x4c, 0x69, 0x6d,
	0x69, 0x74, 0x12, 0x34, 0x0a, 0x15, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x4e, 0x65, 0x65, 0x64,
	0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x0b, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x15, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x4e, 0x65, 0x65, 0x64, 0x50, 0x6c, 0x61,
	0x79, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x1a, 0x5c, 0x0a, 0x0d, 0x4e, 0x65, 0x65, 0x64,
	0x42, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x30, 0x0a, 0x13, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x4e, 0x65, 0x65, 0x64, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x13, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x4e, 0x65,
	0x65, 0x64, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x69,
	0x73, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x69,
	0x73, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ChapterStateNotify_proto_rawDescOnce sync.Once
	file_ChapterStateNotify_proto_rawDescData = file_ChapterStateNotify_proto_rawDesc
)

func file_ChapterStateNotify_proto_rawDescGZIP() []byte {
	file_ChapterStateNotify_proto_rawDescOnce.Do(func() {
		file_ChapterStateNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_ChapterStateNotify_proto_rawDescData)
	})
	return file_ChapterStateNotify_proto_rawDescData
}

var file_ChapterStateNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_ChapterStateNotify_proto_goTypes = []interface{}{
	(*ChapterStateNotify)(nil),                 // 0: ChapterStateNotify
	(*ChapterStateNotify_NeedPlayerLevel)(nil), // 1: ChapterStateNotify.NeedPlayerLevel
	(*ChapterStateNotify_NeedBeginTime)(nil),   // 2: ChapterStateNotify.NeedBeginTime
	(ChapterState)(0),                          // 3: ChapterState
}
var file_ChapterStateNotify_proto_depIdxs = []int32{
	2, // 0: ChapterStateNotify.need_begin_time:type_name -> ChapterStateNotify.NeedBeginTime
	1, // 1: ChapterStateNotify.need_player_level:type_name -> ChapterStateNotify.NeedPlayerLevel
	3, // 2: ChapterStateNotify.chapter_state:type_name -> ChapterState
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_ChapterStateNotify_proto_init() }
func file_ChapterStateNotify_proto_init() {
	if File_ChapterStateNotify_proto != nil {
		return
	}
	file_ChapterState_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ChapterStateNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChapterStateNotify); i {
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
		file_ChapterStateNotify_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChapterStateNotify_NeedPlayerLevel); i {
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
		file_ChapterStateNotify_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChapterStateNotify_NeedBeginTime); i {
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
			RawDescriptor: file_ChapterStateNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ChapterStateNotify_proto_goTypes,
		DependencyIndexes: file_ChapterStateNotify_proto_depIdxs,
		MessageInfos:      file_ChapterStateNotify_proto_msgTypes,
	}.Build()
	File_ChapterStateNotify_proto = out.File
	file_ChapterStateNotify_proto_rawDesc = nil
	file_ChapterStateNotify_proto_goTypes = nil
	file_ChapterStateNotify_proto_depIdxs = nil
}
