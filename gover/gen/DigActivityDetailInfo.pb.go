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
// source: DigActivityDetailInfo.proto

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

// Obf: BNNCLBHONBI
type DigActivityDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StageId          uint32          `protobuf:"varint,10,opt,name=stage_id,json=stageId,proto3" json:"stage_id,omitempty"`
	StageIdList      []uint32        `protobuf:"varint,4,rep,packed,name=stage_id_list,json=stageIdList,proto3" json:"stage_id_list,omitempty"`
	DigMarkPointList []*DigMarkPoint `protobuf:"bytes,14,rep,name=dig_mark_point_list,json=digMarkPointList,proto3" json:"dig_mark_point_list,omitempty"`
}

func (x *DigActivityDetailInfo) Reset() {
	*x = DigActivityDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_DigActivityDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DigActivityDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DigActivityDetailInfo) ProtoMessage() {}

func (x *DigActivityDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_DigActivityDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DigActivityDetailInfo.ProtoReflect.Descriptor instead.
func (*DigActivityDetailInfo) Descriptor() ([]byte, []int) {
	return file_DigActivityDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *DigActivityDetailInfo) GetStageId() uint32 {
	if x != nil {
		return x.StageId
	}
	return 0
}

func (x *DigActivityDetailInfo) GetStageIdList() []uint32 {
	if x != nil {
		return x.StageIdList
	}
	return nil
}

func (x *DigActivityDetailInfo) GetDigMarkPointList() []*DigMarkPoint {
	if x != nil {
		return x.DigMarkPointList
	}
	return nil
}

var File_DigActivityDetailInfo_proto protoreflect.FileDescriptor

var file_DigActivityDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x44, 0x69, 0x67, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x44,
	0x69, 0x67, 0x4d, 0x61, 0x72, 0x6b, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x94, 0x01, 0x0a, 0x15, 0x44, 0x69, 0x67, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
	0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x19, 0x0a, 0x08, 0x73,
	0x74, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x73,
	0x74, 0x61, 0x67, 0x65, 0x49, 0x64, 0x12, 0x22, 0x0a, 0x0d, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f,
	0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b, 0x73,
	0x74, 0x61, 0x67, 0x65, 0x49, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x3c, 0x0a, 0x13, 0x64, 0x69,
	0x67, 0x5f, 0x6d, 0x61, 0x72, 0x6b, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x44, 0x69, 0x67, 0x4d, 0x61, 0x72,
	0x6b, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x10, 0x64, 0x69, 0x67, 0x4d, 0x61, 0x72, 0x6b, 0x50,
	0x6f, 0x69, 0x6e, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_DigActivityDetailInfo_proto_rawDescOnce sync.Once
	file_DigActivityDetailInfo_proto_rawDescData = file_DigActivityDetailInfo_proto_rawDesc
)

func file_DigActivityDetailInfo_proto_rawDescGZIP() []byte {
	file_DigActivityDetailInfo_proto_rawDescOnce.Do(func() {
		file_DigActivityDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_DigActivityDetailInfo_proto_rawDescData)
	})
	return file_DigActivityDetailInfo_proto_rawDescData
}

var file_DigActivityDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_DigActivityDetailInfo_proto_goTypes = []interface{}{
	(*DigActivityDetailInfo)(nil), // 0: DigActivityDetailInfo
	(*DigMarkPoint)(nil),          // 1: DigMarkPoint
}
var file_DigActivityDetailInfo_proto_depIdxs = []int32{
	1, // 0: DigActivityDetailInfo.dig_mark_point_list:type_name -> DigMarkPoint
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_DigActivityDetailInfo_proto_init() }
func file_DigActivityDetailInfo_proto_init() {
	if File_DigActivityDetailInfo_proto != nil {
		return
	}
	file_DigMarkPoint_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_DigActivityDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DigActivityDetailInfo); i {
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
			RawDescriptor: file_DigActivityDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DigActivityDetailInfo_proto_goTypes,
		DependencyIndexes: file_DigActivityDetailInfo_proto_depIdxs,
		MessageInfos:      file_DigActivityDetailInfo_proto_msgTypes,
	}.Build()
	File_DigActivityDetailInfo_proto = out.File
	file_DigActivityDetailInfo_proto_rawDesc = nil
	file_DigActivityDetailInfo_proto_goTypes = nil
	file_DigActivityDetailInfo_proto_depIdxs = nil
}
