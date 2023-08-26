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
// source: RogueCellInfo.proto

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

// Obf: LKOLNEHLBLB
type RogueCellInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CellConfigId uint32         `protobuf:"varint,8,opt,name=cell_config_id,json=cellConfigId,proto3" json:"cell_config_id,omitempty"`
	DungeonId    uint32         `protobuf:"varint,1,opt,name=dungeon_id,json=dungeonId,proto3" json:"dungeon_id,omitempty"`
	CellId       uint32         `protobuf:"varint,11,opt,name=cell_id,json=cellId,proto3" json:"cell_id,omitempty"`
	State        RogueCellState `protobuf:"varint,3,opt,name=state,proto3,enum=RogueCellState" json:"state,omitempty"`
	CellType     uint32         `protobuf:"varint,13,opt,name=cell_type,json=cellType,proto3" json:"cell_type,omitempty"`
}

func (x *RogueCellInfo) Reset() {
	*x = RogueCellInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_RogueCellInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RogueCellInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RogueCellInfo) ProtoMessage() {}

func (x *RogueCellInfo) ProtoReflect() protoreflect.Message {
	mi := &file_RogueCellInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RogueCellInfo.ProtoReflect.Descriptor instead.
func (*RogueCellInfo) Descriptor() ([]byte, []int) {
	return file_RogueCellInfo_proto_rawDescGZIP(), []int{0}
}

func (x *RogueCellInfo) GetCellConfigId() uint32 {
	if x != nil {
		return x.CellConfigId
	}
	return 0
}

func (x *RogueCellInfo) GetDungeonId() uint32 {
	if x != nil {
		return x.DungeonId
	}
	return 0
}

func (x *RogueCellInfo) GetCellId() uint32 {
	if x != nil {
		return x.CellId
	}
	return 0
}

func (x *RogueCellInfo) GetState() RogueCellState {
	if x != nil {
		return x.State
	}
	return RogueCellState_ROGUE_CELL_NONE
}

func (x *RogueCellInfo) GetCellType() uint32 {
	if x != nil {
		return x.CellType
	}
	return 0
}

var File_RogueCellInfo_proto protoreflect.FileDescriptor

var file_RogueCellInfo_proto_rawDesc = []byte{
	0x0a, 0x13, 0x52, 0x6f, 0x67, 0x75, 0x65, 0x43, 0x65, 0x6c, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x52, 0x6f, 0x67, 0x75, 0x65, 0x43, 0x65, 0x6c, 0x6c,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb1, 0x01, 0x0a, 0x0d,
	0x52, 0x6f, 0x67, 0x75, 0x65, 0x43, 0x65, 0x6c, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x24, 0x0a,
	0x0e, 0x63, 0x65, 0x6c, 0x6c, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x69, 0x64, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x63, 0x65, 0x6c, 0x6c, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x64, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e,
	0x49, 0x64, 0x12, 0x17, 0x0a, 0x07, 0x63, 0x65, 0x6c, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x0b, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x06, 0x63, 0x65, 0x6c, 0x6c, 0x49, 0x64, 0x12, 0x25, 0x0a, 0x05, 0x73,
	0x74, 0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0f, 0x2e, 0x52, 0x6f, 0x67,
	0x75, 0x65, 0x43, 0x65, 0x6c, 0x6c, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x05, 0x73, 0x74, 0x61,
	0x74, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x65, 0x6c, 0x6c, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x63, 0x65, 0x6c, 0x6c, 0x54, 0x79, 0x70, 0x65, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_RogueCellInfo_proto_rawDescOnce sync.Once
	file_RogueCellInfo_proto_rawDescData = file_RogueCellInfo_proto_rawDesc
)

func file_RogueCellInfo_proto_rawDescGZIP() []byte {
	file_RogueCellInfo_proto_rawDescOnce.Do(func() {
		file_RogueCellInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_RogueCellInfo_proto_rawDescData)
	})
	return file_RogueCellInfo_proto_rawDescData
}

var file_RogueCellInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_RogueCellInfo_proto_goTypes = []interface{}{
	(*RogueCellInfo)(nil), // 0: RogueCellInfo
	(RogueCellState)(0),   // 1: RogueCellState
}
var file_RogueCellInfo_proto_depIdxs = []int32{
	1, // 0: RogueCellInfo.state:type_name -> RogueCellState
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_RogueCellInfo_proto_init() }
func file_RogueCellInfo_proto_init() {
	if File_RogueCellInfo_proto != nil {
		return
	}
	file_RogueCellState_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_RogueCellInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RogueCellInfo); i {
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
			RawDescriptor: file_RogueCellInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_RogueCellInfo_proto_goTypes,
		DependencyIndexes: file_RogueCellInfo_proto_depIdxs,
		MessageInfos:      file_RogueCellInfo_proto_msgTypes,
	}.Build()
	File_RogueCellInfo_proto = out.File
	file_RogueCellInfo_proto_rawDesc = nil
	file_RogueCellInfo_proto_goTypes = nil
	file_RogueCellInfo_proto_depIdxs = nil
}
