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
// source: TowerLevelStarCondNotify.proto

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

// CmdId: 2042
// Obf: ALNLBDBGCAE
type TowerLevelStarCondNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FloorId      uint32                    `protobuf:"varint,9,opt,name=floor_id,json=floorId,proto3" json:"floor_id,omitempty"`
	LevelIndex   uint32                    `protobuf:"varint,2,opt,name=level_index,json=levelIndex,proto3" json:"level_index,omitempty"`
	CondDataList []*TowerLevelStarCondData `protobuf:"bytes,10,rep,name=cond_data_list,json=condDataList,proto3" json:"cond_data_list,omitempty"`
}

func (x *TowerLevelStarCondNotify) Reset() {
	*x = TowerLevelStarCondNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_TowerLevelStarCondNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TowerLevelStarCondNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TowerLevelStarCondNotify) ProtoMessage() {}

func (x *TowerLevelStarCondNotify) ProtoReflect() protoreflect.Message {
	mi := &file_TowerLevelStarCondNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TowerLevelStarCondNotify.ProtoReflect.Descriptor instead.
func (*TowerLevelStarCondNotify) Descriptor() ([]byte, []int) {
	return file_TowerLevelStarCondNotify_proto_rawDescGZIP(), []int{0}
}

func (x *TowerLevelStarCondNotify) GetFloorId() uint32 {
	if x != nil {
		return x.FloorId
	}
	return 0
}

func (x *TowerLevelStarCondNotify) GetLevelIndex() uint32 {
	if x != nil {
		return x.LevelIndex
	}
	return 0
}

func (x *TowerLevelStarCondNotify) GetCondDataList() []*TowerLevelStarCondData {
	if x != nil {
		return x.CondDataList
	}
	return nil
}

var File_TowerLevelStarCondNotify_proto protoreflect.FileDescriptor

var file_TowerLevelStarCondNotify_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x53, 0x74, 0x61, 0x72,
	0x43, 0x6f, 0x6e, 0x64, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1c, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x53, 0x74, 0x61, 0x72,
	0x43, 0x6f, 0x6e, 0x64, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x95,
	0x01, 0x0a, 0x18, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x53, 0x74, 0x61,
	0x72, 0x43, 0x6f, 0x6e, 0x64, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x19, 0x0a, 0x08, 0x66,
	0x6c, 0x6f, 0x6f, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x66,
	0x6c, 0x6f, 0x6f, 0x72, 0x49, 0x64, 0x12, 0x1f, 0x0a, 0x0b, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x5f,
	0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x3d, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x64, 0x5f,
	0x64, 0x61, 0x74, 0x61, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x17, 0x2e, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x53, 0x74, 0x61, 0x72,
	0x43, 0x6f, 0x6e, 0x64, 0x44, 0x61, 0x74, 0x61, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x64, 0x44, 0x61,
	0x74, 0x61, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_TowerLevelStarCondNotify_proto_rawDescOnce sync.Once
	file_TowerLevelStarCondNotify_proto_rawDescData = file_TowerLevelStarCondNotify_proto_rawDesc
)

func file_TowerLevelStarCondNotify_proto_rawDescGZIP() []byte {
	file_TowerLevelStarCondNotify_proto_rawDescOnce.Do(func() {
		file_TowerLevelStarCondNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_TowerLevelStarCondNotify_proto_rawDescData)
	})
	return file_TowerLevelStarCondNotify_proto_rawDescData
}

var file_TowerLevelStarCondNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_TowerLevelStarCondNotify_proto_goTypes = []interface{}{
	(*TowerLevelStarCondNotify)(nil), // 0: TowerLevelStarCondNotify
	(*TowerLevelStarCondData)(nil),   // 1: TowerLevelStarCondData
}
var file_TowerLevelStarCondNotify_proto_depIdxs = []int32{
	1, // 0: TowerLevelStarCondNotify.cond_data_list:type_name -> TowerLevelStarCondData
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_TowerLevelStarCondNotify_proto_init() }
func file_TowerLevelStarCondNotify_proto_init() {
	if File_TowerLevelStarCondNotify_proto != nil {
		return
	}
	file_TowerLevelStarCondData_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_TowerLevelStarCondNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TowerLevelStarCondNotify); i {
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
			RawDescriptor: file_TowerLevelStarCondNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_TowerLevelStarCondNotify_proto_goTypes,
		DependencyIndexes: file_TowerLevelStarCondNotify_proto_depIdxs,
		MessageInfos:      file_TowerLevelStarCondNotify_proto_msgTypes,
	}.Build()
	File_TowerLevelStarCondNotify_proto = out.File
	file_TowerLevelStarCondNotify_proto_rawDesc = nil
	file_TowerLevelStarCondNotify_proto_goTypes = nil
	file_TowerLevelStarCondNotify_proto_depIdxs = nil
}
