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
// source: PlantFlowerGiveFriendFlowerReq.proto

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

// CmdId: 512
// Obf: BLIGHIHGCGN
type PlantFlowerGiveFriendFlowerReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ScheduleId   uint32            `protobuf:"varint,6,opt,name=schedule_id,json=scheduleId,proto3" json:"schedule_id,omitempty"`
	Uid          uint32            `protobuf:"varint,11,opt,name=uid,proto3" json:"uid,omitempty"`
	FlowerNumMap map[uint32]uint32 `protobuf:"bytes,9,rep,name=flower_num_map,json=flowerNumMap,proto3" json:"flower_num_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
}

func (x *PlantFlowerGiveFriendFlowerReq) Reset() {
	*x = PlantFlowerGiveFriendFlowerReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_PlantFlowerGiveFriendFlowerReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PlantFlowerGiveFriendFlowerReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PlantFlowerGiveFriendFlowerReq) ProtoMessage() {}

func (x *PlantFlowerGiveFriendFlowerReq) ProtoReflect() protoreflect.Message {
	mi := &file_PlantFlowerGiveFriendFlowerReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PlantFlowerGiveFriendFlowerReq.ProtoReflect.Descriptor instead.
func (*PlantFlowerGiveFriendFlowerReq) Descriptor() ([]byte, []int) {
	return file_PlantFlowerGiveFriendFlowerReq_proto_rawDescGZIP(), []int{0}
}

func (x *PlantFlowerGiveFriendFlowerReq) GetScheduleId() uint32 {
	if x != nil {
		return x.ScheduleId
	}
	return 0
}

func (x *PlantFlowerGiveFriendFlowerReq) GetUid() uint32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

func (x *PlantFlowerGiveFriendFlowerReq) GetFlowerNumMap() map[uint32]uint32 {
	if x != nil {
		return x.FlowerNumMap
	}
	return nil
}

var File_PlantFlowerGiveFriendFlowerReq_proto protoreflect.FileDescriptor

var file_PlantFlowerGiveFriendFlowerReq_proto_rawDesc = []byte{
	0x0a, 0x24, 0x50, 0x6c, 0x61, 0x6e, 0x74, 0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x47, 0x69, 0x76,
	0x65, 0x46, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x52, 0x65, 0x71,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xed, 0x01, 0x0a, 0x1e, 0x50, 0x6c, 0x61, 0x6e, 0x74,
	0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x47, 0x69, 0x76, 0x65, 0x46, 0x72, 0x69, 0x65, 0x6e, 0x64,
	0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x52, 0x65, 0x71, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x63, 0x68,
	0x65, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a,
	0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x49, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x69,
	0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12, 0x57, 0x0a, 0x0e,
	0x66, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x5f, 0x6e, 0x75, 0x6d, 0x5f, 0x6d, 0x61, 0x70, 0x18, 0x09,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x50, 0x6c, 0x61, 0x6e, 0x74, 0x46, 0x6c, 0x6f, 0x77,
	0x65, 0x72, 0x47, 0x69, 0x76, 0x65, 0x46, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x46, 0x6c, 0x6f, 0x77,
	0x65, 0x72, 0x52, 0x65, 0x71, 0x2e, 0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x4e, 0x75, 0x6d, 0x4d,
	0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0c, 0x66, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x4e,
	0x75, 0x6d, 0x4d, 0x61, 0x70, 0x1a, 0x3f, 0x0a, 0x11, 0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x4e,
	0x75, 0x6d, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_PlantFlowerGiveFriendFlowerReq_proto_rawDescOnce sync.Once
	file_PlantFlowerGiveFriendFlowerReq_proto_rawDescData = file_PlantFlowerGiveFriendFlowerReq_proto_rawDesc
)

func file_PlantFlowerGiveFriendFlowerReq_proto_rawDescGZIP() []byte {
	file_PlantFlowerGiveFriendFlowerReq_proto_rawDescOnce.Do(func() {
		file_PlantFlowerGiveFriendFlowerReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_PlantFlowerGiveFriendFlowerReq_proto_rawDescData)
	})
	return file_PlantFlowerGiveFriendFlowerReq_proto_rawDescData
}

var file_PlantFlowerGiveFriendFlowerReq_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_PlantFlowerGiveFriendFlowerReq_proto_goTypes = []interface{}{
	(*PlantFlowerGiveFriendFlowerReq)(nil), // 0: PlantFlowerGiveFriendFlowerReq
	nil,                                    // 1: PlantFlowerGiveFriendFlowerReq.FlowerNumMapEntry
}
var file_PlantFlowerGiveFriendFlowerReq_proto_depIdxs = []int32{
	1, // 0: PlantFlowerGiveFriendFlowerReq.flower_num_map:type_name -> PlantFlowerGiveFriendFlowerReq.FlowerNumMapEntry
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_PlantFlowerGiveFriendFlowerReq_proto_init() }
func file_PlantFlowerGiveFriendFlowerReq_proto_init() {
	if File_PlantFlowerGiveFriendFlowerReq_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_PlantFlowerGiveFriendFlowerReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PlantFlowerGiveFriendFlowerReq); i {
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
			RawDescriptor: file_PlantFlowerGiveFriendFlowerReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PlantFlowerGiveFriendFlowerReq_proto_goTypes,
		DependencyIndexes: file_PlantFlowerGiveFriendFlowerReq_proto_depIdxs,
		MessageInfos:      file_PlantFlowerGiveFriendFlowerReq_proto_msgTypes,
	}.Build()
	File_PlantFlowerGiveFriendFlowerReq_proto = out.File
	file_PlantFlowerGiveFriendFlowerReq_proto_rawDesc = nil
	file_PlantFlowerGiveFriendFlowerReq_proto_goTypes = nil
	file_PlantFlowerGiveFriendFlowerReq_proto_depIdxs = nil
}
