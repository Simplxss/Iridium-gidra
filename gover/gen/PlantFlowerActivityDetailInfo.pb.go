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
// source: PlantFlowerActivityDetailInfo.proto

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

// Obf: EFJGNELKFMH
type PlantFlowerActivityDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TodaySeedRewardId uint32            `protobuf:"varint,10,opt,name=today_seed_reward_id,json=todaySeedRewardId,proto3" json:"today_seed_reward_id,omitempty"`
	DAOOKPHJPKA       map[uint32]uint32 `protobuf:"bytes,9,rep,name=DAOOKPHJPKA,proto3" json:"DAOOKPHJPKA,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	IsContentClosed   bool              `protobuf:"varint,5,opt,name=is_content_closed,json=isContentClosed,proto3" json:"is_content_closed,omitempty"`
	IsTodayHasAwarded bool              `protobuf:"varint,2,opt,name=is_today_has_awarded,json=isTodayHasAwarded,proto3" json:"is_today_has_awarded,omitempty"`
	IPADJEILKIB       map[uint32]uint32 `protobuf:"bytes,4,rep,name=IPADJEILKIB,proto3" json:"IPADJEILKIB,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	DayIndex          uint32            `protobuf:"varint,8,opt,name=day_index,json=dayIndex,proto3" json:"day_index,omitempty"`
}

func (x *PlantFlowerActivityDetailInfo) Reset() {
	*x = PlantFlowerActivityDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_PlantFlowerActivityDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PlantFlowerActivityDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PlantFlowerActivityDetailInfo) ProtoMessage() {}

func (x *PlantFlowerActivityDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_PlantFlowerActivityDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PlantFlowerActivityDetailInfo.ProtoReflect.Descriptor instead.
func (*PlantFlowerActivityDetailInfo) Descriptor() ([]byte, []int) {
	return file_PlantFlowerActivityDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *PlantFlowerActivityDetailInfo) GetTodaySeedRewardId() uint32 {
	if x != nil {
		return x.TodaySeedRewardId
	}
	return 0
}

func (x *PlantFlowerActivityDetailInfo) GetDAOOKPHJPKA() map[uint32]uint32 {
	if x != nil {
		return x.DAOOKPHJPKA
	}
	return nil
}

func (x *PlantFlowerActivityDetailInfo) GetIsContentClosed() bool {
	if x != nil {
		return x.IsContentClosed
	}
	return false
}

func (x *PlantFlowerActivityDetailInfo) GetIsTodayHasAwarded() bool {
	if x != nil {
		return x.IsTodayHasAwarded
	}
	return false
}

func (x *PlantFlowerActivityDetailInfo) GetIPADJEILKIB() map[uint32]uint32 {
	if x != nil {
		return x.IPADJEILKIB
	}
	return nil
}

func (x *PlantFlowerActivityDetailInfo) GetDayIndex() uint32 {
	if x != nil {
		return x.DayIndex
	}
	return 0
}

var File_PlantFlowerActivityDetailInfo_proto protoreflect.FileDescriptor

var file_PlantFlowerActivityDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x23, 0x50, 0x6c, 0x61, 0x6e, 0x74, 0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x41, 0x63, 0x74,
	0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf0, 0x03, 0x0a, 0x1d, 0x50, 0x6c, 0x61, 0x6e, 0x74, 0x46,
	0x6c, 0x6f, 0x77, 0x65, 0x72, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2f, 0x0a, 0x14, 0x74, 0x6f, 0x64, 0x61, 0x79,
	0x5f, 0x73, 0x65, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x77, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x64, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x11, 0x74, 0x6f, 0x64, 0x61, 0x79, 0x53, 0x65, 0x65, 0x64,
	0x52, 0x65, 0x77, 0x61, 0x72, 0x64, 0x49, 0x64, 0x12, 0x51, 0x0a, 0x0b, 0x44, 0x41, 0x4f, 0x4f,
	0x4b, 0x50, 0x48, 0x4a, 0x50, 0x4b, 0x41, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2f, 0x2e,
	0x50, 0x6c, 0x61, 0x6e, 0x74, 0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x41, 0x63, 0x74, 0x69, 0x76,
	0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x44, 0x41,
	0x4f, 0x4f, 0x4b, 0x50, 0x48, 0x4a, 0x50, 0x4b, 0x41, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b,
	0x44, 0x41, 0x4f, 0x4f, 0x4b, 0x50, 0x48, 0x4a, 0x50, 0x4b, 0x41, 0x12, 0x2a, 0x0a, 0x11, 0x69,
	0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x64,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0f, 0x69, 0x73, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
	0x74, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x12, 0x2f, 0x0a, 0x14, 0x69, 0x73, 0x5f, 0x74, 0x6f,
	0x64, 0x61, 0x79, 0x5f, 0x68, 0x61, 0x73, 0x5f, 0x61, 0x77, 0x61, 0x72, 0x64, 0x65, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x11, 0x69, 0x73, 0x54, 0x6f, 0x64, 0x61, 0x79, 0x48, 0x61,
	0x73, 0x41, 0x77, 0x61, 0x72, 0x64, 0x65, 0x64, 0x12, 0x51, 0x0a, 0x0b, 0x49, 0x50, 0x41, 0x44,
	0x4a, 0x45, 0x49, 0x4c, 0x4b, 0x49, 0x42, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2f, 0x2e,
	0x50, 0x6c, 0x61, 0x6e, 0x74, 0x46, 0x6c, 0x6f, 0x77, 0x65, 0x72, 0x41, 0x63, 0x74, 0x69, 0x76,
	0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x49, 0x50,
	0x41, 0x44, 0x4a, 0x45, 0x49, 0x4c, 0x4b, 0x49, 0x42, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b,
	0x49, 0x50, 0x41, 0x44, 0x4a, 0x45, 0x49, 0x4c, 0x4b, 0x49, 0x42, 0x12, 0x1b, 0x0a, 0x09, 0x64,
	0x61, 0x79, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08,
	0x64, 0x61, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x1a, 0x3e, 0x0a, 0x10, 0x44, 0x41, 0x4f, 0x4f,
	0x4b, 0x50, 0x48, 0x4a, 0x50, 0x4b, 0x41, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x3e, 0x0a, 0x10, 0x49, 0x50, 0x41, 0x44,
	0x4a, 0x45, 0x49, 0x4c, 0x4b, 0x49, 0x42, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_PlantFlowerActivityDetailInfo_proto_rawDescOnce sync.Once
	file_PlantFlowerActivityDetailInfo_proto_rawDescData = file_PlantFlowerActivityDetailInfo_proto_rawDesc
)

func file_PlantFlowerActivityDetailInfo_proto_rawDescGZIP() []byte {
	file_PlantFlowerActivityDetailInfo_proto_rawDescOnce.Do(func() {
		file_PlantFlowerActivityDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_PlantFlowerActivityDetailInfo_proto_rawDescData)
	})
	return file_PlantFlowerActivityDetailInfo_proto_rawDescData
}

var file_PlantFlowerActivityDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_PlantFlowerActivityDetailInfo_proto_goTypes = []interface{}{
	(*PlantFlowerActivityDetailInfo)(nil), // 0: PlantFlowerActivityDetailInfo
	nil,                                   // 1: PlantFlowerActivityDetailInfo.DAOOKPHJPKAEntry
	nil,                                   // 2: PlantFlowerActivityDetailInfo.IPADJEILKIBEntry
}
var file_PlantFlowerActivityDetailInfo_proto_depIdxs = []int32{
	1, // 0: PlantFlowerActivityDetailInfo.DAOOKPHJPKA:type_name -> PlantFlowerActivityDetailInfo.DAOOKPHJPKAEntry
	2, // 1: PlantFlowerActivityDetailInfo.IPADJEILKIB:type_name -> PlantFlowerActivityDetailInfo.IPADJEILKIBEntry
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_PlantFlowerActivityDetailInfo_proto_init() }
func file_PlantFlowerActivityDetailInfo_proto_init() {
	if File_PlantFlowerActivityDetailInfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_PlantFlowerActivityDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PlantFlowerActivityDetailInfo); i {
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
			RawDescriptor: file_PlantFlowerActivityDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_PlantFlowerActivityDetailInfo_proto_goTypes,
		DependencyIndexes: file_PlantFlowerActivityDetailInfo_proto_depIdxs,
		MessageInfos:      file_PlantFlowerActivityDetailInfo_proto_msgTypes,
	}.Build()
	File_PlantFlowerActivityDetailInfo_proto = out.File
	file_PlantFlowerActivityDetailInfo_proto_rawDesc = nil
	file_PlantFlowerActivityDetailInfo_proto_goTypes = nil
	file_PlantFlowerActivityDetailInfo_proto_depIdxs = nil
}
