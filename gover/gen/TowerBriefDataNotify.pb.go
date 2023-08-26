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
// source: TowerBriefDataNotify.proto

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

// CmdId: 28206
// Obf: FDNCNACOCMJ
type TowerBriefDataNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IPKPGKDBNBL             uint32 `protobuf:"varint,5,opt,name=IPKPGKDBNBL,proto3" json:"IPKPGKDBNBL,omitempty"`
	NextScheduleChangeTime  uint32 `protobuf:"varint,15,opt,name=next_schedule_change_time,json=nextScheduleChangeTime,proto3" json:"next_schedule_change_time,omitempty"`
	TowerScheduleId         uint32 `protobuf:"varint,9,opt,name=tower_schedule_id,json=towerScheduleId,proto3" json:"tower_schedule_id,omitempty"`
	ScheduleStartTime       uint32 `protobuf:"varint,14,opt,name=schedule_start_time,json=scheduleStartTime,proto3" json:"schedule_start_time,omitempty"`
	OJCGNKBJNBG             uint32 `protobuf:"varint,13,opt,name=OJCGNKBJNBG,proto3" json:"OJCGNKBJNBG,omitempty"`
	CLDPGFCBJEA             uint32 `protobuf:"varint,2,opt,name=CLDPGFCBJEA,proto3" json:"CLDPGFCBJEA,omitempty"`
	IsFinishedEntranceFloor bool   `protobuf:"varint,4,opt,name=is_finished_entrance_floor,json=isFinishedEntranceFloor,proto3" json:"is_finished_entrance_floor,omitempty"`
}

func (x *TowerBriefDataNotify) Reset() {
	*x = TowerBriefDataNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_TowerBriefDataNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TowerBriefDataNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TowerBriefDataNotify) ProtoMessage() {}

func (x *TowerBriefDataNotify) ProtoReflect() protoreflect.Message {
	mi := &file_TowerBriefDataNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TowerBriefDataNotify.ProtoReflect.Descriptor instead.
func (*TowerBriefDataNotify) Descriptor() ([]byte, []int) {
	return file_TowerBriefDataNotify_proto_rawDescGZIP(), []int{0}
}

func (x *TowerBriefDataNotify) GetIPKPGKDBNBL() uint32 {
	if x != nil {
		return x.IPKPGKDBNBL
	}
	return 0
}

func (x *TowerBriefDataNotify) GetNextScheduleChangeTime() uint32 {
	if x != nil {
		return x.NextScheduleChangeTime
	}
	return 0
}

func (x *TowerBriefDataNotify) GetTowerScheduleId() uint32 {
	if x != nil {
		return x.TowerScheduleId
	}
	return 0
}

func (x *TowerBriefDataNotify) GetScheduleStartTime() uint32 {
	if x != nil {
		return x.ScheduleStartTime
	}
	return 0
}

func (x *TowerBriefDataNotify) GetOJCGNKBJNBG() uint32 {
	if x != nil {
		return x.OJCGNKBJNBG
	}
	return 0
}

func (x *TowerBriefDataNotify) GetCLDPGFCBJEA() uint32 {
	if x != nil {
		return x.CLDPGFCBJEA
	}
	return 0
}

func (x *TowerBriefDataNotify) GetIsFinishedEntranceFloor() bool {
	if x != nil {
		return x.IsFinishedEntranceFloor
	}
	return false
}

var File_TowerBriefDataNotify_proto protoreflect.FileDescriptor

var file_TowerBriefDataNotify_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x42, 0x72, 0x69, 0x65, 0x66, 0x44, 0x61, 0x74, 0x61,
	0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd0, 0x02, 0x0a,
	0x14, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x42, 0x72, 0x69, 0x65, 0x66, 0x44, 0x61, 0x74, 0x61, 0x4e,
	0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x20, 0x0a, 0x0b, 0x49, 0x50, 0x4b, 0x50, 0x47, 0x4b, 0x44,
	0x42, 0x4e, 0x42, 0x4c, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x49, 0x50, 0x4b, 0x50,
	0x47, 0x4b, 0x44, 0x42, 0x4e, 0x42, 0x4c, 0x12, 0x39, 0x0a, 0x19, 0x6e, 0x65, 0x78, 0x74, 0x5f,
	0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x16, 0x6e, 0x65, 0x78, 0x74,
	0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x2a, 0x0a, 0x11, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x5f, 0x73, 0x63, 0x68, 0x65,
	0x64, 0x75, 0x6c, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x74,
	0x6f, 0x77, 0x65, 0x72, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x49, 0x64, 0x12, 0x2e,
	0x0a, 0x13, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x11, 0x73, 0x63, 0x68,
	0x65, 0x64, 0x75, 0x6c, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x20,
	0x0a, 0x0b, 0x4f, 0x4a, 0x43, 0x47, 0x4e, 0x4b, 0x42, 0x4a, 0x4e, 0x42, 0x47, 0x18, 0x0d, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4f, 0x4a, 0x43, 0x47, 0x4e, 0x4b, 0x42, 0x4a, 0x4e, 0x42, 0x47,
	0x12, 0x20, 0x0a, 0x0b, 0x43, 0x4c, 0x44, 0x50, 0x47, 0x46, 0x43, 0x42, 0x4a, 0x45, 0x41, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x43, 0x4c, 0x44, 0x50, 0x47, 0x46, 0x43, 0x42, 0x4a,
	0x45, 0x41, 0x12, 0x3b, 0x0a, 0x1a, 0x69, 0x73, 0x5f, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x65,
	0x64, 0x5f, 0x65, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x66, 0x6c, 0x6f, 0x6f, 0x72,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x17, 0x69, 0x73, 0x46, 0x69, 0x6e, 0x69, 0x73, 0x68,
	0x65, 0x64, 0x45, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x46, 0x6c, 0x6f, 0x6f, 0x72, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_TowerBriefDataNotify_proto_rawDescOnce sync.Once
	file_TowerBriefDataNotify_proto_rawDescData = file_TowerBriefDataNotify_proto_rawDesc
)

func file_TowerBriefDataNotify_proto_rawDescGZIP() []byte {
	file_TowerBriefDataNotify_proto_rawDescOnce.Do(func() {
		file_TowerBriefDataNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_TowerBriefDataNotify_proto_rawDescData)
	})
	return file_TowerBriefDataNotify_proto_rawDescData
}

var file_TowerBriefDataNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_TowerBriefDataNotify_proto_goTypes = []interface{}{
	(*TowerBriefDataNotify)(nil), // 0: TowerBriefDataNotify
}
var file_TowerBriefDataNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_TowerBriefDataNotify_proto_init() }
func file_TowerBriefDataNotify_proto_init() {
	if File_TowerBriefDataNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_TowerBriefDataNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TowerBriefDataNotify); i {
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
			RawDescriptor: file_TowerBriefDataNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_TowerBriefDataNotify_proto_goTypes,
		DependencyIndexes: file_TowerBriefDataNotify_proto_depIdxs,
		MessageInfos:      file_TowerBriefDataNotify_proto_msgTypes,
	}.Build()
	File_TowerBriefDataNotify_proto = out.File
	file_TowerBriefDataNotify_proto_rawDesc = nil
	file_TowerBriefDataNotify_proto_goTypes = nil
	file_TowerBriefDataNotify_proto_depIdxs = nil
}
