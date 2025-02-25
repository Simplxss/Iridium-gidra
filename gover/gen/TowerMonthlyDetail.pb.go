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
// source: TowerMonthlyDetail.proto

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

// Obf: BODKPJIIDPO
type TowerMonthlyDetail struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LastScheduleMonthlyBrief *TowerMonthlyBrief        `protobuf:"bytes,3,opt,name=last_schedule_monthly_brief,json=lastScheduleMonthlyBrief,proto3" json:"last_schedule_monthly_brief,omitempty"`
	MonthlyCombatRecord      *TowerMonthlyCombatRecord `protobuf:"bytes,15,opt,name=monthly_combat_record,json=monthlyCombatRecord,proto3" json:"monthly_combat_record,omitempty"`
}

func (x *TowerMonthlyDetail) Reset() {
	*x = TowerMonthlyDetail{}
	if protoimpl.UnsafeEnabled {
		mi := &file_TowerMonthlyDetail_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TowerMonthlyDetail) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TowerMonthlyDetail) ProtoMessage() {}

func (x *TowerMonthlyDetail) ProtoReflect() protoreflect.Message {
	mi := &file_TowerMonthlyDetail_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TowerMonthlyDetail.ProtoReflect.Descriptor instead.
func (*TowerMonthlyDetail) Descriptor() ([]byte, []int) {
	return file_TowerMonthlyDetail_proto_rawDescGZIP(), []int{0}
}

func (x *TowerMonthlyDetail) GetLastScheduleMonthlyBrief() *TowerMonthlyBrief {
	if x != nil {
		return x.LastScheduleMonthlyBrief
	}
	return nil
}

func (x *TowerMonthlyDetail) GetMonthlyCombatRecord() *TowerMonthlyCombatRecord {
	if x != nil {
		return x.MonthlyCombatRecord
	}
	return nil
}

var File_TowerMonthlyDetail_proto protoreflect.FileDescriptor

var file_TowerMonthlyDetail_proto_rawDesc = []byte{
	0x0a, 0x18, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x44, 0x65,
	0x74, 0x61, 0x69, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x54, 0x6f, 0x77, 0x65,
	0x72, 0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x42, 0x72, 0x69, 0x65, 0x66, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c,
	0x79, 0x43, 0x6f, 0x6d, 0x62, 0x61, 0x74, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xb6, 0x01, 0x0a, 0x12, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4d, 0x6f, 0x6e,
	0x74, 0x68, 0x6c, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x12, 0x51, 0x0a, 0x1b, 0x6c, 0x61,
	0x73, 0x74, 0x5f, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x6d, 0x6f, 0x6e, 0x74,
	0x68, 0x6c, 0x79, 0x5f, 0x62, 0x72, 0x69, 0x65, 0x66, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x12, 0x2e, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x42, 0x72,
	0x69, 0x65, 0x66, 0x52, 0x18, 0x6c, 0x61, 0x73, 0x74, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c,
	0x65, 0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x42, 0x72, 0x69, 0x65, 0x66, 0x12, 0x4d, 0x0a,
	0x15, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x5f, 0x63, 0x6f, 0x6d, 0x62, 0x61, 0x74, 0x5f,
	0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x54,
	0x6f, 0x77, 0x65, 0x72, 0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x43, 0x6f, 0x6d, 0x62, 0x61,
	0x74, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x52, 0x13, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79,
	0x43, 0x6f, 0x6d, 0x62, 0x61, 0x74, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x42, 0x06, 0x5a, 0x04,
	0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_TowerMonthlyDetail_proto_rawDescOnce sync.Once
	file_TowerMonthlyDetail_proto_rawDescData = file_TowerMonthlyDetail_proto_rawDesc
)

func file_TowerMonthlyDetail_proto_rawDescGZIP() []byte {
	file_TowerMonthlyDetail_proto_rawDescOnce.Do(func() {
		file_TowerMonthlyDetail_proto_rawDescData = protoimpl.X.CompressGZIP(file_TowerMonthlyDetail_proto_rawDescData)
	})
	return file_TowerMonthlyDetail_proto_rawDescData
}

var file_TowerMonthlyDetail_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_TowerMonthlyDetail_proto_goTypes = []interface{}{
	(*TowerMonthlyDetail)(nil),       // 0: TowerMonthlyDetail
	(*TowerMonthlyBrief)(nil),        // 1: TowerMonthlyBrief
	(*TowerMonthlyCombatRecord)(nil), // 2: TowerMonthlyCombatRecord
}
var file_TowerMonthlyDetail_proto_depIdxs = []int32{
	1, // 0: TowerMonthlyDetail.last_schedule_monthly_brief:type_name -> TowerMonthlyBrief
	2, // 1: TowerMonthlyDetail.monthly_combat_record:type_name -> TowerMonthlyCombatRecord
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_TowerMonthlyDetail_proto_init() }
func file_TowerMonthlyDetail_proto_init() {
	if File_TowerMonthlyDetail_proto != nil {
		return
	}
	file_TowerMonthlyBrief_proto_init()
	file_TowerMonthlyCombatRecord_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_TowerMonthlyDetail_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TowerMonthlyDetail); i {
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
			RawDescriptor: file_TowerMonthlyDetail_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_TowerMonthlyDetail_proto_goTypes,
		DependencyIndexes: file_TowerMonthlyDetail_proto_depIdxs,
		MessageInfos:      file_TowerMonthlyDetail_proto_msgTypes,
	}.Build()
	File_TowerMonthlyDetail_proto = out.File
	file_TowerMonthlyDetail_proto_rawDesc = nil
	file_TowerMonthlyDetail_proto_goTypes = nil
	file_TowerMonthlyDetail_proto_depIdxs = nil
}
