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
// source: SummerTimeSprintBoatSettleNotify.proto

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

// CmdId: 20382
// Obf: CHKPPPMCLBM
type SummerTimeSprintBoatSettleNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsNewRecord bool   `protobuf:"varint,8,opt,name=is_new_record,json=isNewRecord,proto3" json:"is_new_record,omitempty"`
	LeftTime    uint32 `protobuf:"varint,5,opt,name=left_time,json=leftTime,proto3" json:"left_time,omitempty"`
	TotalNum    uint32 `protobuf:"varint,7,opt,name=total_num,json=totalNum,proto3" json:"total_num,omitempty"`
	KPCGAHJMMLB uint32 `protobuf:"varint,11,opt,name=KPCGAHJMMLB,proto3" json:"KPCGAHJMMLB,omitempty"`
	GroupId     uint32 `protobuf:"varint,6,opt,name=group_id,json=groupId,proto3" json:"group_id,omitempty"`
	IsSuccess   bool   `protobuf:"varint,12,opt,name=is_success,json=isSuccess,proto3" json:"is_success,omitempty"`
	Score       uint32 `protobuf:"varint,9,opt,name=score,proto3" json:"score,omitempty"`
	MKOHDHLECBN uint32 `protobuf:"varint,10,opt,name=MKOHDHLECBN,proto3" json:"MKOHDHLECBN,omitempty"`
}

func (x *SummerTimeSprintBoatSettleNotify) Reset() {
	*x = SummerTimeSprintBoatSettleNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SummerTimeSprintBoatSettleNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SummerTimeSprintBoatSettleNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SummerTimeSprintBoatSettleNotify) ProtoMessage() {}

func (x *SummerTimeSprintBoatSettleNotify) ProtoReflect() protoreflect.Message {
	mi := &file_SummerTimeSprintBoatSettleNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SummerTimeSprintBoatSettleNotify.ProtoReflect.Descriptor instead.
func (*SummerTimeSprintBoatSettleNotify) Descriptor() ([]byte, []int) {
	return file_SummerTimeSprintBoatSettleNotify_proto_rawDescGZIP(), []int{0}
}

func (x *SummerTimeSprintBoatSettleNotify) GetIsNewRecord() bool {
	if x != nil {
		return x.IsNewRecord
	}
	return false
}

func (x *SummerTimeSprintBoatSettleNotify) GetLeftTime() uint32 {
	if x != nil {
		return x.LeftTime
	}
	return 0
}

func (x *SummerTimeSprintBoatSettleNotify) GetTotalNum() uint32 {
	if x != nil {
		return x.TotalNum
	}
	return 0
}

func (x *SummerTimeSprintBoatSettleNotify) GetKPCGAHJMMLB() uint32 {
	if x != nil {
		return x.KPCGAHJMMLB
	}
	return 0
}

func (x *SummerTimeSprintBoatSettleNotify) GetGroupId() uint32 {
	if x != nil {
		return x.GroupId
	}
	return 0
}

func (x *SummerTimeSprintBoatSettleNotify) GetIsSuccess() bool {
	if x != nil {
		return x.IsSuccess
	}
	return false
}

func (x *SummerTimeSprintBoatSettleNotify) GetScore() uint32 {
	if x != nil {
		return x.Score
	}
	return 0
}

func (x *SummerTimeSprintBoatSettleNotify) GetMKOHDHLECBN() uint32 {
	if x != nil {
		return x.MKOHDHLECBN
	}
	return 0
}

var File_SummerTimeSprintBoatSettleNotify_proto protoreflect.FileDescriptor

var file_SummerTimeSprintBoatSettleNotify_proto_rawDesc = []byte{
	0x0a, 0x26, 0x53, 0x75, 0x6d, 0x6d, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65, 0x53, 0x70, 0x72, 0x69,
	0x6e, 0x74, 0x42, 0x6f, 0x61, 0x74, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x69,
	0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x94, 0x02, 0x0a, 0x20, 0x53, 0x75, 0x6d,
	0x6d, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65, 0x53, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x42, 0x6f, 0x61,
	0x74, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x22, 0x0a,
	0x0d, 0x69, 0x73, 0x5f, 0x6e, 0x65, 0x77, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x69, 0x73, 0x4e, 0x65, 0x77, 0x52, 0x65, 0x63, 0x6f, 0x72,
	0x64, 0x12, 0x1b, 0x0a, 0x09, 0x6c, 0x65, 0x66, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x6c, 0x65, 0x66, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1b,
	0x0a, 0x09, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x08, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x4e, 0x75, 0x6d, 0x12, 0x20, 0x0a, 0x0b, 0x4b,
	0x50, 0x43, 0x47, 0x41, 0x48, 0x4a, 0x4d, 0x4d, 0x4c, 0x42, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0b, 0x4b, 0x50, 0x43, 0x47, 0x41, 0x48, 0x4a, 0x4d, 0x4d, 0x4c, 0x42, 0x12, 0x19, 0x0a,
	0x08, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x07, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x69, 0x73, 0x5f, 0x73,
	0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x69, 0x73,
	0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65,
	0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x12, 0x20, 0x0a,
	0x0b, 0x4d, 0x4b, 0x4f, 0x48, 0x44, 0x48, 0x4c, 0x45, 0x43, 0x42, 0x4e, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x4d, 0x4b, 0x4f, 0x48, 0x44, 0x48, 0x4c, 0x45, 0x43, 0x42, 0x4e, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_SummerTimeSprintBoatSettleNotify_proto_rawDescOnce sync.Once
	file_SummerTimeSprintBoatSettleNotify_proto_rawDescData = file_SummerTimeSprintBoatSettleNotify_proto_rawDesc
)

func file_SummerTimeSprintBoatSettleNotify_proto_rawDescGZIP() []byte {
	file_SummerTimeSprintBoatSettleNotify_proto_rawDescOnce.Do(func() {
		file_SummerTimeSprintBoatSettleNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_SummerTimeSprintBoatSettleNotify_proto_rawDescData)
	})
	return file_SummerTimeSprintBoatSettleNotify_proto_rawDescData
}

var file_SummerTimeSprintBoatSettleNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SummerTimeSprintBoatSettleNotify_proto_goTypes = []interface{}{
	(*SummerTimeSprintBoatSettleNotify)(nil), // 0: SummerTimeSprintBoatSettleNotify
}
var file_SummerTimeSprintBoatSettleNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_SummerTimeSprintBoatSettleNotify_proto_init() }
func file_SummerTimeSprintBoatSettleNotify_proto_init() {
	if File_SummerTimeSprintBoatSettleNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_SummerTimeSprintBoatSettleNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SummerTimeSprintBoatSettleNotify); i {
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
			RawDescriptor: file_SummerTimeSprintBoatSettleNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SummerTimeSprintBoatSettleNotify_proto_goTypes,
		DependencyIndexes: file_SummerTimeSprintBoatSettleNotify_proto_depIdxs,
		MessageInfos:      file_SummerTimeSprintBoatSettleNotify_proto_msgTypes,
	}.Build()
	File_SummerTimeSprintBoatSettleNotify_proto = out.File
	file_SummerTimeSprintBoatSettleNotify_proto_rawDesc = nil
	file_SummerTimeSprintBoatSettleNotify_proto_goTypes = nil
	file_SummerTimeSprintBoatSettleNotify_proto_depIdxs = nil
}
