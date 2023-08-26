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
// source: FCEDDGJPMLM.proto

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

// CmdId: 24173
type FCEDDGJPMLM struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SettleInfoList []*CLNEPMAAKFB `protobuf:"bytes,3,rep,name=settle_info_list,json=settleInfoList,proto3" json:"settle_info_list,omitempty"`
	IPELDMIMABF    bool           `protobuf:"varint,10,opt,name=IPELDMIMABF,proto3" json:"IPELDMIMABF,omitempty"`
	IsSingle       bool           `protobuf:"varint,5,opt,name=is_single,json=isSingle,proto3" json:"is_single,omitempty"`
	PlayIndex      uint32         `protobuf:"varint,7,opt,name=play_index,json=playIndex,proto3" json:"play_index,omitempty"`
	StageType      uint32         `protobuf:"varint,8,opt,name=stage_type,json=stageType,proto3" json:"stage_type,omitempty"`
	LevelId        uint32         `protobuf:"varint,12,opt,name=level_id,json=levelId,proto3" json:"level_id,omitempty"`
	Duration       uint32         `protobuf:"varint,2,opt,name=duration,proto3" json:"duration,omitempty"`
	Score          uint32         `protobuf:"varint,1,opt,name=score,proto3" json:"score,omitempty"`
	BeginTime      int32          `protobuf:"fixed32,6,opt,name=begin_time,json=beginTime,proto3" json:"begin_time,omitempty"`
	INHKDNJEOAP    uint32         `protobuf:"varint,4,opt,name=INHKDNJEOAP,proto3" json:"INHKDNJEOAP,omitempty"`
}

func (x *FCEDDGJPMLM) Reset() {
	*x = FCEDDGJPMLM{}
	if protoimpl.UnsafeEnabled {
		mi := &file_FCEDDGJPMLM_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FCEDDGJPMLM) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FCEDDGJPMLM) ProtoMessage() {}

func (x *FCEDDGJPMLM) ProtoReflect() protoreflect.Message {
	mi := &file_FCEDDGJPMLM_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FCEDDGJPMLM.ProtoReflect.Descriptor instead.
func (*FCEDDGJPMLM) Descriptor() ([]byte, []int) {
	return file_FCEDDGJPMLM_proto_rawDescGZIP(), []int{0}
}

func (x *FCEDDGJPMLM) GetSettleInfoList() []*CLNEPMAAKFB {
	if x != nil {
		return x.SettleInfoList
	}
	return nil
}

func (x *FCEDDGJPMLM) GetIPELDMIMABF() bool {
	if x != nil {
		return x.IPELDMIMABF
	}
	return false
}

func (x *FCEDDGJPMLM) GetIsSingle() bool {
	if x != nil {
		return x.IsSingle
	}
	return false
}

func (x *FCEDDGJPMLM) GetPlayIndex() uint32 {
	if x != nil {
		return x.PlayIndex
	}
	return 0
}

func (x *FCEDDGJPMLM) GetStageType() uint32 {
	if x != nil {
		return x.StageType
	}
	return 0
}

func (x *FCEDDGJPMLM) GetLevelId() uint32 {
	if x != nil {
		return x.LevelId
	}
	return 0
}

func (x *FCEDDGJPMLM) GetDuration() uint32 {
	if x != nil {
		return x.Duration
	}
	return 0
}

func (x *FCEDDGJPMLM) GetScore() uint32 {
	if x != nil {
		return x.Score
	}
	return 0
}

func (x *FCEDDGJPMLM) GetBeginTime() int32 {
	if x != nil {
		return x.BeginTime
	}
	return 0
}

func (x *FCEDDGJPMLM) GetINHKDNJEOAP() uint32 {
	if x != nil {
		return x.INHKDNJEOAP
	}
	return 0
}

var File_FCEDDGJPMLM_proto protoreflect.FileDescriptor

var file_FCEDDGJPMLM_proto_rawDesc = []byte{
	0x0a, 0x11, 0x46, 0x43, 0x45, 0x44, 0x44, 0x47, 0x4a, 0x50, 0x4d, 0x4c, 0x4d, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x43, 0x4c, 0x4e, 0x45, 0x50, 0x4d, 0x41, 0x41, 0x4b, 0x46, 0x42,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd0, 0x02, 0x0a, 0x0b, 0x46, 0x43, 0x45, 0x44, 0x44,
	0x47, 0x4a, 0x50, 0x4d, 0x4c, 0x4d, 0x12, 0x36, 0x0a, 0x10, 0x73, 0x65, 0x74, 0x74, 0x6c, 0x65,
	0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x0c, 0x2e, 0x43, 0x4c, 0x4e, 0x45, 0x50, 0x4d, 0x41, 0x41, 0x4b, 0x46, 0x42, 0x52, 0x0e,
	0x73, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x20,
	0x0a, 0x0b, 0x49, 0x50, 0x45, 0x4c, 0x44, 0x4d, 0x49, 0x4d, 0x41, 0x42, 0x46, 0x18, 0x0a, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0b, 0x49, 0x50, 0x45, 0x4c, 0x44, 0x4d, 0x49, 0x4d, 0x41, 0x42, 0x46,
	0x12, 0x1b, 0x0a, 0x09, 0x69, 0x73, 0x5f, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x08, 0x69, 0x73, 0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x12, 0x1d, 0x0a,
	0x0a, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x09, 0x70, 0x6c, 0x61, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1d, 0x0a, 0x0a,
	0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x09, 0x73, 0x74, 0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x62, 0x65, 0x67, 0x69,
	0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0f, 0x52, 0x09, 0x62, 0x65,
	0x67, 0x69, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x49, 0x4e, 0x48, 0x4b, 0x44,
	0x4e, 0x4a, 0x45, 0x4f, 0x41, 0x50, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x49, 0x4e,
	0x48, 0x4b, 0x44, 0x4e, 0x4a, 0x45, 0x4f, 0x41, 0x50, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_FCEDDGJPMLM_proto_rawDescOnce sync.Once
	file_FCEDDGJPMLM_proto_rawDescData = file_FCEDDGJPMLM_proto_rawDesc
)

func file_FCEDDGJPMLM_proto_rawDescGZIP() []byte {
	file_FCEDDGJPMLM_proto_rawDescOnce.Do(func() {
		file_FCEDDGJPMLM_proto_rawDescData = protoimpl.X.CompressGZIP(file_FCEDDGJPMLM_proto_rawDescData)
	})
	return file_FCEDDGJPMLM_proto_rawDescData
}

var file_FCEDDGJPMLM_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_FCEDDGJPMLM_proto_goTypes = []interface{}{
	(*FCEDDGJPMLM)(nil), // 0: FCEDDGJPMLM
	(*CLNEPMAAKFB)(nil), // 1: CLNEPMAAKFB
}
var file_FCEDDGJPMLM_proto_depIdxs = []int32{
	1, // 0: FCEDDGJPMLM.settle_info_list:type_name -> CLNEPMAAKFB
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_FCEDDGJPMLM_proto_init() }
func file_FCEDDGJPMLM_proto_init() {
	if File_FCEDDGJPMLM_proto != nil {
		return
	}
	file_CLNEPMAAKFB_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_FCEDDGJPMLM_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FCEDDGJPMLM); i {
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
			RawDescriptor: file_FCEDDGJPMLM_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_FCEDDGJPMLM_proto_goTypes,
		DependencyIndexes: file_FCEDDGJPMLM_proto_depIdxs,
		MessageInfos:      file_FCEDDGJPMLM_proto_msgTypes,
	}.Build()
	File_FCEDDGJPMLM_proto = out.File
	file_FCEDDGJPMLM_proto_rawDesc = nil
	file_FCEDDGJPMLM_proto_goTypes = nil
	file_FCEDDGJPMLM_proto_depIdxs = nil
}
