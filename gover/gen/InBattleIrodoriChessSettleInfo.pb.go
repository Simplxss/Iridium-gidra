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
// source: InBattleIrodoriChessSettleInfo.proto

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

// Obf: MOMBFEIPFCD
type InBattleIrodoriChessSettleInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsNewRecord   bool   `protobuf:"varint,7,opt,name=is_new_record,json=isNewRecord,proto3" json:"is_new_record,omitempty"`
	SceneTimeMs   uint64 `protobuf:"varint,15,opt,name=scene_time_ms,json=sceneTimeMs,proto3" json:"scene_time_ms,omitempty"`
	BPPCDLMFKCP   uint32 `protobuf:"varint,12,opt,name=BPPCDLMFKCP,proto3" json:"BPPCDLMFKCP,omitempty"`
	IsPerfect     bool   `protobuf:"varint,2,opt,name=is_perfect,json=isPerfect,proto3" json:"is_perfect,omitempty"`
	KDPNBLFJKND   uint32 `protobuf:"varint,10,opt,name=KDPNBLFJKND,proto3" json:"KDPNBLFJKND,omitempty"`
	IsActivityEnd bool   `protobuf:"varint,5,opt,name=is_activity_end,json=isActivityEnd,proto3" json:"is_activity_end,omitempty"`
}

func (x *InBattleIrodoriChessSettleInfo) Reset() {
	*x = InBattleIrodoriChessSettleInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_InBattleIrodoriChessSettleInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InBattleIrodoriChessSettleInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InBattleIrodoriChessSettleInfo) ProtoMessage() {}

func (x *InBattleIrodoriChessSettleInfo) ProtoReflect() protoreflect.Message {
	mi := &file_InBattleIrodoriChessSettleInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InBattleIrodoriChessSettleInfo.ProtoReflect.Descriptor instead.
func (*InBattleIrodoriChessSettleInfo) Descriptor() ([]byte, []int) {
	return file_InBattleIrodoriChessSettleInfo_proto_rawDescGZIP(), []int{0}
}

func (x *InBattleIrodoriChessSettleInfo) GetIsNewRecord() bool {
	if x != nil {
		return x.IsNewRecord
	}
	return false
}

func (x *InBattleIrodoriChessSettleInfo) GetSceneTimeMs() uint64 {
	if x != nil {
		return x.SceneTimeMs
	}
	return 0
}

func (x *InBattleIrodoriChessSettleInfo) GetBPPCDLMFKCP() uint32 {
	if x != nil {
		return x.BPPCDLMFKCP
	}
	return 0
}

func (x *InBattleIrodoriChessSettleInfo) GetIsPerfect() bool {
	if x != nil {
		return x.IsPerfect
	}
	return false
}

func (x *InBattleIrodoriChessSettleInfo) GetKDPNBLFJKND() uint32 {
	if x != nil {
		return x.KDPNBLFJKND
	}
	return 0
}

func (x *InBattleIrodoriChessSettleInfo) GetIsActivityEnd() bool {
	if x != nil {
		return x.IsActivityEnd
	}
	return false
}

var File_InBattleIrodoriChessSettleInfo_proto protoreflect.FileDescriptor

var file_InBattleIrodoriChessSettleInfo_proto_rawDesc = []byte{
	0x0a, 0x24, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72,
	0x69, 0x43, 0x68, 0x65, 0x73, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf3, 0x01, 0x0a, 0x1e, 0x49, 0x6e, 0x42, 0x61, 0x74,
	0x74, 0x6c, 0x65, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73, 0x53,
	0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x22, 0x0a, 0x0d, 0x69, 0x73, 0x5f,
	0x6e, 0x65, 0x77, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x0b, 0x69, 0x73, 0x4e, 0x65, 0x77, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x12, 0x22, 0x0a,
	0x0d, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x6d, 0x73, 0x18, 0x0f,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x4d,
	0x73, 0x12, 0x20, 0x0a, 0x0b, 0x42, 0x50, 0x50, 0x43, 0x44, 0x4c, 0x4d, 0x46, 0x4b, 0x43, 0x50,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x42, 0x50, 0x50, 0x43, 0x44, 0x4c, 0x4d, 0x46,
	0x4b, 0x43, 0x50, 0x12, 0x1d, 0x0a, 0x0a, 0x69, 0x73, 0x5f, 0x70, 0x65, 0x72, 0x66, 0x65, 0x63,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x69, 0x73, 0x50, 0x65, 0x72, 0x66, 0x65,
	0x63, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x4b, 0x44, 0x50, 0x4e, 0x42, 0x4c, 0x46, 0x4a, 0x4b, 0x4e,
	0x44, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4b, 0x44, 0x50, 0x4e, 0x42, 0x4c, 0x46,
	0x4a, 0x4b, 0x4e, 0x44, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x73, 0x5f, 0x61, 0x63, 0x74, 0x69, 0x76,
	0x69, 0x74, 0x79, 0x5f, 0x65, 0x6e, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x69,
	0x73, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x45, 0x6e, 0x64, 0x42, 0x06, 0x5a, 0x04,
	0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_InBattleIrodoriChessSettleInfo_proto_rawDescOnce sync.Once
	file_InBattleIrodoriChessSettleInfo_proto_rawDescData = file_InBattleIrodoriChessSettleInfo_proto_rawDesc
)

func file_InBattleIrodoriChessSettleInfo_proto_rawDescGZIP() []byte {
	file_InBattleIrodoriChessSettleInfo_proto_rawDescOnce.Do(func() {
		file_InBattleIrodoriChessSettleInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_InBattleIrodoriChessSettleInfo_proto_rawDescData)
	})
	return file_InBattleIrodoriChessSettleInfo_proto_rawDescData
}

var file_InBattleIrodoriChessSettleInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_InBattleIrodoriChessSettleInfo_proto_goTypes = []interface{}{
	(*InBattleIrodoriChessSettleInfo)(nil), // 0: InBattleIrodoriChessSettleInfo
}
var file_InBattleIrodoriChessSettleInfo_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_InBattleIrodoriChessSettleInfo_proto_init() }
func file_InBattleIrodoriChessSettleInfo_proto_init() {
	if File_InBattleIrodoriChessSettleInfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_InBattleIrodoriChessSettleInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InBattleIrodoriChessSettleInfo); i {
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
			RawDescriptor: file_InBattleIrodoriChessSettleInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_InBattleIrodoriChessSettleInfo_proto_goTypes,
		DependencyIndexes: file_InBattleIrodoriChessSettleInfo_proto_depIdxs,
		MessageInfos:      file_InBattleIrodoriChessSettleInfo_proto_msgTypes,
	}.Build()
	File_InBattleIrodoriChessSettleInfo_proto = out.File
	file_InBattleIrodoriChessSettleInfo_proto_rawDesc = nil
	file_InBattleIrodoriChessSettleInfo_proto_goTypes = nil
	file_InBattleIrodoriChessSettleInfo_proto_depIdxs = nil
}
