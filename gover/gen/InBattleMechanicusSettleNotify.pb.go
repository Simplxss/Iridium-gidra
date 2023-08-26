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
// source: InBattleMechanicusSettleNotify.proto

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

// CmdId: 9184
// Obf: JOPPLCFOMEF
type InBattleMechanicusSettleNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MOPJLMJENOM uint32                         `protobuf:"varint,4,opt,name=MOPJLMJENOM,proto3" json:"MOPJLMJENOM,omitempty"`
	PlayIndex   uint32                         `protobuf:"varint,9,opt,name=play_index,json=playIndex,proto3" json:"play_index,omitempty"`
	GroupId     uint32                         `protobuf:"varint,2,opt,name=group_id,json=groupId,proto3" json:"group_id,omitempty"`
	WatcherList []*MultistageSettleWatcherInfo `protobuf:"bytes,15,rep,name=watcher_list,json=watcherList,proto3" json:"watcher_list,omitempty"`
	IsSuccess   bool                           `protobuf:"varint,8,opt,name=is_success,json=isSuccess,proto3" json:"is_success,omitempty"`
	SceneTimeMs uint64                         `protobuf:"varint,6,opt,name=scene_time_ms,json=sceneTimeMs,proto3" json:"scene_time_ms,omitempty"`
	OPBCDCIEDHF uint32                         `protobuf:"varint,7,opt,name=OPBCDCIEDHF,proto3" json:"OPBCDCIEDHF,omitempty"`
	MEKFBBKKKGP uint32                         `protobuf:"varint,11,opt,name=MEKFBBKKKGP,proto3" json:"MEKFBBKKKGP,omitempty"`
}

func (x *InBattleMechanicusSettleNotify) Reset() {
	*x = InBattleMechanicusSettleNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_InBattleMechanicusSettleNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InBattleMechanicusSettleNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InBattleMechanicusSettleNotify) ProtoMessage() {}

func (x *InBattleMechanicusSettleNotify) ProtoReflect() protoreflect.Message {
	mi := &file_InBattleMechanicusSettleNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InBattleMechanicusSettleNotify.ProtoReflect.Descriptor instead.
func (*InBattleMechanicusSettleNotify) Descriptor() ([]byte, []int) {
	return file_InBattleMechanicusSettleNotify_proto_rawDescGZIP(), []int{0}
}

func (x *InBattleMechanicusSettleNotify) GetMOPJLMJENOM() uint32 {
	if x != nil {
		return x.MOPJLMJENOM
	}
	return 0
}

func (x *InBattleMechanicusSettleNotify) GetPlayIndex() uint32 {
	if x != nil {
		return x.PlayIndex
	}
	return 0
}

func (x *InBattleMechanicusSettleNotify) GetGroupId() uint32 {
	if x != nil {
		return x.GroupId
	}
	return 0
}

func (x *InBattleMechanicusSettleNotify) GetWatcherList() []*MultistageSettleWatcherInfo {
	if x != nil {
		return x.WatcherList
	}
	return nil
}

func (x *InBattleMechanicusSettleNotify) GetIsSuccess() bool {
	if x != nil {
		return x.IsSuccess
	}
	return false
}

func (x *InBattleMechanicusSettleNotify) GetSceneTimeMs() uint64 {
	if x != nil {
		return x.SceneTimeMs
	}
	return 0
}

func (x *InBattleMechanicusSettleNotify) GetOPBCDCIEDHF() uint32 {
	if x != nil {
		return x.OPBCDCIEDHF
	}
	return 0
}

func (x *InBattleMechanicusSettleNotify) GetMEKFBBKKKGP() uint32 {
	if x != nil {
		return x.MEKFBBKKKGP
	}
	return 0
}

var File_InBattleMechanicusSettleNotify_proto protoreflect.FileDescriptor

var file_InBattleMechanicusSettleNotify_proto_rawDesc = []byte{
	0x0a, 0x24, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e,
	0x69, 0x63, 0x75, 0x73, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x73, 0x74, 0x61,
	0x67, 0x65, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x57, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x49,
	0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc4, 0x02, 0x0a, 0x1e, 0x49, 0x6e,
	0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e, 0x69, 0x63, 0x75, 0x73,
	0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x20, 0x0a, 0x0b,
	0x4d, 0x4f, 0x50, 0x4a, 0x4c, 0x4d, 0x4a, 0x45, 0x4e, 0x4f, 0x4d, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x0b, 0x4d, 0x4f, 0x50, 0x4a, 0x4c, 0x4d, 0x4a, 0x45, 0x4e, 0x4f, 0x4d, 0x12, 0x1d,
	0x0a, 0x0a, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x09, 0x70, 0x6c, 0x61, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x19, 0x0a,
	0x08, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x07, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x64, 0x12, 0x3f, 0x0a, 0x0c, 0x77, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x72, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0f, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c,
	0x2e, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x73, 0x74, 0x61, 0x67, 0x65, 0x53, 0x65, 0x74, 0x74, 0x6c,
	0x65, 0x57, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0b, 0x77, 0x61,
	0x74, 0x63, 0x68, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x69, 0x73, 0x5f,
	0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x69,
	0x73, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x22, 0x0a, 0x0d, 0x73, 0x63, 0x65, 0x6e,
	0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x6d, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x0b, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x4d, 0x73, 0x12, 0x20, 0x0a, 0x0b,
	0x4f, 0x50, 0x42, 0x43, 0x44, 0x43, 0x49, 0x45, 0x44, 0x48, 0x46, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x0b, 0x4f, 0x50, 0x42, 0x43, 0x44, 0x43, 0x49, 0x45, 0x44, 0x48, 0x46, 0x12, 0x20,
	0x0a, 0x0b, 0x4d, 0x45, 0x4b, 0x46, 0x42, 0x42, 0x4b, 0x4b, 0x4b, 0x47, 0x50, 0x18, 0x0b, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4d, 0x45, 0x4b, 0x46, 0x42, 0x42, 0x4b, 0x4b, 0x4b, 0x47, 0x50,
	0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_InBattleMechanicusSettleNotify_proto_rawDescOnce sync.Once
	file_InBattleMechanicusSettleNotify_proto_rawDescData = file_InBattleMechanicusSettleNotify_proto_rawDesc
)

func file_InBattleMechanicusSettleNotify_proto_rawDescGZIP() []byte {
	file_InBattleMechanicusSettleNotify_proto_rawDescOnce.Do(func() {
		file_InBattleMechanicusSettleNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_InBattleMechanicusSettleNotify_proto_rawDescData)
	})
	return file_InBattleMechanicusSettleNotify_proto_rawDescData
}

var file_InBattleMechanicusSettleNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_InBattleMechanicusSettleNotify_proto_goTypes = []interface{}{
	(*InBattleMechanicusSettleNotify)(nil), // 0: InBattleMechanicusSettleNotify
	(*MultistageSettleWatcherInfo)(nil),    // 1: MultistageSettleWatcherInfo
}
var file_InBattleMechanicusSettleNotify_proto_depIdxs = []int32{
	1, // 0: InBattleMechanicusSettleNotify.watcher_list:type_name -> MultistageSettleWatcherInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_InBattleMechanicusSettleNotify_proto_init() }
func file_InBattleMechanicusSettleNotify_proto_init() {
	if File_InBattleMechanicusSettleNotify_proto != nil {
		return
	}
	file_MultistageSettleWatcherInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_InBattleMechanicusSettleNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InBattleMechanicusSettleNotify); i {
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
			RawDescriptor: file_InBattleMechanicusSettleNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_InBattleMechanicusSettleNotify_proto_goTypes,
		DependencyIndexes: file_InBattleMechanicusSettleNotify_proto_depIdxs,
		MessageInfos:      file_InBattleMechanicusSettleNotify_proto_msgTypes,
	}.Build()
	File_InBattleMechanicusSettleNotify_proto = out.File
	file_InBattleMechanicusSettleNotify_proto_rawDesc = nil
	file_InBattleMechanicusSettleNotify_proto_goTypes = nil
	file_InBattleMechanicusSettleNotify_proto_depIdxs = nil
}
