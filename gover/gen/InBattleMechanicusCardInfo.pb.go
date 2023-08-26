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
// source: InBattleMechanicusCardInfo.proto

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

// Obf: PFAMMDCAHHL
type InBattleMechanicusCardInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CardId         uint32                               `protobuf:"varint,8,opt,name=card_id,json=cardId,proto3" json:"card_id,omitempty"`
	ChallengeState InBattleMechanicusCardChallengeState `protobuf:"varint,15,opt,name=challenge_state,json=challengeState,proto3,enum=InBattleMechanicusCardChallengeState" json:"challenge_state,omitempty"`
	CostPoints     uint32                               `protobuf:"varint,12,opt,name=cost_points,json=costPoints,proto3" json:"cost_points,omitempty"`
	CMCAKMHEKKF    uint32                               `protobuf:"varint,2,opt,name=CMCAKMHEKKF,proto3" json:"CMCAKMHEKKF,omitempty"`
	BJBMPCFLGFD    uint32                               `protobuf:"varint,10,opt,name=BJBMPCFLGFD,proto3" json:"BJBMPCFLGFD,omitempty"`
	GKBGMCFIOJI    uint32                               `protobuf:"varint,4,opt,name=GKBGMCFIOJI,proto3" json:"GKBGMCFIOJI,omitempty"`
}

func (x *InBattleMechanicusCardInfo) Reset() {
	*x = InBattleMechanicusCardInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_InBattleMechanicusCardInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *InBattleMechanicusCardInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InBattleMechanicusCardInfo) ProtoMessage() {}

func (x *InBattleMechanicusCardInfo) ProtoReflect() protoreflect.Message {
	mi := &file_InBattleMechanicusCardInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InBattleMechanicusCardInfo.ProtoReflect.Descriptor instead.
func (*InBattleMechanicusCardInfo) Descriptor() ([]byte, []int) {
	return file_InBattleMechanicusCardInfo_proto_rawDescGZIP(), []int{0}
}

func (x *InBattleMechanicusCardInfo) GetCardId() uint32 {
	if x != nil {
		return x.CardId
	}
	return 0
}

func (x *InBattleMechanicusCardInfo) GetChallengeState() InBattleMechanicusCardChallengeState {
	if x != nil {
		return x.ChallengeState
	}
	return InBattleMechanicusCardChallengeState_IN_BATTLE_MECHANICUS_CARD_CHALLENGE_NONE
}

func (x *InBattleMechanicusCardInfo) GetCostPoints() uint32 {
	if x != nil {
		return x.CostPoints
	}
	return 0
}

func (x *InBattleMechanicusCardInfo) GetCMCAKMHEKKF() uint32 {
	if x != nil {
		return x.CMCAKMHEKKF
	}
	return 0
}

func (x *InBattleMechanicusCardInfo) GetBJBMPCFLGFD() uint32 {
	if x != nil {
		return x.BJBMPCFLGFD
	}
	return 0
}

func (x *InBattleMechanicusCardInfo) GetGKBGMCFIOJI() uint32 {
	if x != nil {
		return x.GKBGMCFIOJI
	}
	return 0
}

var File_InBattleMechanicusCardInfo_proto protoreflect.FileDescriptor

var file_InBattleMechanicusCardInfo_proto_rawDesc = []byte{
	0x0a, 0x20, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e,
	0x69, 0x63, 0x75, 0x73, 0x43, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x2a, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68,
	0x61, 0x6e, 0x69, 0x63, 0x75, 0x73, 0x43, 0x61, 0x72, 0x64, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65,
	0x6e, 0x67, 0x65, 0x53, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8c,
	0x02, 0x0a, 0x1a, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61,
	0x6e, 0x69, 0x63, 0x75, 0x73, 0x43, 0x61, 0x72, 0x64, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x17, 0x0a,
	0x07, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06,
	0x63, 0x61, 0x72, 0x64, 0x49, 0x64, 0x12, 0x4e, 0x0a, 0x0f, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65,
	0x6e, 0x67, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x25, 0x2e, 0x49, 0x6e, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x4d, 0x65, 0x63, 0x68, 0x61, 0x6e,
	0x69, 0x63, 0x75, 0x73, 0x43, 0x61, 0x72, 0x64, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67,
	0x65, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x0e, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67,
	0x65, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6f, 0x73, 0x74, 0x5f, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x73, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x63, 0x6f, 0x73,
	0x74, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x43, 0x4d, 0x43, 0x41, 0x4b,
	0x4d, 0x48, 0x45, 0x4b, 0x4b, 0x46, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x43, 0x4d,
	0x43, 0x41, 0x4b, 0x4d, 0x48, 0x45, 0x4b, 0x4b, 0x46, 0x12, 0x20, 0x0a, 0x0b, 0x42, 0x4a, 0x42,
	0x4d, 0x50, 0x43, 0x46, 0x4c, 0x47, 0x46, 0x44, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b,
	0x42, 0x4a, 0x42, 0x4d, 0x50, 0x43, 0x46, 0x4c, 0x47, 0x46, 0x44, 0x12, 0x20, 0x0a, 0x0b, 0x47,
	0x4b, 0x42, 0x47, 0x4d, 0x43, 0x46, 0x49, 0x4f, 0x4a, 0x49, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0b, 0x47, 0x4b, 0x42, 0x47, 0x4d, 0x43, 0x46, 0x49, 0x4f, 0x4a, 0x49, 0x42, 0x06, 0x5a,
	0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_InBattleMechanicusCardInfo_proto_rawDescOnce sync.Once
	file_InBattleMechanicusCardInfo_proto_rawDescData = file_InBattleMechanicusCardInfo_proto_rawDesc
)

func file_InBattleMechanicusCardInfo_proto_rawDescGZIP() []byte {
	file_InBattleMechanicusCardInfo_proto_rawDescOnce.Do(func() {
		file_InBattleMechanicusCardInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_InBattleMechanicusCardInfo_proto_rawDescData)
	})
	return file_InBattleMechanicusCardInfo_proto_rawDescData
}

var file_InBattleMechanicusCardInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_InBattleMechanicusCardInfo_proto_goTypes = []interface{}{
	(*InBattleMechanicusCardInfo)(nil),        // 0: InBattleMechanicusCardInfo
	(InBattleMechanicusCardChallengeState)(0), // 1: InBattleMechanicusCardChallengeState
}
var file_InBattleMechanicusCardInfo_proto_depIdxs = []int32{
	1, // 0: InBattleMechanicusCardInfo.challenge_state:type_name -> InBattleMechanicusCardChallengeState
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_InBattleMechanicusCardInfo_proto_init() }
func file_InBattleMechanicusCardInfo_proto_init() {
	if File_InBattleMechanicusCardInfo_proto != nil {
		return
	}
	file_InBattleMechanicusCardChallengeState_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_InBattleMechanicusCardInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*InBattleMechanicusCardInfo); i {
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
			RawDescriptor: file_InBattleMechanicusCardInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_InBattleMechanicusCardInfo_proto_goTypes,
		DependencyIndexes: file_InBattleMechanicusCardInfo_proto_depIdxs,
		MessageInfos:      file_InBattleMechanicusCardInfo_proto_msgTypes,
	}.Build()
	File_InBattleMechanicusCardInfo_proto = out.File
	file_InBattleMechanicusCardInfo_proto_rawDesc = nil
	file_InBattleMechanicusCardInfo_proto_goTypes = nil
	file_InBattleMechanicusCardInfo_proto_depIdxs = nil
}
