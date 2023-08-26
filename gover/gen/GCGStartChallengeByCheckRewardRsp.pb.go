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
// source: GCGStartChallengeByCheckRewardRsp.proto

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

// CmdId: 25802
// Obf: FNKFMOMJHFE
type GCGStartChallengeByCheckRewardRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OJJEDPGEKFK HPJPOMAIPNC `protobuf:"varint,4,opt,name=OJJEDPGEKFK,proto3,enum=HPJPOMAIPNC" json:"OJJEDPGEKFK,omitempty"`
	JJHKBJLIPNA []uint32    `protobuf:"varint,10,rep,packed,name=JJHKBJLIPNA,proto3" json:"JJHKBJLIPNA,omitempty"`
	ConfigId    uint32      `protobuf:"varint,8,opt,name=config_id,json=configId,proto3" json:"config_id,omitempty"`
	Retcode     int32       `protobuf:"varint,12,opt,name=retcode,proto3" json:"retcode,omitempty"`
	OPFPLNLHLMA []uint32    `protobuf:"varint,13,rep,packed,name=OPFPLNLHLMA,proto3" json:"OPFPLNLHLMA,omitempty"`
	LevelId     uint32      `protobuf:"varint,11,opt,name=level_id,json=levelId,proto3" json:"level_id,omitempty"`
}

func (x *GCGStartChallengeByCheckRewardRsp) Reset() {
	*x = GCGStartChallengeByCheckRewardRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGStartChallengeByCheckRewardRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGStartChallengeByCheckRewardRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGStartChallengeByCheckRewardRsp) ProtoMessage() {}

func (x *GCGStartChallengeByCheckRewardRsp) ProtoReflect() protoreflect.Message {
	mi := &file_GCGStartChallengeByCheckRewardRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGStartChallengeByCheckRewardRsp.ProtoReflect.Descriptor instead.
func (*GCGStartChallengeByCheckRewardRsp) Descriptor() ([]byte, []int) {
	return file_GCGStartChallengeByCheckRewardRsp_proto_rawDescGZIP(), []int{0}
}

func (x *GCGStartChallengeByCheckRewardRsp) GetOJJEDPGEKFK() HPJPOMAIPNC {
	if x != nil {
		return x.OJJEDPGEKFK
	}
	return HPJPOMAIPNC_HPJPOMAIPNC_GcgLevelNone
}

func (x *GCGStartChallengeByCheckRewardRsp) GetJJHKBJLIPNA() []uint32 {
	if x != nil {
		return x.JJHKBJLIPNA
	}
	return nil
}

func (x *GCGStartChallengeByCheckRewardRsp) GetConfigId() uint32 {
	if x != nil {
		return x.ConfigId
	}
	return 0
}

func (x *GCGStartChallengeByCheckRewardRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *GCGStartChallengeByCheckRewardRsp) GetOPFPLNLHLMA() []uint32 {
	if x != nil {
		return x.OPFPLNLHLMA
	}
	return nil
}

func (x *GCGStartChallengeByCheckRewardRsp) GetLevelId() uint32 {
	if x != nil {
		return x.LevelId
	}
	return 0
}

var File_GCGStartChallengeByCheckRewardRsp_proto protoreflect.FileDescriptor

var file_GCGStartChallengeByCheckRewardRsp_proto_rawDesc = []byte{
	0x0a, 0x27, 0x47, 0x43, 0x47, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65,
	0x6e, 0x67, 0x65, 0x42, 0x79, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x52, 0x65, 0x77, 0x61, 0x72, 0x64,
	0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x48, 0x50, 0x4a, 0x50, 0x4f,
	0x4d, 0x41, 0x49, 0x50, 0x4e, 0x43, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe9, 0x01, 0x0a,
	0x21, 0x47, 0x43, 0x47, 0x53, 0x74, 0x61, 0x72, 0x74, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e,
	0x67, 0x65, 0x42, 0x79, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x52, 0x65, 0x77, 0x61, 0x72, 0x64, 0x52,
	0x73, 0x70, 0x12, 0x2e, 0x0a, 0x0b, 0x4f, 0x4a, 0x4a, 0x45, 0x44, 0x50, 0x47, 0x45, 0x4b, 0x46,
	0x4b, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0c, 0x2e, 0x48, 0x50, 0x4a, 0x50, 0x4f, 0x4d,
	0x41, 0x49, 0x50, 0x4e, 0x43, 0x52, 0x0b, 0x4f, 0x4a, 0x4a, 0x45, 0x44, 0x50, 0x47, 0x45, 0x4b,
	0x46, 0x4b, 0x12, 0x20, 0x0a, 0x0b, 0x4a, 0x4a, 0x48, 0x4b, 0x42, 0x4a, 0x4c, 0x49, 0x50, 0x4e,
	0x41, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b, 0x4a, 0x4a, 0x48, 0x4b, 0x42, 0x4a, 0x4c,
	0x49, 0x50, 0x4e, 0x41, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x69,
	0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x49,
	0x64, 0x12, 0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x0c, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x4f,
	0x50, 0x46, 0x50, 0x4c, 0x4e, 0x4c, 0x48, 0x4c, 0x4d, 0x41, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0d,
	0x52, 0x0b, 0x4f, 0x50, 0x46, 0x50, 0x4c, 0x4e, 0x4c, 0x48, 0x4c, 0x4d, 0x41, 0x12, 0x19, 0x0a,
	0x08, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x07, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x49, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGStartChallengeByCheckRewardRsp_proto_rawDescOnce sync.Once
	file_GCGStartChallengeByCheckRewardRsp_proto_rawDescData = file_GCGStartChallengeByCheckRewardRsp_proto_rawDesc
)

func file_GCGStartChallengeByCheckRewardRsp_proto_rawDescGZIP() []byte {
	file_GCGStartChallengeByCheckRewardRsp_proto_rawDescOnce.Do(func() {
		file_GCGStartChallengeByCheckRewardRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGStartChallengeByCheckRewardRsp_proto_rawDescData)
	})
	return file_GCGStartChallengeByCheckRewardRsp_proto_rawDescData
}

var file_GCGStartChallengeByCheckRewardRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGStartChallengeByCheckRewardRsp_proto_goTypes = []interface{}{
	(*GCGStartChallengeByCheckRewardRsp)(nil), // 0: GCGStartChallengeByCheckRewardRsp
	(HPJPOMAIPNC)(0), // 1: HPJPOMAIPNC
}
var file_GCGStartChallengeByCheckRewardRsp_proto_depIdxs = []int32{
	1, // 0: GCGStartChallengeByCheckRewardRsp.OJJEDPGEKFK:type_name -> HPJPOMAIPNC
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GCGStartChallengeByCheckRewardRsp_proto_init() }
func file_GCGStartChallengeByCheckRewardRsp_proto_init() {
	if File_GCGStartChallengeByCheckRewardRsp_proto != nil {
		return
	}
	file_HPJPOMAIPNC_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GCGStartChallengeByCheckRewardRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGStartChallengeByCheckRewardRsp); i {
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
			RawDescriptor: file_GCGStartChallengeByCheckRewardRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGStartChallengeByCheckRewardRsp_proto_goTypes,
		DependencyIndexes: file_GCGStartChallengeByCheckRewardRsp_proto_depIdxs,
		MessageInfos:      file_GCGStartChallengeByCheckRewardRsp_proto_msgTypes,
	}.Build()
	File_GCGStartChallengeByCheckRewardRsp_proto = out.File
	file_GCGStartChallengeByCheckRewardRsp_proto_rawDesc = nil
	file_GCGStartChallengeByCheckRewardRsp_proto_goTypes = nil
	file_GCGStartChallengeByCheckRewardRsp_proto_depIdxs = nil
}
