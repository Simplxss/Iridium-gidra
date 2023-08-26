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
// source: EffigyChallengeV2LevelData.proto

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

// Obf: CAFLDJBAKMC
type EffigyChallengeV2LevelData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PPMPMJHEJHJ uint32 `protobuf:"varint,15,opt,name=PPMPMJHEJHJ,proto3" json:"PPMPMJHEJHJ,omitempty"`
	LAICFKMFKEH uint32 `protobuf:"varint,6,opt,name=LAICFKMFKEH,proto3" json:"LAICFKMFKEH,omitempty"`
	GGBMJHIMBDP uint32 `protobuf:"varint,3,opt,name=GGBMJHIMBDP,proto3" json:"GGBMJHIMBDP,omitempty"`
	NPLPFHEKCIH uint32 `protobuf:"varint,14,opt,name=NPLPFHEKCIH,proto3" json:"NPLPFHEKCIH,omitempty"`
	LevelId     uint32 `protobuf:"varint,12,opt,name=level_id,json=levelId,proto3" json:"level_id,omitempty"`
	IsLevelOpen bool   `protobuf:"varint,11,opt,name=is_level_open,json=isLevelOpen,proto3" json:"is_level_open,omitempty"`
}

func (x *EffigyChallengeV2LevelData) Reset() {
	*x = EffigyChallengeV2LevelData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_EffigyChallengeV2LevelData_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EffigyChallengeV2LevelData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EffigyChallengeV2LevelData) ProtoMessage() {}

func (x *EffigyChallengeV2LevelData) ProtoReflect() protoreflect.Message {
	mi := &file_EffigyChallengeV2LevelData_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EffigyChallengeV2LevelData.ProtoReflect.Descriptor instead.
func (*EffigyChallengeV2LevelData) Descriptor() ([]byte, []int) {
	return file_EffigyChallengeV2LevelData_proto_rawDescGZIP(), []int{0}
}

func (x *EffigyChallengeV2LevelData) GetPPMPMJHEJHJ() uint32 {
	if x != nil {
		return x.PPMPMJHEJHJ
	}
	return 0
}

func (x *EffigyChallengeV2LevelData) GetLAICFKMFKEH() uint32 {
	if x != nil {
		return x.LAICFKMFKEH
	}
	return 0
}

func (x *EffigyChallengeV2LevelData) GetGGBMJHIMBDP() uint32 {
	if x != nil {
		return x.GGBMJHIMBDP
	}
	return 0
}

func (x *EffigyChallengeV2LevelData) GetNPLPFHEKCIH() uint32 {
	if x != nil {
		return x.NPLPFHEKCIH
	}
	return 0
}

func (x *EffigyChallengeV2LevelData) GetLevelId() uint32 {
	if x != nil {
		return x.LevelId
	}
	return 0
}

func (x *EffigyChallengeV2LevelData) GetIsLevelOpen() bool {
	if x != nil {
		return x.IsLevelOpen
	}
	return false
}

var File_EffigyChallengeV2LevelData_proto protoreflect.FileDescriptor

var file_EffigyChallengeV2LevelData_proto_rawDesc = []byte{
	0x0a, 0x20, 0x45, 0x66, 0x66, 0x69, 0x67, 0x79, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67,
	0x65, 0x56, 0x32, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xe3, 0x01, 0x0a, 0x1a, 0x45, 0x66, 0x66, 0x69, 0x67, 0x79, 0x43, 0x68, 0x61,
	0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x56, 0x32, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x44, 0x61, 0x74,
	0x61, 0x12, 0x20, 0x0a, 0x0b, 0x50, 0x50, 0x4d, 0x50, 0x4d, 0x4a, 0x48, 0x45, 0x4a, 0x48, 0x4a,
	0x18, 0x0f, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x50, 0x50, 0x4d, 0x50, 0x4d, 0x4a, 0x48, 0x45,
	0x4a, 0x48, 0x4a, 0x12, 0x20, 0x0a, 0x0b, 0x4c, 0x41, 0x49, 0x43, 0x46, 0x4b, 0x4d, 0x46, 0x4b,
	0x45, 0x48, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4c, 0x41, 0x49, 0x43, 0x46, 0x4b,
	0x4d, 0x46, 0x4b, 0x45, 0x48, 0x12, 0x20, 0x0a, 0x0b, 0x47, 0x47, 0x42, 0x4d, 0x4a, 0x48, 0x49,
	0x4d, 0x42, 0x44, 0x50, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x47, 0x47, 0x42, 0x4d,
	0x4a, 0x48, 0x49, 0x4d, 0x42, 0x44, 0x50, 0x12, 0x20, 0x0a, 0x0b, 0x4e, 0x50, 0x4c, 0x50, 0x46,
	0x48, 0x45, 0x4b, 0x43, 0x49, 0x48, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4e, 0x50,
	0x4c, 0x50, 0x46, 0x48, 0x45, 0x4b, 0x43, 0x49, 0x48, 0x12, 0x19, 0x0a, 0x08, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x49, 0x64, 0x12, 0x22, 0x0a, 0x0d, 0x69, 0x73, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c,
	0x5f, 0x6f, 0x70, 0x65, 0x6e, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x69, 0x73, 0x4c,
	0x65, 0x76, 0x65, 0x6c, 0x4f, 0x70, 0x65, 0x6e, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_EffigyChallengeV2LevelData_proto_rawDescOnce sync.Once
	file_EffigyChallengeV2LevelData_proto_rawDescData = file_EffigyChallengeV2LevelData_proto_rawDesc
)

func file_EffigyChallengeV2LevelData_proto_rawDescGZIP() []byte {
	file_EffigyChallengeV2LevelData_proto_rawDescOnce.Do(func() {
		file_EffigyChallengeV2LevelData_proto_rawDescData = protoimpl.X.CompressGZIP(file_EffigyChallengeV2LevelData_proto_rawDescData)
	})
	return file_EffigyChallengeV2LevelData_proto_rawDescData
}

var file_EffigyChallengeV2LevelData_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_EffigyChallengeV2LevelData_proto_goTypes = []interface{}{
	(*EffigyChallengeV2LevelData)(nil), // 0: EffigyChallengeV2LevelData
}
var file_EffigyChallengeV2LevelData_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_EffigyChallengeV2LevelData_proto_init() }
func file_EffigyChallengeV2LevelData_proto_init() {
	if File_EffigyChallengeV2LevelData_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_EffigyChallengeV2LevelData_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EffigyChallengeV2LevelData); i {
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
			RawDescriptor: file_EffigyChallengeV2LevelData_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_EffigyChallengeV2LevelData_proto_goTypes,
		DependencyIndexes: file_EffigyChallengeV2LevelData_proto_depIdxs,
		MessageInfos:      file_EffigyChallengeV2LevelData_proto_msgTypes,
	}.Build()
	File_EffigyChallengeV2LevelData_proto = out.File
	file_EffigyChallengeV2LevelData_proto_rawDesc = nil
	file_EffigyChallengeV2LevelData_proto_goTypes = nil
	file_EffigyChallengeV2LevelData_proto_depIdxs = nil
}
