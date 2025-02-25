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
// source: ToyBattleInfo.proto

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

// Obf: OFHIHCENLLL
type ToyBattleInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	LPBHCPBFNHK *CKBMIEMDAEP `protobuf:"bytes,3,opt,name=LPBHCPBFNHK,proto3" json:"LPBHCPBFNHK,omitempty"`
	CampInfo    *ODDAOBNJLAH `protobuf:"bytes,13,opt,name=camp_info,json=campInfo,proto3" json:"camp_info,omitempty"`
	HLMBLBNIFPJ *PNJGECAFHGE `protobuf:"bytes,15,opt,name=HLMBLBNIFPJ,proto3" json:"HLMBLBNIFPJ,omitempty"`
}

func (x *ToyBattleInfo) Reset() {
	*x = ToyBattleInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ToyBattleInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ToyBattleInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ToyBattleInfo) ProtoMessage() {}

func (x *ToyBattleInfo) ProtoReflect() protoreflect.Message {
	mi := &file_ToyBattleInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ToyBattleInfo.ProtoReflect.Descriptor instead.
func (*ToyBattleInfo) Descriptor() ([]byte, []int) {
	return file_ToyBattleInfo_proto_rawDescGZIP(), []int{0}
}

func (x *ToyBattleInfo) GetLPBHCPBFNHK() *CKBMIEMDAEP {
	if x != nil {
		return x.LPBHCPBFNHK
	}
	return nil
}

func (x *ToyBattleInfo) GetCampInfo() *ODDAOBNJLAH {
	if x != nil {
		return x.CampInfo
	}
	return nil
}

func (x *ToyBattleInfo) GetHLMBLBNIFPJ() *PNJGECAFHGE {
	if x != nil {
		return x.HLMBLBNIFPJ
	}
	return nil
}

var File_ToyBattleInfo_proto protoreflect.FileDescriptor

var file_ToyBattleInfo_proto_rawDesc = []byte{
	0x0a, 0x13, 0x54, 0x6f, 0x79, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x43, 0x4b, 0x42, 0x4d, 0x49, 0x45, 0x4d, 0x44, 0x41,
	0x45, 0x50, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x4f, 0x44, 0x44, 0x41, 0x4f, 0x42,
	0x4e, 0x4a, 0x4c, 0x41, 0x48, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x50, 0x4e, 0x4a,
	0x47, 0x45, 0x43, 0x41, 0x46, 0x48, 0x47, 0x45, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9a,
	0x01, 0x0a, 0x0d, 0x54, 0x6f, 0x79, 0x42, 0x61, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f,
	0x12, 0x2e, 0x0a, 0x0b, 0x4c, 0x50, 0x42, 0x48, 0x43, 0x50, 0x42, 0x46, 0x4e, 0x48, 0x4b, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x43, 0x4b, 0x42, 0x4d, 0x49, 0x45, 0x4d, 0x44,
	0x41, 0x45, 0x50, 0x52, 0x0b, 0x4c, 0x50, 0x42, 0x48, 0x43, 0x50, 0x42, 0x46, 0x4e, 0x48, 0x4b,
	0x12, 0x29, 0x0a, 0x09, 0x63, 0x61, 0x6d, 0x70, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x0d, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x4f, 0x44, 0x44, 0x41, 0x4f, 0x42, 0x4e, 0x4a, 0x4c, 0x41,
	0x48, 0x52, 0x08, 0x63, 0x61, 0x6d, 0x70, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2e, 0x0a, 0x0b, 0x48,
	0x4c, 0x4d, 0x42, 0x4c, 0x42, 0x4e, 0x49, 0x46, 0x50, 0x4a, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0c, 0x2e, 0x50, 0x4e, 0x4a, 0x47, 0x45, 0x43, 0x41, 0x46, 0x48, 0x47, 0x45, 0x52, 0x0b,
	0x48, 0x4c, 0x4d, 0x42, 0x4c, 0x42, 0x4e, 0x49, 0x46, 0x50, 0x4a, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ToyBattleInfo_proto_rawDescOnce sync.Once
	file_ToyBattleInfo_proto_rawDescData = file_ToyBattleInfo_proto_rawDesc
)

func file_ToyBattleInfo_proto_rawDescGZIP() []byte {
	file_ToyBattleInfo_proto_rawDescOnce.Do(func() {
		file_ToyBattleInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_ToyBattleInfo_proto_rawDescData)
	})
	return file_ToyBattleInfo_proto_rawDescData
}

var file_ToyBattleInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ToyBattleInfo_proto_goTypes = []interface{}{
	(*ToyBattleInfo)(nil), // 0: ToyBattleInfo
	(*CKBMIEMDAEP)(nil),   // 1: CKBMIEMDAEP
	(*ODDAOBNJLAH)(nil),   // 2: ODDAOBNJLAH
	(*PNJGECAFHGE)(nil),   // 3: PNJGECAFHGE
}
var file_ToyBattleInfo_proto_depIdxs = []int32{
	1, // 0: ToyBattleInfo.LPBHCPBFNHK:type_name -> CKBMIEMDAEP
	2, // 1: ToyBattleInfo.camp_info:type_name -> ODDAOBNJLAH
	3, // 2: ToyBattleInfo.HLMBLBNIFPJ:type_name -> PNJGECAFHGE
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_ToyBattleInfo_proto_init() }
func file_ToyBattleInfo_proto_init() {
	if File_ToyBattleInfo_proto != nil {
		return
	}
	file_CKBMIEMDAEP_proto_init()
	file_ODDAOBNJLAH_proto_init()
	file_PNJGECAFHGE_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ToyBattleInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ToyBattleInfo); i {
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
			RawDescriptor: file_ToyBattleInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ToyBattleInfo_proto_goTypes,
		DependencyIndexes: file_ToyBattleInfo_proto_depIdxs,
		MessageInfos:      file_ToyBattleInfo_proto_msgTypes,
	}.Build()
	File_ToyBattleInfo_proto = out.File
	file_ToyBattleInfo_proto_rawDesc = nil
	file_ToyBattleInfo_proto_goTypes = nil
	file_ToyBattleInfo_proto_depIdxs = nil
}
