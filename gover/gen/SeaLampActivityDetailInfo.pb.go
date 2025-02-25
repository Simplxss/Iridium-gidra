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
// source: SeaLampActivityDetailInfo.proto

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

// Obf: CFBFFJIHDHB
type SeaLampActivityDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KEEHFLCINNM uint32   `protobuf:"varint,8,opt,name=KEEHFLCINNM,proto3" json:"KEEHFLCINNM,omitempty"`
	Progress    uint32   `protobuf:"varint,7,opt,name=progress,proto3" json:"progress,omitempty"`
	AGBEEFKCBIN uint32   `protobuf:"varint,9,opt,name=AGBEEFKCBIN,proto3" json:"AGBEEFKCBIN,omitempty"`
	Days        uint32   `protobuf:"varint,3,opt,name=days,proto3" json:"days,omitempty"`
	PhaseId     uint32   `protobuf:"varint,6,opt,name=phase_id,json=phaseId,proto3" json:"phase_id,omitempty"`
	MDLABDFGHBC []uint32 `protobuf:"varint,14,rep,packed,name=MDLABDFGHBC,proto3" json:"MDLABDFGHBC,omitempty"`
	NGAIOHOOHDO []uint32 `protobuf:"varint,5,rep,packed,name=NGAIOHOOHDO,proto3" json:"NGAIOHOOHDO,omitempty"`
}

func (x *SeaLampActivityDetailInfo) Reset() {
	*x = SeaLampActivityDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SeaLampActivityDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SeaLampActivityDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SeaLampActivityDetailInfo) ProtoMessage() {}

func (x *SeaLampActivityDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_SeaLampActivityDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SeaLampActivityDetailInfo.ProtoReflect.Descriptor instead.
func (*SeaLampActivityDetailInfo) Descriptor() ([]byte, []int) {
	return file_SeaLampActivityDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *SeaLampActivityDetailInfo) GetKEEHFLCINNM() uint32 {
	if x != nil {
		return x.KEEHFLCINNM
	}
	return 0
}

func (x *SeaLampActivityDetailInfo) GetProgress() uint32 {
	if x != nil {
		return x.Progress
	}
	return 0
}

func (x *SeaLampActivityDetailInfo) GetAGBEEFKCBIN() uint32 {
	if x != nil {
		return x.AGBEEFKCBIN
	}
	return 0
}

func (x *SeaLampActivityDetailInfo) GetDays() uint32 {
	if x != nil {
		return x.Days
	}
	return 0
}

func (x *SeaLampActivityDetailInfo) GetPhaseId() uint32 {
	if x != nil {
		return x.PhaseId
	}
	return 0
}

func (x *SeaLampActivityDetailInfo) GetMDLABDFGHBC() []uint32 {
	if x != nil {
		return x.MDLABDFGHBC
	}
	return nil
}

func (x *SeaLampActivityDetailInfo) GetNGAIOHOOHDO() []uint32 {
	if x != nil {
		return x.NGAIOHOOHDO
	}
	return nil
}

var File_SeaLampActivityDetailInfo_proto protoreflect.FileDescriptor

var file_SeaLampActivityDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x1f, 0x53, 0x65, 0x61, 0x4c, 0x61, 0x6d, 0x70, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
	0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0xee, 0x01, 0x0a, 0x19, 0x53, 0x65, 0x61, 0x4c, 0x61, 0x6d, 0x70, 0x41, 0x63, 0x74,
	0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12,
	0x20, 0x0a, 0x0b, 0x4b, 0x45, 0x45, 0x48, 0x46, 0x4c, 0x43, 0x49, 0x4e, 0x4e, 0x4d, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4b, 0x45, 0x45, 0x48, 0x46, 0x4c, 0x43, 0x49, 0x4e, 0x4e,
	0x4d, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x12, 0x20, 0x0a,
	0x0b, 0x41, 0x47, 0x42, 0x45, 0x45, 0x46, 0x4b, 0x43, 0x42, 0x49, 0x4e, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x41, 0x47, 0x42, 0x45, 0x45, 0x46, 0x4b, 0x43, 0x42, 0x49, 0x4e, 0x12,
	0x12, 0x0a, 0x04, 0x64, 0x61, 0x79, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x64,
	0x61, 0x79, 0x73, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x68, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x64, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x70, 0x68, 0x61, 0x73, 0x65, 0x49, 0x64, 0x12, 0x20,
	0x0a, 0x0b, 0x4d, 0x44, 0x4c, 0x41, 0x42, 0x44, 0x46, 0x47, 0x48, 0x42, 0x43, 0x18, 0x0e, 0x20,
	0x03, 0x28, 0x0d, 0x52, 0x0b, 0x4d, 0x44, 0x4c, 0x41, 0x42, 0x44, 0x46, 0x47, 0x48, 0x42, 0x43,
	0x12, 0x20, 0x0a, 0x0b, 0x4e, 0x47, 0x41, 0x49, 0x4f, 0x48, 0x4f, 0x4f, 0x48, 0x44, 0x4f, 0x18,
	0x05, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0b, 0x4e, 0x47, 0x41, 0x49, 0x4f, 0x48, 0x4f, 0x4f, 0x48,
	0x44, 0x4f, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_SeaLampActivityDetailInfo_proto_rawDescOnce sync.Once
	file_SeaLampActivityDetailInfo_proto_rawDescData = file_SeaLampActivityDetailInfo_proto_rawDesc
)

func file_SeaLampActivityDetailInfo_proto_rawDescGZIP() []byte {
	file_SeaLampActivityDetailInfo_proto_rawDescOnce.Do(func() {
		file_SeaLampActivityDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_SeaLampActivityDetailInfo_proto_rawDescData)
	})
	return file_SeaLampActivityDetailInfo_proto_rawDescData
}

var file_SeaLampActivityDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SeaLampActivityDetailInfo_proto_goTypes = []interface{}{
	(*SeaLampActivityDetailInfo)(nil), // 0: SeaLampActivityDetailInfo
}
var file_SeaLampActivityDetailInfo_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_SeaLampActivityDetailInfo_proto_init() }
func file_SeaLampActivityDetailInfo_proto_init() {
	if File_SeaLampActivityDetailInfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_SeaLampActivityDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SeaLampActivityDetailInfo); i {
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
			RawDescriptor: file_SeaLampActivityDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SeaLampActivityDetailInfo_proto_goTypes,
		DependencyIndexes: file_SeaLampActivityDetailInfo_proto_depIdxs,
		MessageInfos:      file_SeaLampActivityDetailInfo_proto_msgTypes,
	}.Build()
	File_SeaLampActivityDetailInfo_proto = out.File
	file_SeaLampActivityDetailInfo_proto_rawDesc = nil
	file_SeaLampActivityDetailInfo_proto_goTypes = nil
	file_SeaLampActivityDetailInfo_proto_depIdxs = nil
}
