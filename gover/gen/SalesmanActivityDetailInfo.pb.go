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
// source: SalesmanActivityDetailInfo.proto

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

// Obf: OODHMOEJLLE
type SalesmanActivityDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AFJBNMCAMOB         uint32             `protobuf:"varint,9,opt,name=AFJBNMCAMOB,proto3" json:"AFJBNMCAMOB,omitempty"`
	Status              SalesmanStatusType `protobuf:"varint,12,opt,name=status,proto3,enum=SalesmanStatusType" json:"status,omitempty"`
	FNPJPBEODBN         bool               `protobuf:"varint,2,opt,name=FNPJPBEODBN,proto3" json:"FNPJPBEODBN,omitempty"`
	GCGDGLAKAIC         uint32             `protobuf:"varint,3,opt,name=GCGDGLAKAIC,proto3" json:"GCGDGLAKAIC,omitempty"`
	DayIndex            uint32             `protobuf:"varint,4,opt,name=day_index,json=dayIndex,proto3" json:"day_index,omitempty"`
	SelectedRewardIdMap map[uint32]uint32  `protobuf:"bytes,6,rep,name=selected_reward_id_map,json=selectedRewardIdMap,proto3" json:"selected_reward_id_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	CCKNCIGDIDH         uint32             `protobuf:"varint,14,opt,name=CCKNCIGDIDH,proto3" json:"CCKNCIGDIDH,omitempty"`
	DayRewardId         uint32             `protobuf:"varint,8,opt,name=day_reward_id,json=dayRewardId,proto3" json:"day_reward_id,omitempty"`
	PNGNAEEEEHC         bool               `protobuf:"varint,1,opt,name=PNGNAEEEEHC,proto3" json:"PNGNAEEEEHC,omitempty"`
	HCAIPINLEJC         uint32             `protobuf:"varint,15,opt,name=HCAIPINLEJC,proto3" json:"HCAIPINLEJC,omitempty"`
}

func (x *SalesmanActivityDetailInfo) Reset() {
	*x = SalesmanActivityDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SalesmanActivityDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SalesmanActivityDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SalesmanActivityDetailInfo) ProtoMessage() {}

func (x *SalesmanActivityDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_SalesmanActivityDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SalesmanActivityDetailInfo.ProtoReflect.Descriptor instead.
func (*SalesmanActivityDetailInfo) Descriptor() ([]byte, []int) {
	return file_SalesmanActivityDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *SalesmanActivityDetailInfo) GetAFJBNMCAMOB() uint32 {
	if x != nil {
		return x.AFJBNMCAMOB
	}
	return 0
}

func (x *SalesmanActivityDetailInfo) GetStatus() SalesmanStatusType {
	if x != nil {
		return x.Status
	}
	return SalesmanStatusType_SALESMAN_STATUS_NONE
}

func (x *SalesmanActivityDetailInfo) GetFNPJPBEODBN() bool {
	if x != nil {
		return x.FNPJPBEODBN
	}
	return false
}

func (x *SalesmanActivityDetailInfo) GetGCGDGLAKAIC() uint32 {
	if x != nil {
		return x.GCGDGLAKAIC
	}
	return 0
}

func (x *SalesmanActivityDetailInfo) GetDayIndex() uint32 {
	if x != nil {
		return x.DayIndex
	}
	return 0
}

func (x *SalesmanActivityDetailInfo) GetSelectedRewardIdMap() map[uint32]uint32 {
	if x != nil {
		return x.SelectedRewardIdMap
	}
	return nil
}

func (x *SalesmanActivityDetailInfo) GetCCKNCIGDIDH() uint32 {
	if x != nil {
		return x.CCKNCIGDIDH
	}
	return 0
}

func (x *SalesmanActivityDetailInfo) GetDayRewardId() uint32 {
	if x != nil {
		return x.DayRewardId
	}
	return 0
}

func (x *SalesmanActivityDetailInfo) GetPNGNAEEEEHC() bool {
	if x != nil {
		return x.PNGNAEEEEHC
	}
	return false
}

func (x *SalesmanActivityDetailInfo) GetHCAIPINLEJC() uint32 {
	if x != nil {
		return x.HCAIPINLEJC
	}
	return 0
}

var File_SalesmanActivityDetailInfo_proto protoreflect.FileDescriptor

var file_SalesmanActivityDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x20, 0x53, 0x61, 0x6c, 0x65, 0x73, 0x6d, 0x61, 0x6e, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69,
	0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x18, 0x53, 0x61, 0x6c, 0x65, 0x73, 0x6d, 0x61, 0x6e, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x89, 0x04, 0x0a,
	0x1a, 0x53, 0x61, 0x6c, 0x65, 0x73, 0x6d, 0x61, 0x6e, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
	0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x20, 0x0a, 0x0b, 0x41,
	0x46, 0x4a, 0x42, 0x4e, 0x4d, 0x43, 0x41, 0x4d, 0x4f, 0x42, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0b, 0x41, 0x46, 0x4a, 0x42, 0x4e, 0x4d, 0x43, 0x41, 0x4d, 0x4f, 0x42, 0x12, 0x2b, 0x0a,
	0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e,
	0x53, 0x61, 0x6c, 0x65, 0x73, 0x6d, 0x61, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x46, 0x4e,
	0x50, 0x4a, 0x50, 0x42, 0x45, 0x4f, 0x44, 0x42, 0x4e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0b, 0x46, 0x4e, 0x50, 0x4a, 0x50, 0x42, 0x45, 0x4f, 0x44, 0x42, 0x4e, 0x12, 0x20, 0x0a, 0x0b,
	0x47, 0x43, 0x47, 0x44, 0x47, 0x4c, 0x41, 0x4b, 0x41, 0x49, 0x43, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x0b, 0x47, 0x43, 0x47, 0x44, 0x47, 0x4c, 0x41, 0x4b, 0x41, 0x49, 0x43, 0x12, 0x1b,
	0x0a, 0x09, 0x64, 0x61, 0x79, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x08, 0x64, 0x61, 0x79, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x69, 0x0a, 0x16, 0x73,
	0x65, 0x6c, 0x65, 0x63, 0x74, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x77, 0x61, 0x72, 0x64, 0x5f, 0x69,
	0x64, 0x5f, 0x6d, 0x61, 0x70, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x34, 0x2e, 0x53, 0x61,
	0x6c, 0x65, 0x73, 0x6d, 0x61, 0x6e, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65,
	0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x65,
	0x64, 0x52, 0x65, 0x77, 0x61, 0x72, 0x64, 0x49, 0x64, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x52, 0x13, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x65, 0x64, 0x52, 0x65, 0x77, 0x61, 0x72,
	0x64, 0x49, 0x64, 0x4d, 0x61, 0x70, 0x12, 0x20, 0x0a, 0x0b, 0x43, 0x43, 0x4b, 0x4e, 0x43, 0x49,
	0x47, 0x44, 0x49, 0x44, 0x48, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x43, 0x43, 0x4b,
	0x4e, 0x43, 0x49, 0x47, 0x44, 0x49, 0x44, 0x48, 0x12, 0x22, 0x0a, 0x0d, 0x64, 0x61, 0x79, 0x5f,
	0x72, 0x65, 0x77, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x0b, 0x64, 0x61, 0x79, 0x52, 0x65, 0x77, 0x61, 0x72, 0x64, 0x49, 0x64, 0x12, 0x20, 0x0a, 0x0b,
	0x50, 0x4e, 0x47, 0x4e, 0x41, 0x45, 0x45, 0x45, 0x45, 0x48, 0x43, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x0b, 0x50, 0x4e, 0x47, 0x4e, 0x41, 0x45, 0x45, 0x45, 0x45, 0x48, 0x43, 0x12, 0x20,
	0x0a, 0x0b, 0x48, 0x43, 0x41, 0x49, 0x50, 0x49, 0x4e, 0x4c, 0x45, 0x4a, 0x43, 0x18, 0x0f, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0b, 0x48, 0x43, 0x41, 0x49, 0x50, 0x49, 0x4e, 0x4c, 0x45, 0x4a, 0x43,
	0x1a, 0x46, 0x0a, 0x18, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x65, 0x64, 0x52, 0x65, 0x77, 0x61,
	0x72, 0x64, 0x49, 0x64, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_SalesmanActivityDetailInfo_proto_rawDescOnce sync.Once
	file_SalesmanActivityDetailInfo_proto_rawDescData = file_SalesmanActivityDetailInfo_proto_rawDesc
)

func file_SalesmanActivityDetailInfo_proto_rawDescGZIP() []byte {
	file_SalesmanActivityDetailInfo_proto_rawDescOnce.Do(func() {
		file_SalesmanActivityDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_SalesmanActivityDetailInfo_proto_rawDescData)
	})
	return file_SalesmanActivityDetailInfo_proto_rawDescData
}

var file_SalesmanActivityDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_SalesmanActivityDetailInfo_proto_goTypes = []interface{}{
	(*SalesmanActivityDetailInfo)(nil), // 0: SalesmanActivityDetailInfo
	nil,                                // 1: SalesmanActivityDetailInfo.SelectedRewardIdMapEntry
	(SalesmanStatusType)(0),            // 2: SalesmanStatusType
}
var file_SalesmanActivityDetailInfo_proto_depIdxs = []int32{
	2, // 0: SalesmanActivityDetailInfo.status:type_name -> SalesmanStatusType
	1, // 1: SalesmanActivityDetailInfo.selected_reward_id_map:type_name -> SalesmanActivityDetailInfo.SelectedRewardIdMapEntry
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_SalesmanActivityDetailInfo_proto_init() }
func file_SalesmanActivityDetailInfo_proto_init() {
	if File_SalesmanActivityDetailInfo_proto != nil {
		return
	}
	file_SalesmanStatusType_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SalesmanActivityDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SalesmanActivityDetailInfo); i {
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
			RawDescriptor: file_SalesmanActivityDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SalesmanActivityDetailInfo_proto_goTypes,
		DependencyIndexes: file_SalesmanActivityDetailInfo_proto_depIdxs,
		MessageInfos:      file_SalesmanActivityDetailInfo_proto_msgTypes,
	}.Build()
	File_SalesmanActivityDetailInfo_proto = out.File
	file_SalesmanActivityDetailInfo_proto_rawDesc = nil
	file_SalesmanActivityDetailInfo_proto_goTypes = nil
	file_SalesmanActivityDetailInfo_proto_depIdxs = nil
}
