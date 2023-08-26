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
// source: SummerTimeV2BoatSettleNotify.proto

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

// CmdId: 7571
// Obf: PHLOLMELHDI
type SummerTimeV2BoatSettleNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsNewRecord bool                               `protobuf:"varint,2,opt,name=is_new_record,json=isNewRecord,proto3" json:"is_new_record,omitempty"`
	StageId     uint32                             `protobuf:"varint,8,opt,name=stage_id,json=stageId,proto3" json:"stage_id,omitempty"`
	GalleryId   uint32                             `protobuf:"varint,6,opt,name=gallery_id,json=galleryId,proto3" json:"gallery_id,omitempty"`
	SettleInfo  *SummerTimeV2BoatGallerySettleInfo `protobuf:"bytes,9,opt,name=settle_info,json=settleInfo,proto3" json:"settle_info,omitempty"`
}

func (x *SummerTimeV2BoatSettleNotify) Reset() {
	*x = SummerTimeV2BoatSettleNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SummerTimeV2BoatSettleNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SummerTimeV2BoatSettleNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SummerTimeV2BoatSettleNotify) ProtoMessage() {}

func (x *SummerTimeV2BoatSettleNotify) ProtoReflect() protoreflect.Message {
	mi := &file_SummerTimeV2BoatSettleNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SummerTimeV2BoatSettleNotify.ProtoReflect.Descriptor instead.
func (*SummerTimeV2BoatSettleNotify) Descriptor() ([]byte, []int) {
	return file_SummerTimeV2BoatSettleNotify_proto_rawDescGZIP(), []int{0}
}

func (x *SummerTimeV2BoatSettleNotify) GetIsNewRecord() bool {
	if x != nil {
		return x.IsNewRecord
	}
	return false
}

func (x *SummerTimeV2BoatSettleNotify) GetStageId() uint32 {
	if x != nil {
		return x.StageId
	}
	return 0
}

func (x *SummerTimeV2BoatSettleNotify) GetGalleryId() uint32 {
	if x != nil {
		return x.GalleryId
	}
	return 0
}

func (x *SummerTimeV2BoatSettleNotify) GetSettleInfo() *SummerTimeV2BoatGallerySettleInfo {
	if x != nil {
		return x.SettleInfo
	}
	return nil
}

var File_SummerTimeV2BoatSettleNotify_proto protoreflect.FileDescriptor

var file_SummerTimeV2BoatSettleNotify_proto_rawDesc = []byte{
	0x0a, 0x22, 0x53, 0x75, 0x6d, 0x6d, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65, 0x56, 0x32, 0x42, 0x6f,
	0x61, 0x74, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27, 0x53, 0x75, 0x6d, 0x6d, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65,
	0x56, 0x32, 0x42, 0x6f, 0x61, 0x74, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x65, 0x74,
	0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc1, 0x01,
	0x0a, 0x1c, 0x53, 0x75, 0x6d, 0x6d, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65, 0x56, 0x32, 0x42, 0x6f,
	0x61, 0x74, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x22,
	0x0a, 0x0d, 0x69, 0x73, 0x5f, 0x6e, 0x65, 0x77, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x69, 0x73, 0x4e, 0x65, 0x77, 0x52, 0x65, 0x63, 0x6f,
	0x72, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x73, 0x74, 0x61, 0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x73, 0x74, 0x61, 0x67, 0x65, 0x49, 0x64, 0x12, 0x1d, 0x0a,
	0x0a, 0x67, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x09, 0x67, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x49, 0x64, 0x12, 0x43, 0x0a, 0x0b,
	0x73, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x09, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x22, 0x2e, 0x53, 0x75, 0x6d, 0x6d, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65, 0x56, 0x32,
	0x42, 0x6f, 0x61, 0x74, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x65, 0x74, 0x74, 0x6c,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0a, 0x73, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66,
	0x6f, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_SummerTimeV2BoatSettleNotify_proto_rawDescOnce sync.Once
	file_SummerTimeV2BoatSettleNotify_proto_rawDescData = file_SummerTimeV2BoatSettleNotify_proto_rawDesc
)

func file_SummerTimeV2BoatSettleNotify_proto_rawDescGZIP() []byte {
	file_SummerTimeV2BoatSettleNotify_proto_rawDescOnce.Do(func() {
		file_SummerTimeV2BoatSettleNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_SummerTimeV2BoatSettleNotify_proto_rawDescData)
	})
	return file_SummerTimeV2BoatSettleNotify_proto_rawDescData
}

var file_SummerTimeV2BoatSettleNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SummerTimeV2BoatSettleNotify_proto_goTypes = []interface{}{
	(*SummerTimeV2BoatSettleNotify)(nil),      // 0: SummerTimeV2BoatSettleNotify
	(*SummerTimeV2BoatGallerySettleInfo)(nil), // 1: SummerTimeV2BoatGallerySettleInfo
}
var file_SummerTimeV2BoatSettleNotify_proto_depIdxs = []int32{
	1, // 0: SummerTimeV2BoatSettleNotify.settle_info:type_name -> SummerTimeV2BoatGallerySettleInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_SummerTimeV2BoatSettleNotify_proto_init() }
func file_SummerTimeV2BoatSettleNotify_proto_init() {
	if File_SummerTimeV2BoatSettleNotify_proto != nil {
		return
	}
	file_SummerTimeV2BoatGallerySettleInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SummerTimeV2BoatSettleNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SummerTimeV2BoatSettleNotify); i {
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
			RawDescriptor: file_SummerTimeV2BoatSettleNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SummerTimeV2BoatSettleNotify_proto_goTypes,
		DependencyIndexes: file_SummerTimeV2BoatSettleNotify_proto_depIdxs,
		MessageInfos:      file_SummerTimeV2BoatSettleNotify_proto_msgTypes,
	}.Build()
	File_SummerTimeV2BoatSettleNotify_proto = out.File
	file_SummerTimeV2BoatSettleNotify_proto_rawDesc = nil
	file_SummerTimeV2BoatSettleNotify_proto_goTypes = nil
	file_SummerTimeV2BoatSettleNotify_proto_depIdxs = nil
}
