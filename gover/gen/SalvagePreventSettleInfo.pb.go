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
// source: SalvagePreventSettleInfo.proto

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

// Obf: CJHIMPDDGKJ
type SalvagePreventSettleInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SettleInfo  *SalvagePreventGallerySettleInfo `protobuf:"bytes,15,opt,name=settle_info,json=settleInfo,proto3" json:"settle_info,omitempty"`
	IsNewRecord bool                             `protobuf:"varint,14,opt,name=is_new_record,json=isNewRecord,proto3" json:"is_new_record,omitempty"`
}

func (x *SalvagePreventSettleInfo) Reset() {
	*x = SalvagePreventSettleInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SalvagePreventSettleInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SalvagePreventSettleInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SalvagePreventSettleInfo) ProtoMessage() {}

func (x *SalvagePreventSettleInfo) ProtoReflect() protoreflect.Message {
	mi := &file_SalvagePreventSettleInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SalvagePreventSettleInfo.ProtoReflect.Descriptor instead.
func (*SalvagePreventSettleInfo) Descriptor() ([]byte, []int) {
	return file_SalvagePreventSettleInfo_proto_rawDescGZIP(), []int{0}
}

func (x *SalvagePreventSettleInfo) GetSettleInfo() *SalvagePreventGallerySettleInfo {
	if x != nil {
		return x.SettleInfo
	}
	return nil
}

func (x *SalvagePreventSettleInfo) GetIsNewRecord() bool {
	if x != nil {
		return x.IsNewRecord
	}
	return false
}

var File_SalvagePreventSettleInfo_proto protoreflect.FileDescriptor

var file_SalvagePreventSettleInfo_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x53, 0x61, 0x6c, 0x76, 0x61, 0x67, 0x65, 0x50, 0x72, 0x65, 0x76, 0x65, 0x6e, 0x74,
	0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x25, 0x53, 0x61, 0x6c, 0x76, 0x61, 0x67, 0x65, 0x50, 0x72, 0x65, 0x76, 0x65, 0x6e, 0x74,
	0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66,
	0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x81, 0x01, 0x0a, 0x18, 0x53, 0x61, 0x6c, 0x76,
	0x61, 0x67, 0x65, 0x50, 0x72, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65,
	0x49, 0x6e, 0x66, 0x6f, 0x12, 0x41, 0x0a, 0x0b, 0x73, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x5f, 0x69,
	0x6e, 0x66, 0x6f, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x53, 0x61, 0x6c, 0x76,
	0x61, 0x67, 0x65, 0x50, 0x72, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72,
	0x79, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0a, 0x73, 0x65, 0x74,
	0x74, 0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x22, 0x0a, 0x0d, 0x69, 0x73, 0x5f, 0x6e, 0x65,
	0x77, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b,
	0x69, 0x73, 0x4e, 0x65, 0x77, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_SalvagePreventSettleInfo_proto_rawDescOnce sync.Once
	file_SalvagePreventSettleInfo_proto_rawDescData = file_SalvagePreventSettleInfo_proto_rawDesc
)

func file_SalvagePreventSettleInfo_proto_rawDescGZIP() []byte {
	file_SalvagePreventSettleInfo_proto_rawDescOnce.Do(func() {
		file_SalvagePreventSettleInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_SalvagePreventSettleInfo_proto_rawDescData)
	})
	return file_SalvagePreventSettleInfo_proto_rawDescData
}

var file_SalvagePreventSettleInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SalvagePreventSettleInfo_proto_goTypes = []interface{}{
	(*SalvagePreventSettleInfo)(nil),        // 0: SalvagePreventSettleInfo
	(*SalvagePreventGallerySettleInfo)(nil), // 1: SalvagePreventGallerySettleInfo
}
var file_SalvagePreventSettleInfo_proto_depIdxs = []int32{
	1, // 0: SalvagePreventSettleInfo.settle_info:type_name -> SalvagePreventGallerySettleInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_SalvagePreventSettleInfo_proto_init() }
func file_SalvagePreventSettleInfo_proto_init() {
	if File_SalvagePreventSettleInfo_proto != nil {
		return
	}
	file_SalvagePreventGallerySettleInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SalvagePreventSettleInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SalvagePreventSettleInfo); i {
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
			RawDescriptor: file_SalvagePreventSettleInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SalvagePreventSettleInfo_proto_goTypes,
		DependencyIndexes: file_SalvagePreventSettleInfo_proto_depIdxs,
		MessageInfos:      file_SalvagePreventSettleInfo_proto_msgTypes,
	}.Build()
	File_SalvagePreventSettleInfo_proto = out.File
	file_SalvagePreventSettleInfo_proto_rawDesc = nil
	file_SalvagePreventSettleInfo_proto_goTypes = nil
	file_SalvagePreventSettleInfo_proto_depIdxs = nil
}
