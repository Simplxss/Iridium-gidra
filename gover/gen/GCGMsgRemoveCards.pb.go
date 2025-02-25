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
// source: GCGMsgRemoveCards.proto

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

// Obf: BOOGIFJDFKP
type GCGMsgRemoveCards struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Reason       GCGReason   `protobuf:"varint,8,opt,name=reason,proto3,enum=GCGReason" json:"reason,omitempty"`
	ControllerId uint32      `protobuf:"varint,3,opt,name=controller_id,json=controllerId,proto3" json:"controller_id,omitempty"`
	CardGuidList []uint32    `protobuf:"varint,15,rep,packed,name=card_guid_list,json=cardGuidList,proto3" json:"card_guid_list,omitempty"`
	Zone         GCGZoneType `protobuf:"varint,7,opt,name=zone,proto3,enum=GCGZoneType" json:"zone,omitempty"`
}

func (x *GCGMsgRemoveCards) Reset() {
	*x = GCGMsgRemoveCards{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGMsgRemoveCards_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGMsgRemoveCards) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGMsgRemoveCards) ProtoMessage() {}

func (x *GCGMsgRemoveCards) ProtoReflect() protoreflect.Message {
	mi := &file_GCGMsgRemoveCards_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGMsgRemoveCards.ProtoReflect.Descriptor instead.
func (*GCGMsgRemoveCards) Descriptor() ([]byte, []int) {
	return file_GCGMsgRemoveCards_proto_rawDescGZIP(), []int{0}
}

func (x *GCGMsgRemoveCards) GetReason() GCGReason {
	if x != nil {
		return x.Reason
	}
	return GCGReason_MNDCMMKBIBP_Default
}

func (x *GCGMsgRemoveCards) GetControllerId() uint32 {
	if x != nil {
		return x.ControllerId
	}
	return 0
}

func (x *GCGMsgRemoveCards) GetCardGuidList() []uint32 {
	if x != nil {
		return x.CardGuidList
	}
	return nil
}

func (x *GCGMsgRemoveCards) GetZone() GCGZoneType {
	if x != nil {
		return x.Zone
	}
	return GCGZoneType_GCG_ZONE_INVALID
}

var File_GCGMsgRemoveCards_proto protoreflect.FileDescriptor

var file_GCGMsgRemoveCards_proto_rawDesc = []byte{
	0x0a, 0x17, 0x47, 0x43, 0x47, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x61,
	0x72, 0x64, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x47, 0x43, 0x47, 0x52, 0x65,
	0x61, 0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x47, 0x43, 0x47, 0x5a,
	0x6f, 0x6e, 0x65, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa4, 0x01,
	0x0a, 0x11, 0x47, 0x43, 0x47, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x61,
	0x72, 0x64, 0x73, 0x12, 0x22, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x08, 0x20,
	0x01, 0x28, 0x0e, 0x32, 0x0a, 0x2e, 0x47, 0x43, 0x47, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x52,
	0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x72,
	0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x0e,
	0x63, 0x61, 0x72, 0x64, 0x5f, 0x67, 0x75, 0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0f,
	0x20, 0x03, 0x28, 0x0d, 0x52, 0x0c, 0x63, 0x61, 0x72, 0x64, 0x47, 0x75, 0x69, 0x64, 0x4c, 0x69,
	0x73, 0x74, 0x12, 0x20, 0x0a, 0x04, 0x7a, 0x6f, 0x6e, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x0c, 0x2e, 0x47, 0x43, 0x47, 0x5a, 0x6f, 0x6e, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04,
	0x7a, 0x6f, 0x6e, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGMsgRemoveCards_proto_rawDescOnce sync.Once
	file_GCGMsgRemoveCards_proto_rawDescData = file_GCGMsgRemoveCards_proto_rawDesc
)

func file_GCGMsgRemoveCards_proto_rawDescGZIP() []byte {
	file_GCGMsgRemoveCards_proto_rawDescOnce.Do(func() {
		file_GCGMsgRemoveCards_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGMsgRemoveCards_proto_rawDescData)
	})
	return file_GCGMsgRemoveCards_proto_rawDescData
}

var file_GCGMsgRemoveCards_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGMsgRemoveCards_proto_goTypes = []interface{}{
	(*GCGMsgRemoveCards)(nil), // 0: GCGMsgRemoveCards
	(GCGReason)(0),            // 1: GCGReason
	(GCGZoneType)(0),          // 2: GCGZoneType
}
var file_GCGMsgRemoveCards_proto_depIdxs = []int32{
	1, // 0: GCGMsgRemoveCards.reason:type_name -> GCGReason
	2, // 1: GCGMsgRemoveCards.zone:type_name -> GCGZoneType
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_GCGMsgRemoveCards_proto_init() }
func file_GCGMsgRemoveCards_proto_init() {
	if File_GCGMsgRemoveCards_proto != nil {
		return
	}
	file_GCGReason_proto_init()
	file_GCGZoneType_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GCGMsgRemoveCards_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGMsgRemoveCards); i {
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
			RawDescriptor: file_GCGMsgRemoveCards_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGMsgRemoveCards_proto_goTypes,
		DependencyIndexes: file_GCGMsgRemoveCards_proto_depIdxs,
		MessageInfos:      file_GCGMsgRemoveCards_proto_msgTypes,
	}.Build()
	File_GCGMsgRemoveCards_proto = out.File
	file_GCGMsgRemoveCards_proto_rawDesc = nil
	file_GCGMsgRemoveCards_proto_goTypes = nil
	file_GCGMsgRemoveCards_proto_depIdxs = nil
}
