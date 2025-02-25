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
// source: ClientGadgetInfo.proto

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

// Obf: KCPDCBKPNNL
type ClientGadgetInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	CampId                   uint32   `protobuf:"varint,1,opt,name=camp_id,json=campId,proto3" json:"camp_id,omitempty"`
	CampType                 uint32   `protobuf:"varint,2,opt,name=camp_type,json=campType,proto3" json:"camp_type,omitempty"`
	Guid                     uint64   `protobuf:"varint,3,opt,name=guid,proto3" json:"guid,omitempty"`
	OwnerEntityId            uint32   `protobuf:"varint,4,opt,name=owner_entity_id,json=ownerEntityId,proto3" json:"owner_entity_id,omitempty"`
	TargetEntityId           uint32   `protobuf:"varint,5,opt,name=target_entity_id,json=targetEntityId,proto3" json:"target_entity_id,omitempty"`
	AsyncLoad                bool     `protobuf:"varint,6,opt,name=async_load,json=asyncLoad,proto3" json:"async_load,omitempty"`
	IsPeerIdFromPlayer       bool     `protobuf:"varint,7,opt,name=is_peer_id_from_player,json=isPeerIdFromPlayer,proto3" json:"is_peer_id_from_player,omitempty"`
	TargetEntityIdList       []uint32 `protobuf:"varint,8,rep,packed,name=target_entity_id_list,json=targetEntityIdList,proto3" json:"target_entity_id_list,omitempty"`
	TargetLockPointIndexList []uint32 `protobuf:"varint,9,rep,packed,name=target_lock_point_index_list,json=targetLockPointIndexList,proto3" json:"target_lock_point_index_list,omitempty"`
}

func (x *ClientGadgetInfo) Reset() {
	*x = ClientGadgetInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ClientGadgetInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientGadgetInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientGadgetInfo) ProtoMessage() {}

func (x *ClientGadgetInfo) ProtoReflect() protoreflect.Message {
	mi := &file_ClientGadgetInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientGadgetInfo.ProtoReflect.Descriptor instead.
func (*ClientGadgetInfo) Descriptor() ([]byte, []int) {
	return file_ClientGadgetInfo_proto_rawDescGZIP(), []int{0}
}

func (x *ClientGadgetInfo) GetCampId() uint32 {
	if x != nil {
		return x.CampId
	}
	return 0
}

func (x *ClientGadgetInfo) GetCampType() uint32 {
	if x != nil {
		return x.CampType
	}
	return 0
}

func (x *ClientGadgetInfo) GetGuid() uint64 {
	if x != nil {
		return x.Guid
	}
	return 0
}

func (x *ClientGadgetInfo) GetOwnerEntityId() uint32 {
	if x != nil {
		return x.OwnerEntityId
	}
	return 0
}

func (x *ClientGadgetInfo) GetTargetEntityId() uint32 {
	if x != nil {
		return x.TargetEntityId
	}
	return 0
}

func (x *ClientGadgetInfo) GetAsyncLoad() bool {
	if x != nil {
		return x.AsyncLoad
	}
	return false
}

func (x *ClientGadgetInfo) GetIsPeerIdFromPlayer() bool {
	if x != nil {
		return x.IsPeerIdFromPlayer
	}
	return false
}

func (x *ClientGadgetInfo) GetTargetEntityIdList() []uint32 {
	if x != nil {
		return x.TargetEntityIdList
	}
	return nil
}

func (x *ClientGadgetInfo) GetTargetLockPointIndexList() []uint32 {
	if x != nil {
		return x.TargetLockPointIndexList
	}
	return nil
}

var File_ClientGadgetInfo_proto protoreflect.FileDescriptor

var file_ClientGadgetInfo_proto_rawDesc = []byte{
	0x0a, 0x16, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x49, 0x6e,
	0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf4, 0x02, 0x0a, 0x10, 0x43, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x17, 0x0a,
	0x07, 0x63, 0x61, 0x6d, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06,
	0x63, 0x61, 0x6d, 0x70, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x61, 0x6d, 0x70, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x63, 0x61, 0x6d, 0x70, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x67, 0x75, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x04, 0x67, 0x75, 0x69, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x6f, 0x77, 0x6e, 0x65, 0x72,
	0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0d, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x64, 0x12,
	0x28, 0x0a, 0x10, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x61, 0x73, 0x79,
	0x6e, 0x63, 0x5f, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x61,
	0x73, 0x79, 0x6e, 0x63, 0x4c, 0x6f, 0x61, 0x64, 0x12, 0x32, 0x0a, 0x16, 0x69, 0x73, 0x5f, 0x70,
	0x65, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x5f, 0x70, 0x6c, 0x61, 0x79,
	0x65, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x12, 0x69, 0x73, 0x50, 0x65, 0x65, 0x72,
	0x49, 0x64, 0x46, 0x72, 0x6f, 0x6d, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x12, 0x31, 0x0a, 0x15,
	0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x64,
	0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x12, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x12,
	0x3e, 0x0a, 0x1c, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18,
	0x09, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x18, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x63,
	0x6b, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x4c, 0x69, 0x73, 0x74, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ClientGadgetInfo_proto_rawDescOnce sync.Once
	file_ClientGadgetInfo_proto_rawDescData = file_ClientGadgetInfo_proto_rawDesc
)

func file_ClientGadgetInfo_proto_rawDescGZIP() []byte {
	file_ClientGadgetInfo_proto_rawDescOnce.Do(func() {
		file_ClientGadgetInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_ClientGadgetInfo_proto_rawDescData)
	})
	return file_ClientGadgetInfo_proto_rawDescData
}

var file_ClientGadgetInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ClientGadgetInfo_proto_goTypes = []interface{}{
	(*ClientGadgetInfo)(nil), // 0: ClientGadgetInfo
}
var file_ClientGadgetInfo_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_ClientGadgetInfo_proto_init() }
func file_ClientGadgetInfo_proto_init() {
	if File_ClientGadgetInfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ClientGadgetInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientGadgetInfo); i {
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
			RawDescriptor: file_ClientGadgetInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ClientGadgetInfo_proto_goTypes,
		DependencyIndexes: file_ClientGadgetInfo_proto_depIdxs,
		MessageInfos:      file_ClientGadgetInfo_proto_msgTypes,
	}.Build()
	File_ClientGadgetInfo_proto = out.File
	file_ClientGadgetInfo_proto_rawDesc = nil
	file_ClientGadgetInfo_proto_goTypes = nil
	file_ClientGadgetInfo_proto_depIdxs = nil
}
