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
// source: EntityForceSyncRsp.proto

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

// CmdId: 24909
// Obf: MIKANEGPAPE
type EntityForceSyncRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SceneTime  uint32      `protobuf:"varint,9,opt,name=scene_time,json=sceneTime,proto3" json:"scene_time,omitempty"`
	EntityId   uint32      `protobuf:"varint,7,opt,name=entity_id,json=entityId,proto3" json:"entity_id,omitempty"`
	Retcode    int32       `protobuf:"varint,12,opt,name=retcode,proto3" json:"retcode,omitempty"`
	FailMotion *MotionInfo `protobuf:"bytes,15,opt,name=fail_motion,json=failMotion,proto3" json:"fail_motion,omitempty"`
}

func (x *EntityForceSyncRsp) Reset() {
	*x = EntityForceSyncRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_EntityForceSyncRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EntityForceSyncRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EntityForceSyncRsp) ProtoMessage() {}

func (x *EntityForceSyncRsp) ProtoReflect() protoreflect.Message {
	mi := &file_EntityForceSyncRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EntityForceSyncRsp.ProtoReflect.Descriptor instead.
func (*EntityForceSyncRsp) Descriptor() ([]byte, []int) {
	return file_EntityForceSyncRsp_proto_rawDescGZIP(), []int{0}
}

func (x *EntityForceSyncRsp) GetSceneTime() uint32 {
	if x != nil {
		return x.SceneTime
	}
	return 0
}

func (x *EntityForceSyncRsp) GetEntityId() uint32 {
	if x != nil {
		return x.EntityId
	}
	return 0
}

func (x *EntityForceSyncRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *EntityForceSyncRsp) GetFailMotion() *MotionInfo {
	if x != nil {
		return x.FailMotion
	}
	return nil
}

var File_EntityForceSyncRsp_proto protoreflect.FileDescriptor

var file_EntityForceSyncRsp_proto_rawDesc = []byte{
	0x0a, 0x18, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x46, 0x6f, 0x72, 0x63, 0x65, 0x53, 0x79, 0x6e,
	0x63, 0x52, 0x73, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x10, 0x4d, 0x6f, 0x74, 0x69,
	0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x98, 0x01, 0x0a,
	0x12, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x46, 0x6f, 0x72, 0x63, 0x65, 0x53, 0x79, 0x6e, 0x63,
	0x52, 0x73, 0x70, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x5f, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x73, 0x63, 0x65, 0x6e, 0x65, 0x54, 0x69,
	0x6d, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x69, 0x64, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x64, 0x12,
	0x18, 0x0a, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x05,
	0x52, 0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x2c, 0x0a, 0x0b, 0x66, 0x61, 0x69,
	0x6c, 0x5f, 0x6d, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0b,
	0x2e, 0x4d, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0a, 0x66, 0x61, 0x69,
	0x6c, 0x4d, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_EntityForceSyncRsp_proto_rawDescOnce sync.Once
	file_EntityForceSyncRsp_proto_rawDescData = file_EntityForceSyncRsp_proto_rawDesc
)

func file_EntityForceSyncRsp_proto_rawDescGZIP() []byte {
	file_EntityForceSyncRsp_proto_rawDescOnce.Do(func() {
		file_EntityForceSyncRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_EntityForceSyncRsp_proto_rawDescData)
	})
	return file_EntityForceSyncRsp_proto_rawDescData
}

var file_EntityForceSyncRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_EntityForceSyncRsp_proto_goTypes = []interface{}{
	(*EntityForceSyncRsp)(nil), // 0: EntityForceSyncRsp
	(*MotionInfo)(nil),         // 1: MotionInfo
}
var file_EntityForceSyncRsp_proto_depIdxs = []int32{
	1, // 0: EntityForceSyncRsp.fail_motion:type_name -> MotionInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_EntityForceSyncRsp_proto_init() }
func file_EntityForceSyncRsp_proto_init() {
	if File_EntityForceSyncRsp_proto != nil {
		return
	}
	file_MotionInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_EntityForceSyncRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EntityForceSyncRsp); i {
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
			RawDescriptor: file_EntityForceSyncRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_EntityForceSyncRsp_proto_goTypes,
		DependencyIndexes: file_EntityForceSyncRsp_proto_depIdxs,
		MessageInfos:      file_EntityForceSyncRsp_proto_msgTypes,
	}.Build()
	File_EntityForceSyncRsp_proto = out.File
	file_EntityForceSyncRsp_proto_rawDesc = nil
	file_EntityForceSyncRsp_proto_goTypes = nil
	file_EntityForceSyncRsp_proto_depIdxs = nil
}
