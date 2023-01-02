// Sorapointa - A server software re-implementation for a certain anime game, and avoid sorapointa.
// Copyright (C) 2022  Sorapointa Team
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
// 	protoc        v3.11.3
// source: DungeonChallengeBeginNotify.proto

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

type DungeonChallengeBeginNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChallengeIndex uint32   `protobuf:"varint,3,opt,name=challenge_index,json=challengeIndex,proto3" json:"challenge_index,omitempty"`
	FatherIndex    uint32   `protobuf:"varint,13,opt,name=father_index,json=fatherIndex,proto3" json:"father_index,omitempty"`
	GroupId        uint32   `protobuf:"varint,15,opt,name=group_id,json=groupId,proto3" json:"group_id,omitempty"`
	UidList        []uint32 `protobuf:"varint,8,rep,packed,name=uid_list,json=uidList,proto3" json:"uid_list,omitempty"`
	ChallengeId    uint32   `protobuf:"varint,7,opt,name=challenge_id,json=challengeId,proto3" json:"challenge_id,omitempty"`
	ParamList      []uint32 `protobuf:"varint,2,rep,packed,name=param_list,json=paramList,proto3" json:"param_list,omitempty"`
}

func (x *DungeonChallengeBeginNotify) Reset() {
	*x = DungeonChallengeBeginNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_DungeonChallengeBeginNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DungeonChallengeBeginNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DungeonChallengeBeginNotify) ProtoMessage() {}

func (x *DungeonChallengeBeginNotify) ProtoReflect() protoreflect.Message {
	mi := &file_DungeonChallengeBeginNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DungeonChallengeBeginNotify.ProtoReflect.Descriptor instead.
func (*DungeonChallengeBeginNotify) Descriptor() ([]byte, []int) {
	return file_DungeonChallengeBeginNotify_proto_rawDescGZIP(), []int{0}
}

func (x *DungeonChallengeBeginNotify) GetChallengeIndex() uint32 {
	if x != nil {
		return x.ChallengeIndex
	}
	return 0
}

func (x *DungeonChallengeBeginNotify) GetFatherIndex() uint32 {
	if x != nil {
		return x.FatherIndex
	}
	return 0
}

func (x *DungeonChallengeBeginNotify) GetGroupId() uint32 {
	if x != nil {
		return x.GroupId
	}
	return 0
}

func (x *DungeonChallengeBeginNotify) GetUidList() []uint32 {
	if x != nil {
		return x.UidList
	}
	return nil
}

func (x *DungeonChallengeBeginNotify) GetChallengeId() uint32 {
	if x != nil {
		return x.ChallengeId
	}
	return 0
}

func (x *DungeonChallengeBeginNotify) GetParamList() []uint32 {
	if x != nil {
		return x.ParamList
	}
	return nil
}

var File_DungeonChallengeBeginNotify_proto protoreflect.FileDescriptor

var file_DungeonChallengeBeginNotify_proto_rawDesc = []byte{
	0x0a, 0x21, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e,
	0x67, 0x65, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xe1, 0x01, 0x0a, 0x1b, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43,
	0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x42, 0x65, 0x67, 0x69, 0x6e, 0x4e, 0x6f, 0x74,
	0x69, 0x66, 0x79, 0x12, 0x27, 0x0a, 0x0f, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65,
	0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x63, 0x68,
	0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x21, 0x0a, 0x0c,
	0x66, 0x61, 0x74, 0x68, 0x65, 0x72, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x0d, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0b, 0x66, 0x61, 0x74, 0x68, 0x65, 0x72, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12,
	0x19, 0x0a, 0x08, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x0f, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x07, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x75, 0x69,
	0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x07, 0x75, 0x69,
	0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e,
	0x67, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x63, 0x68, 0x61,
	0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x72, 0x61,
	0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x61,
	0x72, 0x61, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_DungeonChallengeBeginNotify_proto_rawDescOnce sync.Once
	file_DungeonChallengeBeginNotify_proto_rawDescData = file_DungeonChallengeBeginNotify_proto_rawDesc
)

func file_DungeonChallengeBeginNotify_proto_rawDescGZIP() []byte {
	file_DungeonChallengeBeginNotify_proto_rawDescOnce.Do(func() {
		file_DungeonChallengeBeginNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_DungeonChallengeBeginNotify_proto_rawDescData)
	})
	return file_DungeonChallengeBeginNotify_proto_rawDescData
}

var file_DungeonChallengeBeginNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_DungeonChallengeBeginNotify_proto_goTypes = []interface{}{
	(*DungeonChallengeBeginNotify)(nil), // 0: DungeonChallengeBeginNotify
}
var file_DungeonChallengeBeginNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_DungeonChallengeBeginNotify_proto_init() }
func file_DungeonChallengeBeginNotify_proto_init() {
	if File_DungeonChallengeBeginNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_DungeonChallengeBeginNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DungeonChallengeBeginNotify); i {
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
			RawDescriptor: file_DungeonChallengeBeginNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DungeonChallengeBeginNotify_proto_goTypes,
		DependencyIndexes: file_DungeonChallengeBeginNotify_proto_depIdxs,
		MessageInfos:      file_DungeonChallengeBeginNotify_proto_msgTypes,
	}.Build()
	File_DungeonChallengeBeginNotify_proto = out.File
	file_DungeonChallengeBeginNotify_proto_rawDesc = nil
	file_DungeonChallengeBeginNotify_proto_goTypes = nil
	file_DungeonChallengeBeginNotify_proto_depIdxs = nil
}
