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
// source: LuaEnvironmentEffectNotify.proto

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

type LuaEnvironmentEffectNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type           uint32    `protobuf:"varint,8,opt,name=type,proto3" json:"type,omitempty"`
	IntParamList   []int32   `protobuf:"varint,10,rep,packed,name=int_param_list,json=intParamList,proto3" json:"int_param_list,omitempty"`
	EffectAlias    string    `protobuf:"bytes,3,opt,name=effect_alias,json=effectAlias,proto3" json:"effect_alias,omitempty"`
	FloatParamList []float32 `protobuf:"fixed32,12,rep,packed,name=float_param_list,json=floatParamList,proto3" json:"float_param_list,omitempty"`
}

func (x *LuaEnvironmentEffectNotify) Reset() {
	*x = LuaEnvironmentEffectNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_LuaEnvironmentEffectNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LuaEnvironmentEffectNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LuaEnvironmentEffectNotify) ProtoMessage() {}

func (x *LuaEnvironmentEffectNotify) ProtoReflect() protoreflect.Message {
	mi := &file_LuaEnvironmentEffectNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LuaEnvironmentEffectNotify.ProtoReflect.Descriptor instead.
func (*LuaEnvironmentEffectNotify) Descriptor() ([]byte, []int) {
	return file_LuaEnvironmentEffectNotify_proto_rawDescGZIP(), []int{0}
}

func (x *LuaEnvironmentEffectNotify) GetType() uint32 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *LuaEnvironmentEffectNotify) GetIntParamList() []int32 {
	if x != nil {
		return x.IntParamList
	}
	return nil
}

func (x *LuaEnvironmentEffectNotify) GetEffectAlias() string {
	if x != nil {
		return x.EffectAlias
	}
	return ""
}

func (x *LuaEnvironmentEffectNotify) GetFloatParamList() []float32 {
	if x != nil {
		return x.FloatParamList
	}
	return nil
}

var File_LuaEnvironmentEffectNotify_proto protoreflect.FileDescriptor

var file_LuaEnvironmentEffectNotify_proto_rawDesc = []byte{
	0x0a, 0x20, 0x4c, 0x75, 0x61, 0x45, 0x6e, 0x76, 0x69, 0x72, 0x6f, 0x6e, 0x6d, 0x65, 0x6e, 0x74,
	0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xa3, 0x01, 0x0a, 0x1a, 0x4c, 0x75, 0x61, 0x45, 0x6e, 0x76, 0x69, 0x72, 0x6f,
	0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x45, 0x66, 0x66, 0x65, 0x63, 0x74, 0x4e, 0x6f, 0x74, 0x69, 0x66,
	0x79, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x24, 0x0a, 0x0e, 0x69, 0x6e, 0x74, 0x5f, 0x70, 0x61, 0x72,
	0x61, 0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x05, 0x52, 0x0c, 0x69,
	0x6e, 0x74, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x65,
	0x66, 0x66, 0x65, 0x63, 0x74, 0x5f, 0x61, 0x6c, 0x69, 0x61, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x65, 0x66, 0x66, 0x65, 0x63, 0x74, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x12, 0x28,
	0x0a, 0x10, 0x66, 0x6c, 0x6f, 0x61, 0x74, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x5f, 0x6c, 0x69,
	0x73, 0x74, 0x18, 0x0c, 0x20, 0x03, 0x28, 0x02, 0x52, 0x0e, 0x66, 0x6c, 0x6f, 0x61, 0x74, 0x50,
	0x61, 0x72, 0x61, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_LuaEnvironmentEffectNotify_proto_rawDescOnce sync.Once
	file_LuaEnvironmentEffectNotify_proto_rawDescData = file_LuaEnvironmentEffectNotify_proto_rawDesc
)

func file_LuaEnvironmentEffectNotify_proto_rawDescGZIP() []byte {
	file_LuaEnvironmentEffectNotify_proto_rawDescOnce.Do(func() {
		file_LuaEnvironmentEffectNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_LuaEnvironmentEffectNotify_proto_rawDescData)
	})
	return file_LuaEnvironmentEffectNotify_proto_rawDescData
}

var file_LuaEnvironmentEffectNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_LuaEnvironmentEffectNotify_proto_goTypes = []interface{}{
	(*LuaEnvironmentEffectNotify)(nil), // 0: LuaEnvironmentEffectNotify
}
var file_LuaEnvironmentEffectNotify_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_LuaEnvironmentEffectNotify_proto_init() }
func file_LuaEnvironmentEffectNotify_proto_init() {
	if File_LuaEnvironmentEffectNotify_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_LuaEnvironmentEffectNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LuaEnvironmentEffectNotify); i {
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
			RawDescriptor: file_LuaEnvironmentEffectNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_LuaEnvironmentEffectNotify_proto_goTypes,
		DependencyIndexes: file_LuaEnvironmentEffectNotify_proto_depIdxs,
		MessageInfos:      file_LuaEnvironmentEffectNotify_proto_msgTypes,
	}.Build()
	File_LuaEnvironmentEffectNotify_proto = out.File
	file_LuaEnvironmentEffectNotify_proto_rawDesc = nil
	file_LuaEnvironmentEffectNotify_proto_goTypes = nil
	file_LuaEnvironmentEffectNotify_proto_depIdxs = nil
}
