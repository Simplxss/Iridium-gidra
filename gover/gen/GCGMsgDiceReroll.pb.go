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
// source: GCGMsgDiceReroll.proto

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

// Obf: NNGPPLAPAHP
type GCGMsgDiceReroll struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ControllerId        uint32            `protobuf:"varint,13,opt,name=controller_id,json=controllerId,proto3" json:"controller_id,omitempty"`
	SelectDiceIndexList []uint32          `protobuf:"varint,15,rep,packed,name=select_dice_index_list,json=selectDiceIndexList,proto3" json:"select_dice_index_list,omitempty"`
	DiceSideList        []GCGDiceSideType `protobuf:"varint,11,rep,packed,name=dice_side_list,json=diceSideList,proto3,enum=GCGDiceSideType" json:"dice_side_list,omitempty"`
}

func (x *GCGMsgDiceReroll) Reset() {
	*x = GCGMsgDiceReroll{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGMsgDiceReroll_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGMsgDiceReroll) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGMsgDiceReroll) ProtoMessage() {}

func (x *GCGMsgDiceReroll) ProtoReflect() protoreflect.Message {
	mi := &file_GCGMsgDiceReroll_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGMsgDiceReroll.ProtoReflect.Descriptor instead.
func (*GCGMsgDiceReroll) Descriptor() ([]byte, []int) {
	return file_GCGMsgDiceReroll_proto_rawDescGZIP(), []int{0}
}

func (x *GCGMsgDiceReroll) GetControllerId() uint32 {
	if x != nil {
		return x.ControllerId
	}
	return 0
}

func (x *GCGMsgDiceReroll) GetSelectDiceIndexList() []uint32 {
	if x != nil {
		return x.SelectDiceIndexList
	}
	return nil
}

func (x *GCGMsgDiceReroll) GetDiceSideList() []GCGDiceSideType {
	if x != nil {
		return x.DiceSideList
	}
	return nil
}

var File_GCGMsgDiceReroll_proto protoreflect.FileDescriptor

var file_GCGMsgDiceReroll_proto_rawDesc = []byte{
	0x0a, 0x16, 0x47, 0x43, 0x47, 0x4d, 0x73, 0x67, 0x44, 0x69, 0x63, 0x65, 0x52, 0x65, 0x72, 0x6f,
	0x6c, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x15, 0x47, 0x43, 0x47, 0x44, 0x69, 0x63,
	0x65, 0x53, 0x69, 0x64, 0x65, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xa4, 0x01, 0x0a, 0x10, 0x47, 0x43, 0x47, 0x4d, 0x73, 0x67, 0x44, 0x69, 0x63, 0x65, 0x52, 0x65,
	0x72, 0x6f, 0x6c, 0x6c, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0c, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x49, 0x64, 0x12, 0x33, 0x0a, 0x16, 0x73, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x5f, 0x64, 0x69, 0x63, 0x65, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x18, 0x0f, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x13, 0x73, 0x65, 0x6c, 0x65, 0x63,
	0x74, 0x44, 0x69, 0x63, 0x65, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x36,
	0x0a, 0x0e, 0x64, 0x69, 0x63, 0x65, 0x5f, 0x73, 0x69, 0x64, 0x65, 0x5f, 0x6c, 0x69, 0x73, 0x74,
	0x18, 0x0b, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x10, 0x2e, 0x47, 0x43, 0x47, 0x44, 0x69, 0x63, 0x65,
	0x53, 0x69, 0x64, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0c, 0x64, 0x69, 0x63, 0x65, 0x53, 0x69,
	0x64, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGMsgDiceReroll_proto_rawDescOnce sync.Once
	file_GCGMsgDiceReroll_proto_rawDescData = file_GCGMsgDiceReroll_proto_rawDesc
)

func file_GCGMsgDiceReroll_proto_rawDescGZIP() []byte {
	file_GCGMsgDiceReroll_proto_rawDescOnce.Do(func() {
		file_GCGMsgDiceReroll_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGMsgDiceReroll_proto_rawDescData)
	})
	return file_GCGMsgDiceReroll_proto_rawDescData
}

var file_GCGMsgDiceReroll_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGMsgDiceReroll_proto_goTypes = []interface{}{
	(*GCGMsgDiceReroll)(nil), // 0: GCGMsgDiceReroll
	(GCGDiceSideType)(0),     // 1: GCGDiceSideType
}
var file_GCGMsgDiceReroll_proto_depIdxs = []int32{
	1, // 0: GCGMsgDiceReroll.dice_side_list:type_name -> GCGDiceSideType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_GCGMsgDiceReroll_proto_init() }
func file_GCGMsgDiceReroll_proto_init() {
	if File_GCGMsgDiceReroll_proto != nil {
		return
	}
	file_GCGDiceSideType_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GCGMsgDiceReroll_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGMsgDiceReroll); i {
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
			RawDescriptor: file_GCGMsgDiceReroll_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGMsgDiceReroll_proto_goTypes,
		DependencyIndexes: file_GCGMsgDiceReroll_proto_depIdxs,
		MessageInfos:      file_GCGMsgDiceReroll_proto_msgTypes,
	}.Build()
	File_GCGMsgDiceReroll_proto = out.File
	file_GCGMsgDiceReroll_proto_rawDesc = nil
	file_GCGMsgDiceReroll_proto_goTypes = nil
	file_GCGMsgDiceReroll_proto_depIdxs = nil
}
