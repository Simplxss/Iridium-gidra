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
// source: SeaLampFlyLampReq.proto

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

// CmdId: 283
// Obf: IIMOKOHGGJJ
type SeaLampFlyLampReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Pos     *Vector `protobuf:"bytes,6,opt,name=pos,proto3" json:"pos,omitempty"`
	Param   int32   `protobuf:"varint,7,opt,name=param,proto3" json:"param,omitempty"`
	ItemNum uint32  `protobuf:"varint,15,opt,name=item_num,json=itemNum,proto3" json:"item_num,omitempty"`
	ItemId  uint32  `protobuf:"varint,8,opt,name=item_id,json=itemId,proto3" json:"item_id,omitempty"`
}

func (x *SeaLampFlyLampReq) Reset() {
	*x = SeaLampFlyLampReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SeaLampFlyLampReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SeaLampFlyLampReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SeaLampFlyLampReq) ProtoMessage() {}

func (x *SeaLampFlyLampReq) ProtoReflect() protoreflect.Message {
	mi := &file_SeaLampFlyLampReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SeaLampFlyLampReq.ProtoReflect.Descriptor instead.
func (*SeaLampFlyLampReq) Descriptor() ([]byte, []int) {
	return file_SeaLampFlyLampReq_proto_rawDescGZIP(), []int{0}
}

func (x *SeaLampFlyLampReq) GetPos() *Vector {
	if x != nil {
		return x.Pos
	}
	return nil
}

func (x *SeaLampFlyLampReq) GetParam() int32 {
	if x != nil {
		return x.Param
	}
	return 0
}

func (x *SeaLampFlyLampReq) GetItemNum() uint32 {
	if x != nil {
		return x.ItemNum
	}
	return 0
}

func (x *SeaLampFlyLampReq) GetItemId() uint32 {
	if x != nil {
		return x.ItemId
	}
	return 0
}

var File_SeaLampFlyLampReq_proto protoreflect.FileDescriptor

var file_SeaLampFlyLampReq_proto_rawDesc = []byte{
	0x0a, 0x17, 0x53, 0x65, 0x61, 0x4c, 0x61, 0x6d, 0x70, 0x46, 0x6c, 0x79, 0x4c, 0x61, 0x6d, 0x70,
	0x52, 0x65, 0x71, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0c, 0x56, 0x65, 0x63, 0x74, 0x6f,
	0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x78, 0x0a, 0x11, 0x53, 0x65, 0x61, 0x4c, 0x61,
	0x6d, 0x70, 0x46, 0x6c, 0x79, 0x4c, 0x61, 0x6d, 0x70, 0x52, 0x65, 0x71, 0x12, 0x19, 0x0a, 0x03,
	0x70, 0x6f, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x07, 0x2e, 0x56, 0x65, 0x63, 0x74,
	0x6f, 0x72, 0x52, 0x03, 0x70, 0x6f, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x61, 0x72, 0x61, 0x6d,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x12, 0x19, 0x0a,
	0x08, 0x69, 0x74, 0x65, 0x6d, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x07, 0x69, 0x74, 0x65, 0x6d, 0x4e, 0x75, 0x6d, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x74, 0x65, 0x6d,
	0x5f, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x69, 0x74, 0x65, 0x6d, 0x49,
	0x64, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_SeaLampFlyLampReq_proto_rawDescOnce sync.Once
	file_SeaLampFlyLampReq_proto_rawDescData = file_SeaLampFlyLampReq_proto_rawDesc
)

func file_SeaLampFlyLampReq_proto_rawDescGZIP() []byte {
	file_SeaLampFlyLampReq_proto_rawDescOnce.Do(func() {
		file_SeaLampFlyLampReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_SeaLampFlyLampReq_proto_rawDescData)
	})
	return file_SeaLampFlyLampReq_proto_rawDescData
}

var file_SeaLampFlyLampReq_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SeaLampFlyLampReq_proto_goTypes = []interface{}{
	(*SeaLampFlyLampReq)(nil), // 0: SeaLampFlyLampReq
	(*Vector)(nil),            // 1: Vector
}
var file_SeaLampFlyLampReq_proto_depIdxs = []int32{
	1, // 0: SeaLampFlyLampReq.pos:type_name -> Vector
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_SeaLampFlyLampReq_proto_init() }
func file_SeaLampFlyLampReq_proto_init() {
	if File_SeaLampFlyLampReq_proto != nil {
		return
	}
	file_Vector_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SeaLampFlyLampReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SeaLampFlyLampReq); i {
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
			RawDescriptor: file_SeaLampFlyLampReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SeaLampFlyLampReq_proto_goTypes,
		DependencyIndexes: file_SeaLampFlyLampReq_proto_depIdxs,
		MessageInfos:      file_SeaLampFlyLampReq_proto_msgTypes,
	}.Build()
	File_SeaLampFlyLampReq_proto = out.File
	file_SeaLampFlyLampReq_proto_rawDesc = nil
	file_SeaLampFlyLampReq_proto_goTypes = nil
	file_SeaLampFlyLampReq_proto_depIdxs = nil
}
