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
// source: IrodoriChessMysteryInfo.proto

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

// Obf: NHCKIFIGBNE
type IrodoriChessMysteryInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ExitPointIdList     []uint32                        `protobuf:"varint,1,rep,packed,name=exit_point_id_list,json=exitPointIdList,proto3" json:"exit_point_id_list,omitempty"`
	EntrancePointIdList []uint32                        `protobuf:"varint,11,rep,packed,name=entrance_point_id_list,json=entrancePointIdList,proto3" json:"entrance_point_id_list,omitempty"`
	EntranceDetailInfo  *IrodoriChessEntranceDetailInfo `protobuf:"bytes,12,opt,name=entrance_detail_info,json=entranceDetailInfo,proto3" json:"entrance_detail_info,omitempty"`
}

func (x *IrodoriChessMysteryInfo) Reset() {
	*x = IrodoriChessMysteryInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_IrodoriChessMysteryInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IrodoriChessMysteryInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IrodoriChessMysteryInfo) ProtoMessage() {}

func (x *IrodoriChessMysteryInfo) ProtoReflect() protoreflect.Message {
	mi := &file_IrodoriChessMysteryInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IrodoriChessMysteryInfo.ProtoReflect.Descriptor instead.
func (*IrodoriChessMysteryInfo) Descriptor() ([]byte, []int) {
	return file_IrodoriChessMysteryInfo_proto_rawDescGZIP(), []int{0}
}

func (x *IrodoriChessMysteryInfo) GetExitPointIdList() []uint32 {
	if x != nil {
		return x.ExitPointIdList
	}
	return nil
}

func (x *IrodoriChessMysteryInfo) GetEntrancePointIdList() []uint32 {
	if x != nil {
		return x.EntrancePointIdList
	}
	return nil
}

func (x *IrodoriChessMysteryInfo) GetEntranceDetailInfo() *IrodoriChessEntranceDetailInfo {
	if x != nil {
		return x.EntranceDetailInfo
	}
	return nil
}

var File_IrodoriChessMysteryInfo_proto protoreflect.FileDescriptor

var file_IrodoriChessMysteryInfo_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73, 0x4d, 0x79,
	0x73, 0x74, 0x65, 0x72, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x24, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x61, 0x6e, 0x63, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xce, 0x01, 0x0a, 0x17, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72,
	0x69, 0x43, 0x68, 0x65, 0x73, 0x73, 0x4d, 0x79, 0x73, 0x74, 0x65, 0x72, 0x79, 0x49, 0x6e, 0x66,
	0x6f, 0x12, 0x2b, 0x0a, 0x12, 0x65, 0x78, 0x69, 0x74, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f,
	0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0f, 0x65,
	0x78, 0x69, 0x74, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x49, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x33,
	0x0a, 0x16, 0x65, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x5f, 0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x13,
	0x65, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x49, 0x64, 0x4c,
	0x69, 0x73, 0x74, 0x12, 0x51, 0x0a, 0x14, 0x65, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x5f,
	0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x0c, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1f, 0x2e, 0x49, 0x72, 0x6f, 0x64, 0x6f, 0x72, 0x69, 0x43, 0x68, 0x65, 0x73, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x12, 0x65, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x44, 0x65, 0x74, 0x61,
	0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_IrodoriChessMysteryInfo_proto_rawDescOnce sync.Once
	file_IrodoriChessMysteryInfo_proto_rawDescData = file_IrodoriChessMysteryInfo_proto_rawDesc
)

func file_IrodoriChessMysteryInfo_proto_rawDescGZIP() []byte {
	file_IrodoriChessMysteryInfo_proto_rawDescOnce.Do(func() {
		file_IrodoriChessMysteryInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_IrodoriChessMysteryInfo_proto_rawDescData)
	})
	return file_IrodoriChessMysteryInfo_proto_rawDescData
}

var file_IrodoriChessMysteryInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_IrodoriChessMysteryInfo_proto_goTypes = []interface{}{
	(*IrodoriChessMysteryInfo)(nil),        // 0: IrodoriChessMysteryInfo
	(*IrodoriChessEntranceDetailInfo)(nil), // 1: IrodoriChessEntranceDetailInfo
}
var file_IrodoriChessMysteryInfo_proto_depIdxs = []int32{
	1, // 0: IrodoriChessMysteryInfo.entrance_detail_info:type_name -> IrodoriChessEntranceDetailInfo
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_IrodoriChessMysteryInfo_proto_init() }
func file_IrodoriChessMysteryInfo_proto_init() {
	if File_IrodoriChessMysteryInfo_proto != nil {
		return
	}
	file_IrodoriChessEntranceDetailInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_IrodoriChessMysteryInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IrodoriChessMysteryInfo); i {
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
			RawDescriptor: file_IrodoriChessMysteryInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_IrodoriChessMysteryInfo_proto_goTypes,
		DependencyIndexes: file_IrodoriChessMysteryInfo_proto_depIdxs,
		MessageInfos:      file_IrodoriChessMysteryInfo_proto_msgTypes,
	}.Build()
	File_IrodoriChessMysteryInfo_proto = out.File
	file_IrodoriChessMysteryInfo_proto_rawDesc = nil
	file_IrodoriChessMysteryInfo_proto_goTypes = nil
	file_IrodoriChessMysteryInfo_proto_depIdxs = nil
}
