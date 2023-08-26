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
// source: MailChangeNotify.proto

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

// CmdId: 7569
// Obf: COPGIOFFCBJ
type MailChangeNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DelMailIdList []uint32    `protobuf:"varint,11,rep,packed,name=del_mail_id_list,json=delMailIdList,proto3" json:"del_mail_id_list,omitempty"`
	MailList      []*MailData `protobuf:"bytes,3,rep,name=mail_list,json=mailList,proto3" json:"mail_list,omitempty"`
}

func (x *MailChangeNotify) Reset() {
	*x = MailChangeNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_MailChangeNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MailChangeNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MailChangeNotify) ProtoMessage() {}

func (x *MailChangeNotify) ProtoReflect() protoreflect.Message {
	mi := &file_MailChangeNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MailChangeNotify.ProtoReflect.Descriptor instead.
func (*MailChangeNotify) Descriptor() ([]byte, []int) {
	return file_MailChangeNotify_proto_rawDescGZIP(), []int{0}
}

func (x *MailChangeNotify) GetDelMailIdList() []uint32 {
	if x != nil {
		return x.DelMailIdList
	}
	return nil
}

func (x *MailChangeNotify) GetMailList() []*MailData {
	if x != nil {
		return x.MailList
	}
	return nil
}

var File_MailChangeNotify_proto protoreflect.FileDescriptor

var file_MailChangeNotify_proto_rawDesc = []byte{
	0x0a, 0x16, 0x4d, 0x61, 0x69, 0x6c, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4e, 0x6f, 0x74, 0x69,
	0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0e, 0x4d, 0x61, 0x69, 0x6c, 0x44, 0x61,
	0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x63, 0x0a, 0x10, 0x4d, 0x61, 0x69, 0x6c,
	0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x27, 0x0a, 0x10,
	0x64, 0x65, 0x6c, 0x5f, 0x6d, 0x61, 0x69, 0x6c, 0x5f, 0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74,
	0x18, 0x0b, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0d, 0x64, 0x65, 0x6c, 0x4d, 0x61, 0x69, 0x6c, 0x49,
	0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x26, 0x0a, 0x09, 0x6d, 0x61, 0x69, 0x6c, 0x5f, 0x6c, 0x69,
	0x73, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x09, 0x2e, 0x4d, 0x61, 0x69, 0x6c, 0x44,
	0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x61, 0x69, 0x6c, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x06, 0x5a,
	0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_MailChangeNotify_proto_rawDescOnce sync.Once
	file_MailChangeNotify_proto_rawDescData = file_MailChangeNotify_proto_rawDesc
)

func file_MailChangeNotify_proto_rawDescGZIP() []byte {
	file_MailChangeNotify_proto_rawDescOnce.Do(func() {
		file_MailChangeNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_MailChangeNotify_proto_rawDescData)
	})
	return file_MailChangeNotify_proto_rawDescData
}

var file_MailChangeNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_MailChangeNotify_proto_goTypes = []interface{}{
	(*MailChangeNotify)(nil), // 0: MailChangeNotify
	(*MailData)(nil),         // 1: MailData
}
var file_MailChangeNotify_proto_depIdxs = []int32{
	1, // 0: MailChangeNotify.mail_list:type_name -> MailData
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_MailChangeNotify_proto_init() }
func file_MailChangeNotify_proto_init() {
	if File_MailChangeNotify_proto != nil {
		return
	}
	file_MailData_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_MailChangeNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MailChangeNotify); i {
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
			RawDescriptor: file_MailChangeNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_MailChangeNotify_proto_goTypes,
		DependencyIndexes: file_MailChangeNotify_proto_depIdxs,
		MessageInfos:      file_MailChangeNotify_proto_msgTypes,
	}.Build()
	File_MailChangeNotify_proto = out.File
	file_MailChangeNotify_proto_rawDesc = nil
	file_MailChangeNotify_proto_goTypes = nil
	file_MailChangeNotify_proto_depIdxs = nil
}
