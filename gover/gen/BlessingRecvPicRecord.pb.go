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
// source: BlessingRecvPicRecord.proto

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

// Obf: FDIOPMKFCCB
type BlessingRecvPicRecord struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PicId          uint32          `protobuf:"varint,15,opt,name=pic_id,json=picId,proto3" json:"pic_id,omitempty"`
	Uid            uint32          `protobuf:"varint,7,opt,name=uid,proto3" json:"uid,omitempty"`
	ProfilePicture *ProfilePicture `protobuf:"bytes,9,opt,name=profile_picture,json=profilePicture,proto3" json:"profile_picture,omitempty"`
	RemarkName     string          `protobuf:"bytes,1,opt,name=remark_name,json=remarkName,proto3" json:"remark_name,omitempty"`
	AvatarId       uint32          `protobuf:"varint,6,opt,name=avatar_id,json=avatarId,proto3" json:"avatar_id,omitempty"`
	IsRecv         bool            `protobuf:"varint,10,opt,name=is_recv,json=isRecv,proto3" json:"is_recv,omitempty"`
	Signature      string          `protobuf:"bytes,4,opt,name=signature,proto3" json:"signature,omitempty"`
	Index          uint32          `protobuf:"varint,13,opt,name=index,proto3" json:"index,omitempty"`
	Nickname       string          `protobuf:"bytes,14,opt,name=nickname,proto3" json:"nickname,omitempty"`
}

func (x *BlessingRecvPicRecord) Reset() {
	*x = BlessingRecvPicRecord{}
	if protoimpl.UnsafeEnabled {
		mi := &file_BlessingRecvPicRecord_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BlessingRecvPicRecord) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlessingRecvPicRecord) ProtoMessage() {}

func (x *BlessingRecvPicRecord) ProtoReflect() protoreflect.Message {
	mi := &file_BlessingRecvPicRecord_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlessingRecvPicRecord.ProtoReflect.Descriptor instead.
func (*BlessingRecvPicRecord) Descriptor() ([]byte, []int) {
	return file_BlessingRecvPicRecord_proto_rawDescGZIP(), []int{0}
}

func (x *BlessingRecvPicRecord) GetPicId() uint32 {
	if x != nil {
		return x.PicId
	}
	return 0
}

func (x *BlessingRecvPicRecord) GetUid() uint32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

func (x *BlessingRecvPicRecord) GetProfilePicture() *ProfilePicture {
	if x != nil {
		return x.ProfilePicture
	}
	return nil
}

func (x *BlessingRecvPicRecord) GetRemarkName() string {
	if x != nil {
		return x.RemarkName
	}
	return ""
}

func (x *BlessingRecvPicRecord) GetAvatarId() uint32 {
	if x != nil {
		return x.AvatarId
	}
	return 0
}

func (x *BlessingRecvPicRecord) GetIsRecv() bool {
	if x != nil {
		return x.IsRecv
	}
	return false
}

func (x *BlessingRecvPicRecord) GetSignature() string {
	if x != nil {
		return x.Signature
	}
	return ""
}

func (x *BlessingRecvPicRecord) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *BlessingRecvPicRecord) GetNickname() string {
	if x != nil {
		return x.Nickname
	}
	return ""
}

var File_BlessingRecvPicRecord_proto protoreflect.FileDescriptor

var file_BlessingRecvPicRecord_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x42, 0x6c, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x63, 0x76, 0x50, 0x69,
	0x63, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x50,
	0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x50, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xa1, 0x02, 0x0a, 0x15, 0x42, 0x6c, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67,
	0x52, 0x65, 0x63, 0x76, 0x50, 0x69, 0x63, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x12, 0x15, 0x0a,
	0x06, 0x70, 0x69, 0x63, 0x5f, 0x69, 0x64, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x70,
	0x69, 0x63, 0x49, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12, 0x38, 0x0a, 0x0f, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c,
	0x65, 0x5f, 0x70, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x0f, 0x2e, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x50, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65,
	0x52, 0x0e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x50, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65,
	0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x6d, 0x61, 0x72, 0x6b, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x72, 0x65, 0x6d, 0x61, 0x72, 0x6b, 0x4e, 0x61, 0x6d,
	0x65, 0x12, 0x1b, 0x0a, 0x09, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x64, 0x12, 0x17,
	0x0a, 0x07, 0x69, 0x73, 0x5f, 0x72, 0x65, 0x63, 0x76, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x06, 0x69, 0x73, 0x52, 0x65, 0x63, 0x76, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x0d,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1a, 0x0a, 0x08, 0x6e,
	0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6e,
	0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_BlessingRecvPicRecord_proto_rawDescOnce sync.Once
	file_BlessingRecvPicRecord_proto_rawDescData = file_BlessingRecvPicRecord_proto_rawDesc
)

func file_BlessingRecvPicRecord_proto_rawDescGZIP() []byte {
	file_BlessingRecvPicRecord_proto_rawDescOnce.Do(func() {
		file_BlessingRecvPicRecord_proto_rawDescData = protoimpl.X.CompressGZIP(file_BlessingRecvPicRecord_proto_rawDescData)
	})
	return file_BlessingRecvPicRecord_proto_rawDescData
}

var file_BlessingRecvPicRecord_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_BlessingRecvPicRecord_proto_goTypes = []interface{}{
	(*BlessingRecvPicRecord)(nil), // 0: BlessingRecvPicRecord
	(*ProfilePicture)(nil),        // 1: ProfilePicture
}
var file_BlessingRecvPicRecord_proto_depIdxs = []int32{
	1, // 0: BlessingRecvPicRecord.profile_picture:type_name -> ProfilePicture
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_BlessingRecvPicRecord_proto_init() }
func file_BlessingRecvPicRecord_proto_init() {
	if File_BlessingRecvPicRecord_proto != nil {
		return
	}
	file_ProfilePicture_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_BlessingRecvPicRecord_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BlessingRecvPicRecord); i {
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
			RawDescriptor: file_BlessingRecvPicRecord_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_BlessingRecvPicRecord_proto_goTypes,
		DependencyIndexes: file_BlessingRecvPicRecord_proto_depIdxs,
		MessageInfos:      file_BlessingRecvPicRecord_proto_msgTypes,
	}.Build()
	File_BlessingRecvPicRecord_proto = out.File
	file_BlessingRecvPicRecord_proto_rawDesc = nil
	file_BlessingRecvPicRecord_proto_goTypes = nil
	file_BlessingRecvPicRecord_proto_depIdxs = nil
}
