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
// source: BlossomScheduleInfo.proto

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

// Obf: OAHPDJFJHLB
type BlossomScheduleInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FinishProgress uint32 `protobuf:"varint,1,opt,name=finish_progress,json=finishProgress,proto3" json:"finish_progress,omitempty"`
	Round          uint32 `protobuf:"varint,15,opt,name=round,proto3" json:"round,omitempty"`
	State          uint32 `protobuf:"varint,2,opt,name=state,proto3" json:"state,omitempty"`
	RefreshId      uint32 `protobuf:"varint,5,opt,name=refresh_id,json=refreshId,proto3" json:"refresh_id,omitempty"`
	CircleCampId   uint32 `protobuf:"varint,13,opt,name=circle_camp_id,json=circleCampId,proto3" json:"circle_camp_id,omitempty"`
	Progress       uint32 `protobuf:"varint,14,opt,name=progress,proto3" json:"progress,omitempty"`
}

func (x *BlossomScheduleInfo) Reset() {
	*x = BlossomScheduleInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_BlossomScheduleInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BlossomScheduleInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlossomScheduleInfo) ProtoMessage() {}

func (x *BlossomScheduleInfo) ProtoReflect() protoreflect.Message {
	mi := &file_BlossomScheduleInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlossomScheduleInfo.ProtoReflect.Descriptor instead.
func (*BlossomScheduleInfo) Descriptor() ([]byte, []int) {
	return file_BlossomScheduleInfo_proto_rawDescGZIP(), []int{0}
}

func (x *BlossomScheduleInfo) GetFinishProgress() uint32 {
	if x != nil {
		return x.FinishProgress
	}
	return 0
}

func (x *BlossomScheduleInfo) GetRound() uint32 {
	if x != nil {
		return x.Round
	}
	return 0
}

func (x *BlossomScheduleInfo) GetState() uint32 {
	if x != nil {
		return x.State
	}
	return 0
}

func (x *BlossomScheduleInfo) GetRefreshId() uint32 {
	if x != nil {
		return x.RefreshId
	}
	return 0
}

func (x *BlossomScheduleInfo) GetCircleCampId() uint32 {
	if x != nil {
		return x.CircleCampId
	}
	return 0
}

func (x *BlossomScheduleInfo) GetProgress() uint32 {
	if x != nil {
		return x.Progress
	}
	return 0
}

var File_BlossomScheduleInfo_proto protoreflect.FileDescriptor

var file_BlossomScheduleInfo_proto_rawDesc = []byte{
	0x0a, 0x19, 0x42, 0x6c, 0x6f, 0x73, 0x73, 0x6f, 0x6d, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c,
	0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xcb, 0x01, 0x0a, 0x13,
	0x42, 0x6c, 0x6f, 0x73, 0x73, 0x6f, 0x6d, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x49,
	0x6e, 0x66, 0x6f, 0x12, 0x27, 0x0a, 0x0f, 0x66, 0x69, 0x6e, 0x69, 0x73, 0x68, 0x5f, 0x70, 0x72,
	0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x66, 0x69,
	0x6e, 0x69, 0x73, 0x68, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x12, 0x14, 0x0a, 0x05,
	0x72, 0x6f, 0x75, 0x6e, 0x64, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x72, 0x6f, 0x75,
	0x6e, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x66, 0x72,
	0x65, 0x73, 0x68, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x72, 0x65,
	0x66, 0x72, 0x65, 0x73, 0x68, 0x49, 0x64, 0x12, 0x24, 0x0a, 0x0e, 0x63, 0x69, 0x72, 0x63, 0x6c,
	0x65, 0x5f, 0x63, 0x61, 0x6d, 0x70, 0x5f, 0x69, 0x64, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x0c, 0x63, 0x69, 0x72, 0x63, 0x6c, 0x65, 0x43, 0x61, 0x6d, 0x70, 0x49, 0x64, 0x12, 0x1a, 0x0a,
	0x08, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x08, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x65, 0x73, 0x73, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_BlossomScheduleInfo_proto_rawDescOnce sync.Once
	file_BlossomScheduleInfo_proto_rawDescData = file_BlossomScheduleInfo_proto_rawDesc
)

func file_BlossomScheduleInfo_proto_rawDescGZIP() []byte {
	file_BlossomScheduleInfo_proto_rawDescOnce.Do(func() {
		file_BlossomScheduleInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_BlossomScheduleInfo_proto_rawDescData)
	})
	return file_BlossomScheduleInfo_proto_rawDescData
}

var file_BlossomScheduleInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_BlossomScheduleInfo_proto_goTypes = []interface{}{
	(*BlossomScheduleInfo)(nil), // 0: BlossomScheduleInfo
}
var file_BlossomScheduleInfo_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_BlossomScheduleInfo_proto_init() }
func file_BlossomScheduleInfo_proto_init() {
	if File_BlossomScheduleInfo_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_BlossomScheduleInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BlossomScheduleInfo); i {
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
			RawDescriptor: file_BlossomScheduleInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_BlossomScheduleInfo_proto_goTypes,
		DependencyIndexes: file_BlossomScheduleInfo_proto_depIdxs,
		MessageInfos:      file_BlossomScheduleInfo_proto_msgTypes,
	}.Build()
	File_BlossomScheduleInfo_proto = out.File
	file_BlossomScheduleInfo_proto_rawDesc = nil
	file_BlossomScheduleInfo_proto_goTypes = nil
	file_BlossomScheduleInfo_proto_depIdxs = nil
}
