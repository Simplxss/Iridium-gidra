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
// source: BartenderActivityDetailInfo.proto

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

type BartenderActivityDetailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsContentClosed     bool                  `protobuf:"varint,15,opt,name=is_content_closed,json=isContentClosed,proto3" json:"is_content_closed,omitempty"`
	UnlockLevelList     []*BartenderLevelInfo `protobuf:"bytes,10,rep,name=unlock_level_list,json=unlockLevelList,proto3" json:"unlock_level_list,omitempty"`
	UnlockItemList      []uint32              `protobuf:"varint,3,rep,packed,name=unlock_item_list,json=unlockItemList,proto3" json:"unlock_item_list,omitempty"`
	UnlockFormulaList   []uint32              `protobuf:"varint,6,rep,packed,name=unlock_formula_list,json=unlockFormulaList,proto3" json:"unlock_formula_list,omitempty"`
	UnlockTaskList      []*BartenderTaskInfo  `protobuf:"bytes,5,rep,name=unlock_task_list,json=unlockTaskList,proto3" json:"unlock_task_list,omitempty"`
	IsDevelopModuleOpen bool                  `protobuf:"varint,9,opt,name=is_develop_module_open,json=isDevelopModuleOpen,proto3" json:"is_develop_module_open,omitempty"`
}

func (x *BartenderActivityDetailInfo) Reset() {
	*x = BartenderActivityDetailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_BartenderActivityDetailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BartenderActivityDetailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BartenderActivityDetailInfo) ProtoMessage() {}

func (x *BartenderActivityDetailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_BartenderActivityDetailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BartenderActivityDetailInfo.ProtoReflect.Descriptor instead.
func (*BartenderActivityDetailInfo) Descriptor() ([]byte, []int) {
	return file_BartenderActivityDetailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *BartenderActivityDetailInfo) GetIsContentClosed() bool {
	if x != nil {
		return x.IsContentClosed
	}
	return false
}

func (x *BartenderActivityDetailInfo) GetUnlockLevelList() []*BartenderLevelInfo {
	if x != nil {
		return x.UnlockLevelList
	}
	return nil
}

func (x *BartenderActivityDetailInfo) GetUnlockItemList() []uint32 {
	if x != nil {
		return x.UnlockItemList
	}
	return nil
}

func (x *BartenderActivityDetailInfo) GetUnlockFormulaList() []uint32 {
	if x != nil {
		return x.UnlockFormulaList
	}
	return nil
}

func (x *BartenderActivityDetailInfo) GetUnlockTaskList() []*BartenderTaskInfo {
	if x != nil {
		return x.UnlockTaskList
	}
	return nil
}

func (x *BartenderActivityDetailInfo) GetIsDevelopModuleOpen() bool {
	if x != nil {
		return x.IsDevelopModuleOpen
	}
	return false
}

var File_BartenderActivityDetailInfo_proto protoreflect.FileDescriptor

var file_BartenderActivityDetailInfo_proto_rawDesc = []byte{
	0x0a, 0x21, 0x42, 0x61, 0x72, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x41, 0x63, 0x74, 0x69, 0x76,
	0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x42, 0x61, 0x72, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x4c, 0x65,
	0x76, 0x65, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x42,
	0x61, 0x72, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x49, 0x6e, 0x66, 0x6f,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd7, 0x02, 0x0a, 0x1b, 0x42, 0x61, 0x72, 0x74, 0x65,
	0x6e, 0x64, 0x65, 0x72, 0x41, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79, 0x44, 0x65, 0x74, 0x61,
	0x69, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2a, 0x0a, 0x11, 0x69, 0x73, 0x5f, 0x63, 0x6f, 0x6e,
	0x74, 0x65, 0x6e, 0x74, 0x5f, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x18, 0x0f, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x0f, 0x69, 0x73, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x43, 0x6c, 0x6f, 0x73,
	0x65, 0x64, 0x12, 0x3f, 0x0a, 0x11, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e,
	0x42, 0x61, 0x72, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x49, 0x6e,
	0x66, 0x6f, 0x52, 0x0f, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x4c,
	0x69, 0x73, 0x74, 0x12, 0x28, 0x0a, 0x10, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x69, 0x74,
	0x65, 0x6d, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0e, 0x75,
	0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x74, 0x65, 0x6d, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x2e, 0x0a,
	0x13, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x75, 0x6c, 0x61, 0x5f,
	0x6c, 0x69, 0x73, 0x74, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x11, 0x75, 0x6e, 0x6c, 0x6f,
	0x63, 0x6b, 0x46, 0x6f, 0x72, 0x6d, 0x75, 0x6c, 0x61, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x3c, 0x0a,
	0x10, 0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x74, 0x61, 0x73, 0x6b, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x42, 0x61, 0x72, 0x74, 0x65, 0x6e,
	0x64, 0x65, 0x72, 0x54, 0x61, 0x73, 0x6b, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0e, 0x75, 0x6e, 0x6c,
	0x6f, 0x63, 0x6b, 0x54, 0x61, 0x73, 0x6b, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x33, 0x0a, 0x16, 0x69,
	0x73, 0x5f, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x5f, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65,
	0x5f, 0x6f, 0x70, 0x65, 0x6e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x69, 0x73, 0x44,
	0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x4f, 0x70, 0x65, 0x6e,
	0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_BartenderActivityDetailInfo_proto_rawDescOnce sync.Once
	file_BartenderActivityDetailInfo_proto_rawDescData = file_BartenderActivityDetailInfo_proto_rawDesc
)

func file_BartenderActivityDetailInfo_proto_rawDescGZIP() []byte {
	file_BartenderActivityDetailInfo_proto_rawDescOnce.Do(func() {
		file_BartenderActivityDetailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_BartenderActivityDetailInfo_proto_rawDescData)
	})
	return file_BartenderActivityDetailInfo_proto_rawDescData
}

var file_BartenderActivityDetailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_BartenderActivityDetailInfo_proto_goTypes = []interface{}{
	(*BartenderActivityDetailInfo)(nil), // 0: BartenderActivityDetailInfo
	(*BartenderLevelInfo)(nil),          // 1: BartenderLevelInfo
	(*BartenderTaskInfo)(nil),           // 2: BartenderTaskInfo
}
var file_BartenderActivityDetailInfo_proto_depIdxs = []int32{
	1, // 0: BartenderActivityDetailInfo.unlock_level_list:type_name -> BartenderLevelInfo
	2, // 1: BartenderActivityDetailInfo.unlock_task_list:type_name -> BartenderTaskInfo
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_BartenderActivityDetailInfo_proto_init() }
func file_BartenderActivityDetailInfo_proto_init() {
	if File_BartenderActivityDetailInfo_proto != nil {
		return
	}
	file_BartenderLevelInfo_proto_init()
	file_BartenderTaskInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_BartenderActivityDetailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BartenderActivityDetailInfo); i {
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
			RawDescriptor: file_BartenderActivityDetailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_BartenderActivityDetailInfo_proto_goTypes,
		DependencyIndexes: file_BartenderActivityDetailInfo_proto_depIdxs,
		MessageInfos:      file_BartenderActivityDetailInfo_proto_msgTypes,
	}.Build()
	File_BartenderActivityDetailInfo_proto = out.File
	file_BartenderActivityDetailInfo_proto_rawDesc = nil
	file_BartenderActivityDetailInfo_proto_goTypes = nil
	file_BartenderActivityDetailInfo_proto_depIdxs = nil
}
