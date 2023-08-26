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
// source: ENHHFCIOJNJ.proto

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

type ENHHFCIOJNJ struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JILFLMPJMFP bool         `protobuf:"varint,8,opt,name=JILFLMPJMFP,proto3" json:"JILFLMPJMFP,omitempty"`
	BasicInfo   *HPGMMJOIFNE `protobuf:"bytes,6,opt,name=basic_info,json=basicInfo,proto3" json:"basic_info,omitempty"`
	DHKCIBJCOLD uint32       `protobuf:"varint,5,opt,name=DHKCIBJCOLD,proto3" json:"DHKCIBJCOLD,omitempty"`
	MBPHHDHHCEG bool         `protobuf:"varint,14,opt,name=MBPHHDHHCEG,proto3" json:"MBPHHDHHCEG,omitempty"`
	GMMMLOGKFGO bool         `protobuf:"varint,1,opt,name=GMMMLOGKFGO,proto3" json:"GMMMLOGKFGO,omitempty"`
	CKMLJPELCAE []uint32     `protobuf:"varint,12,rep,packed,name=CKMLJPELCAE,proto3" json:"CKMLJPELCAE,omitempty"`
}

func (x *ENHHFCIOJNJ) Reset() {
	*x = ENHHFCIOJNJ{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ENHHFCIOJNJ_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ENHHFCIOJNJ) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ENHHFCIOJNJ) ProtoMessage() {}

func (x *ENHHFCIOJNJ) ProtoReflect() protoreflect.Message {
	mi := &file_ENHHFCIOJNJ_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ENHHFCIOJNJ.ProtoReflect.Descriptor instead.
func (*ENHHFCIOJNJ) Descriptor() ([]byte, []int) {
	return file_ENHHFCIOJNJ_proto_rawDescGZIP(), []int{0}
}

func (x *ENHHFCIOJNJ) GetJILFLMPJMFP() bool {
	if x != nil {
		return x.JILFLMPJMFP
	}
	return false
}

func (x *ENHHFCIOJNJ) GetBasicInfo() *HPGMMJOIFNE {
	if x != nil {
		return x.BasicInfo
	}
	return nil
}

func (x *ENHHFCIOJNJ) GetDHKCIBJCOLD() uint32 {
	if x != nil {
		return x.DHKCIBJCOLD
	}
	return 0
}

func (x *ENHHFCIOJNJ) GetMBPHHDHHCEG() bool {
	if x != nil {
		return x.MBPHHDHHCEG
	}
	return false
}

func (x *ENHHFCIOJNJ) GetGMMMLOGKFGO() bool {
	if x != nil {
		return x.GMMMLOGKFGO
	}
	return false
}

func (x *ENHHFCIOJNJ) GetCKMLJPELCAE() []uint32 {
	if x != nil {
		return x.CKMLJPELCAE
	}
	return nil
}

var File_ENHHFCIOJNJ_proto protoreflect.FileDescriptor

var file_ENHHFCIOJNJ_proto_rawDesc = []byte{
	0x0a, 0x11, 0x45, 0x4e, 0x48, 0x48, 0x46, 0x43, 0x49, 0x4f, 0x4a, 0x4e, 0x4a, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x48, 0x50, 0x47, 0x4d, 0x4d, 0x4a, 0x4f, 0x49, 0x46, 0x4e, 0x45,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe4, 0x01, 0x0a, 0x0b, 0x45, 0x4e, 0x48, 0x48, 0x46,
	0x43, 0x49, 0x4f, 0x4a, 0x4e, 0x4a, 0x12, 0x20, 0x0a, 0x0b, 0x4a, 0x49, 0x4c, 0x46, 0x4c, 0x4d,
	0x50, 0x4a, 0x4d, 0x46, 0x50, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x4a, 0x49, 0x4c,
	0x46, 0x4c, 0x4d, 0x50, 0x4a, 0x4d, 0x46, 0x50, 0x12, 0x2b, 0x0a, 0x0a, 0x62, 0x61, 0x73, 0x69,
	0x63, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x48,
	0x50, 0x47, 0x4d, 0x4d, 0x4a, 0x4f, 0x49, 0x46, 0x4e, 0x45, 0x52, 0x09, 0x62, 0x61, 0x73, 0x69,
	0x63, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x20, 0x0a, 0x0b, 0x44, 0x48, 0x4b, 0x43, 0x49, 0x42, 0x4a,
	0x43, 0x4f, 0x4c, 0x44, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x44, 0x48, 0x4b, 0x43,
	0x49, 0x42, 0x4a, 0x43, 0x4f, 0x4c, 0x44, 0x12, 0x20, 0x0a, 0x0b, 0x4d, 0x42, 0x50, 0x48, 0x48,
	0x44, 0x48, 0x48, 0x43, 0x45, 0x47, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x4d, 0x42,
	0x50, 0x48, 0x48, 0x44, 0x48, 0x48, 0x43, 0x45, 0x47, 0x12, 0x20, 0x0a, 0x0b, 0x47, 0x4d, 0x4d,
	0x4d, 0x4c, 0x4f, 0x47, 0x4b, 0x46, 0x47, 0x4f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b,
	0x47, 0x4d, 0x4d, 0x4d, 0x4c, 0x4f, 0x47, 0x4b, 0x46, 0x47, 0x4f, 0x12, 0x20, 0x0a, 0x0b, 0x43,
	0x4b, 0x4d, 0x4c, 0x4a, 0x50, 0x45, 0x4c, 0x43, 0x41, 0x45, 0x18, 0x0c, 0x20, 0x03, 0x28, 0x0d,
	0x52, 0x0b, 0x43, 0x4b, 0x4d, 0x4c, 0x4a, 0x50, 0x45, 0x4c, 0x43, 0x41, 0x45, 0x42, 0x06, 0x5a,
	0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ENHHFCIOJNJ_proto_rawDescOnce sync.Once
	file_ENHHFCIOJNJ_proto_rawDescData = file_ENHHFCIOJNJ_proto_rawDesc
)

func file_ENHHFCIOJNJ_proto_rawDescGZIP() []byte {
	file_ENHHFCIOJNJ_proto_rawDescOnce.Do(func() {
		file_ENHHFCIOJNJ_proto_rawDescData = protoimpl.X.CompressGZIP(file_ENHHFCIOJNJ_proto_rawDescData)
	})
	return file_ENHHFCIOJNJ_proto_rawDescData
}

var file_ENHHFCIOJNJ_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_ENHHFCIOJNJ_proto_goTypes = []interface{}{
	(*ENHHFCIOJNJ)(nil), // 0: ENHHFCIOJNJ
	(*HPGMMJOIFNE)(nil), // 1: HPGMMJOIFNE
}
var file_ENHHFCIOJNJ_proto_depIdxs = []int32{
	1, // 0: ENHHFCIOJNJ.basic_info:type_name -> HPGMMJOIFNE
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_ENHHFCIOJNJ_proto_init() }
func file_ENHHFCIOJNJ_proto_init() {
	if File_ENHHFCIOJNJ_proto != nil {
		return
	}
	file_HPGMMJOIFNE_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ENHHFCIOJNJ_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ENHHFCIOJNJ); i {
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
			RawDescriptor: file_ENHHFCIOJNJ_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ENHHFCIOJNJ_proto_goTypes,
		DependencyIndexes: file_ENHHFCIOJNJ_proto_depIdxs,
		MessageInfos:      file_ENHHFCIOJNJ_proto_msgTypes,
	}.Build()
	File_ENHHFCIOJNJ_proto = out.File
	file_ENHHFCIOJNJ_proto_rawDesc = nil
	file_ENHHFCIOJNJ_proto_goTypes = nil
	file_ENHHFCIOJNJ_proto_depIdxs = nil
}
