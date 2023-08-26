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
// source: GCGMsgAddDice.proto

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

// Obf: DIHCMOBJACH
type GCGMsgAddDice struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChangeCount  int32                      `protobuf:"varint,6,opt,name=change_count,json=changeCount,proto3" json:"change_count,omitempty"`
	Reason       GCGReason                  `protobuf:"varint,5,opt,name=reason,proto3,enum=GCGReason" json:"reason,omitempty"`
	ACBEOEAMOEF  map[uint32]GCGDiceSideType `protobuf:"bytes,3,rep,name=ACBEOEAMOEF,proto3" json:"ACBEOEAMOEF,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3,enum=GCGDiceSideType"`
	HLOGPOGEMKE  map[uint32]GCGDiceSideType `protobuf:"bytes,10,rep,name=HLOGPOGEMKE,proto3" json:"HLOGPOGEMKE,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3,enum=GCGDiceSideType"`
	ControllerId uint32                     `protobuf:"varint,7,opt,name=controller_id,json=controllerId,proto3" json:"controller_id,omitempty"`
}

func (x *GCGMsgAddDice) Reset() {
	*x = GCGMsgAddDice{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGMsgAddDice_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGMsgAddDice) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGMsgAddDice) ProtoMessage() {}

func (x *GCGMsgAddDice) ProtoReflect() protoreflect.Message {
	mi := &file_GCGMsgAddDice_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGMsgAddDice.ProtoReflect.Descriptor instead.
func (*GCGMsgAddDice) Descriptor() ([]byte, []int) {
	return file_GCGMsgAddDice_proto_rawDescGZIP(), []int{0}
}

func (x *GCGMsgAddDice) GetChangeCount() int32 {
	if x != nil {
		return x.ChangeCount
	}
	return 0
}

func (x *GCGMsgAddDice) GetReason() GCGReason {
	if x != nil {
		return x.Reason
	}
	return GCGReason_MNDCMMKBIBP_Default
}

func (x *GCGMsgAddDice) GetACBEOEAMOEF() map[uint32]GCGDiceSideType {
	if x != nil {
		return x.ACBEOEAMOEF
	}
	return nil
}

func (x *GCGMsgAddDice) GetHLOGPOGEMKE() map[uint32]GCGDiceSideType {
	if x != nil {
		return x.HLOGPOGEMKE
	}
	return nil
}

func (x *GCGMsgAddDice) GetControllerId() uint32 {
	if x != nil {
		return x.ControllerId
	}
	return 0
}

var File_GCGMsgAddDice_proto protoreflect.FileDescriptor

var file_GCGMsgAddDice_proto_rawDesc = []byte{
	0x0a, 0x13, 0x47, 0x43, 0x47, 0x4d, 0x73, 0x67, 0x41, 0x64, 0x64, 0x44, 0x69, 0x63, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x47, 0x43, 0x47, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x15, 0x47, 0x43, 0x47, 0x44, 0x69, 0x63, 0x65, 0x53,
	0x69, 0x64, 0x65, 0x54, 0x79, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa5, 0x03,
	0x0a, 0x0d, 0x47, 0x43, 0x47, 0x4d, 0x73, 0x67, 0x41, 0x64, 0x64, 0x44, 0x69, 0x63, 0x65, 0x12,
	0x21, 0x0a, 0x0c, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0b, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x43, 0x6f, 0x75,
	0x6e, 0x74, 0x12, 0x22, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x0a, 0x2e, 0x47, 0x43, 0x47, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x52, 0x06,
	0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x41, 0x0a, 0x0b, 0x41, 0x43, 0x42, 0x45, 0x4f, 0x45,
	0x41, 0x4d, 0x4f, 0x45, 0x46, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f, 0x2e, 0x47, 0x43,
	0x47, 0x4d, 0x73, 0x67, 0x41, 0x64, 0x64, 0x44, 0x69, 0x63, 0x65, 0x2e, 0x41, 0x43, 0x42, 0x45,
	0x4f, 0x45, 0x41, 0x4d, 0x4f, 0x45, 0x46, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0b, 0x41, 0x43,
	0x42, 0x45, 0x4f, 0x45, 0x41, 0x4d, 0x4f, 0x45, 0x46, 0x12, 0x41, 0x0a, 0x0b, 0x48, 0x4c, 0x4f,
	0x47, 0x50, 0x4f, 0x47, 0x45, 0x4d, 0x4b, 0x45, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1f,
	0x2e, 0x47, 0x43, 0x47, 0x4d, 0x73, 0x67, 0x41, 0x64, 0x64, 0x44, 0x69, 0x63, 0x65, 0x2e, 0x48,
	0x4c, 0x4f, 0x47, 0x50, 0x4f, 0x47, 0x45, 0x4d, 0x4b, 0x45, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52,
	0x0b, 0x48, 0x4c, 0x4f, 0x47, 0x50, 0x4f, 0x47, 0x45, 0x4d, 0x4b, 0x45, 0x12, 0x23, 0x0a, 0x0d,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x49,
	0x64, 0x1a, 0x50, 0x0a, 0x10, 0x41, 0x43, 0x42, 0x45, 0x4f, 0x45, 0x41, 0x4d, 0x4f, 0x45, 0x46,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x26, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x10, 0x2e, 0x47, 0x43, 0x47, 0x44, 0x69, 0x63, 0x65,
	0x53, 0x69, 0x64, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a,
	0x02, 0x38, 0x01, 0x1a, 0x50, 0x0a, 0x10, 0x48, 0x4c, 0x4f, 0x47, 0x50, 0x4f, 0x47, 0x45, 0x4d,
	0x4b, 0x45, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x26, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x10, 0x2e, 0x47, 0x43, 0x47, 0x44, 0x69,
	0x63, 0x65, 0x53, 0x69, 0x64, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGMsgAddDice_proto_rawDescOnce sync.Once
	file_GCGMsgAddDice_proto_rawDescData = file_GCGMsgAddDice_proto_rawDesc
)

func file_GCGMsgAddDice_proto_rawDescGZIP() []byte {
	file_GCGMsgAddDice_proto_rawDescOnce.Do(func() {
		file_GCGMsgAddDice_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGMsgAddDice_proto_rawDescData)
	})
	return file_GCGMsgAddDice_proto_rawDescData
}

var file_GCGMsgAddDice_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_GCGMsgAddDice_proto_goTypes = []interface{}{
	(*GCGMsgAddDice)(nil), // 0: GCGMsgAddDice
	nil,                   // 1: GCGMsgAddDice.ACBEOEAMOEFEntry
	nil,                   // 2: GCGMsgAddDice.HLOGPOGEMKEEntry
	(GCGReason)(0),        // 3: GCGReason
	(GCGDiceSideType)(0),  // 4: GCGDiceSideType
}
var file_GCGMsgAddDice_proto_depIdxs = []int32{
	3, // 0: GCGMsgAddDice.reason:type_name -> GCGReason
	1, // 1: GCGMsgAddDice.ACBEOEAMOEF:type_name -> GCGMsgAddDice.ACBEOEAMOEFEntry
	2, // 2: GCGMsgAddDice.HLOGPOGEMKE:type_name -> GCGMsgAddDice.HLOGPOGEMKEEntry
	4, // 3: GCGMsgAddDice.ACBEOEAMOEFEntry.value:type_name -> GCGDiceSideType
	4, // 4: GCGMsgAddDice.HLOGPOGEMKEEntry.value:type_name -> GCGDiceSideType
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_GCGMsgAddDice_proto_init() }
func file_GCGMsgAddDice_proto_init() {
	if File_GCGMsgAddDice_proto != nil {
		return
	}
	file_GCGReason_proto_init()
	file_GCGDiceSideType_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GCGMsgAddDice_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGMsgAddDice); i {
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
			RawDescriptor: file_GCGMsgAddDice_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGMsgAddDice_proto_goTypes,
		DependencyIndexes: file_GCGMsgAddDice_proto_depIdxs,
		MessageInfos:      file_GCGMsgAddDice_proto_msgTypes,
	}.Build()
	File_GCGMsgAddDice_proto = out.File
	file_GCGMsgAddDice_proto_rawDesc = nil
	file_GCGMsgAddDice_proto_goTypes = nil
	file_GCGMsgAddDice_proto_depIdxs = nil
}
