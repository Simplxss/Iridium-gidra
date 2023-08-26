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
// source: EntityFightPropChangeReasonNotify.proto

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

// CmdId: 2489
// Obf: KHFJILELHPL
type EntityFightPropChangeReasonNotify struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChangeHpReason     ChangeHpReason     `protobuf:"varint,12,opt,name=changeHpReason,proto3,enum=ChangeHpReason" json:"changeHpReason,omitempty"`
	EntityId           uint32             `protobuf:"varint,6,opt,name=entity_id,json=entityId,proto3" json:"entity_id,omitempty"`
	PropType           uint32             `protobuf:"varint,1,opt,name=prop_type,json=propType,proto3" json:"prop_type,omitempty"`
	PropDelta          float32            `protobuf:"fixed32,10,opt,name=prop_delta,json=propDelta,proto3" json:"prop_delta,omitempty"`
	ChangeEnergyReason ChangeEnergyReason `protobuf:"varint,8,opt,name=changeEnergyReason,proto3,enum=ChangeEnergyReason" json:"changeEnergyReason,omitempty"`
	DetailInfo         *FAFPLBDIGDH       `protobuf:"bytes,11,opt,name=detail_info,json=detailInfo,proto3" json:"detail_info,omitempty"`
	ParamList          []uint32           `protobuf:"varint,9,rep,packed,name=param_list,json=paramList,proto3" json:"param_list,omitempty"`
	AEFJJGCHIJH        OFDEHFOCIFP        `protobuf:"varint,14,opt,name=AEFJJGCHIJH,proto3,enum=OFDEHFOCIFP" json:"AEFJJGCHIJH,omitempty"`
	Reason             PropChangeReason   `protobuf:"varint,3,opt,name=reason,proto3,enum=PropChangeReason" json:"reason,omitempty"`
	JJEEABMPEKL        float32            `protobuf:"fixed32,13,opt,name=JJEEABMPEKL,proto3" json:"JJEEABMPEKL,omitempty"`
}

func (x *EntityFightPropChangeReasonNotify) Reset() {
	*x = EntityFightPropChangeReasonNotify{}
	if protoimpl.UnsafeEnabled {
		mi := &file_EntityFightPropChangeReasonNotify_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EntityFightPropChangeReasonNotify) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EntityFightPropChangeReasonNotify) ProtoMessage() {}

func (x *EntityFightPropChangeReasonNotify) ProtoReflect() protoreflect.Message {
	mi := &file_EntityFightPropChangeReasonNotify_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EntityFightPropChangeReasonNotify.ProtoReflect.Descriptor instead.
func (*EntityFightPropChangeReasonNotify) Descriptor() ([]byte, []int) {
	return file_EntityFightPropChangeReasonNotify_proto_rawDescGZIP(), []int{0}
}

func (x *EntityFightPropChangeReasonNotify) GetChangeHpReason() ChangeHpReason {
	if x != nil {
		return x.ChangeHpReason
	}
	return ChangeHpReason_CHANGE_HP_REASON_NONE
}

func (x *EntityFightPropChangeReasonNotify) GetEntityId() uint32 {
	if x != nil {
		return x.EntityId
	}
	return 0
}

func (x *EntityFightPropChangeReasonNotify) GetPropType() uint32 {
	if x != nil {
		return x.PropType
	}
	return 0
}

func (x *EntityFightPropChangeReasonNotify) GetPropDelta() float32 {
	if x != nil {
		return x.PropDelta
	}
	return 0
}

func (x *EntityFightPropChangeReasonNotify) GetChangeEnergyReason() ChangeEnergyReason {
	if x != nil {
		return x.ChangeEnergyReason
	}
	return ChangeEnergyReason_CHANGE_ENERGY_REASON_NONE
}

func (x *EntityFightPropChangeReasonNotify) GetDetailInfo() *FAFPLBDIGDH {
	if x != nil {
		return x.DetailInfo
	}
	return nil
}

func (x *EntityFightPropChangeReasonNotify) GetParamList() []uint32 {
	if x != nil {
		return x.ParamList
	}
	return nil
}

func (x *EntityFightPropChangeReasonNotify) GetAEFJJGCHIJH() OFDEHFOCIFP {
	if x != nil {
		return x.AEFJJGCHIJH
	}
	return OFDEHFOCIFP_OFDEHFOCIFP_ChangeHpDebtsNone
}

func (x *EntityFightPropChangeReasonNotify) GetReason() PropChangeReason {
	if x != nil {
		return x.Reason
	}
	return PropChangeReason_PROP_CHANGE_REASON_NONE
}

func (x *EntityFightPropChangeReasonNotify) GetJJEEABMPEKL() float32 {
	if x != nil {
		return x.JJEEABMPEKL
	}
	return 0
}

var File_EntityFightPropChangeReasonNotify_proto protoreflect.FileDescriptor

var file_EntityFightPropChangeReasonNotify_proto_rawDesc = []byte{
	0x0a, 0x27, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x46, 0x69, 0x67, 0x68, 0x74, 0x50, 0x72, 0x6f,
	0x70, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x4e, 0x6f, 0x74,
	0x69, 0x66, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x43, 0x68, 0x61, 0x6e, 0x67,
	0x65, 0x48, 0x70, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x18, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x45, 0x6e, 0x65, 0x72, 0x67, 0x79, 0x52, 0x65, 0x61,
	0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x46, 0x41, 0x46, 0x50, 0x4c,
	0x42, 0x44, 0x49, 0x47, 0x44, 0x48, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x4f, 0x46,
	0x44, 0x45, 0x48, 0x46, 0x4f, 0x43, 0x49, 0x46, 0x50, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x16, 0x50, 0x72, 0x6f, 0x70, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x52, 0x65, 0x61, 0x73, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc5, 0x03, 0x0a, 0x21, 0x45, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x46, 0x69, 0x67, 0x68, 0x74, 0x50, 0x72, 0x6f, 0x70, 0x43, 0x68, 0x61, 0x6e, 0x67,
	0x65, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x12, 0x37, 0x0a,
	0x0e, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x48, 0x70, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18,
	0x0c, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0f, 0x2e, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x48, 0x70,
	0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x52, 0x0e, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x48, 0x70,
	0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x72, 0x6f, 0x70, 0x5f, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x70, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x6f, 0x70, 0x5f, 0x64, 0x65, 0x6c, 0x74, 0x61, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x02, 0x52, 0x09, 0x70, 0x72, 0x6f, 0x70, 0x44, 0x65, 0x6c, 0x74, 0x61, 0x12,
	0x43, 0x0a, 0x12, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x45, 0x6e, 0x65, 0x72, 0x67, 0x79, 0x52,
	0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x13, 0x2e, 0x43, 0x68,
	0x61, 0x6e, 0x67, 0x65, 0x45, 0x6e, 0x65, 0x72, 0x67, 0x79, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e,
	0x52, 0x12, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x45, 0x6e, 0x65, 0x72, 0x67, 0x79, 0x52, 0x65,
	0x61, 0x73, 0x6f, 0x6e, 0x12, 0x2d, 0x0a, 0x0b, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x5f, 0x69,
	0x6e, 0x66, 0x6f, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e, 0x46, 0x41, 0x46, 0x50,
	0x4c, 0x42, 0x44, 0x49, 0x47, 0x44, 0x48, 0x52, 0x0a, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x49,
	0x6e, 0x66, 0x6f, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x4c, 0x69,
	0x73, 0x74, 0x12, 0x2e, 0x0a, 0x0b, 0x41, 0x45, 0x46, 0x4a, 0x4a, 0x47, 0x43, 0x48, 0x49, 0x4a,
	0x48, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x0c, 0x2e, 0x4f, 0x46, 0x44, 0x45, 0x48, 0x46,
	0x4f, 0x43, 0x49, 0x46, 0x50, 0x52, 0x0b, 0x41, 0x45, 0x46, 0x4a, 0x4a, 0x47, 0x43, 0x48, 0x49,
	0x4a, 0x48, 0x12, 0x29, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x11, 0x2e, 0x50, 0x72, 0x6f, 0x70, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x52,
	0x65, 0x61, 0x73, 0x6f, 0x6e, 0x52, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x20, 0x0a,
	0x0b, 0x4a, 0x4a, 0x45, 0x45, 0x41, 0x42, 0x4d, 0x50, 0x45, 0x4b, 0x4c, 0x18, 0x0d, 0x20, 0x01,
	0x28, 0x02, 0x52, 0x0b, 0x4a, 0x4a, 0x45, 0x45, 0x41, 0x42, 0x4d, 0x50, 0x45, 0x4b, 0x4c, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_EntityFightPropChangeReasonNotify_proto_rawDescOnce sync.Once
	file_EntityFightPropChangeReasonNotify_proto_rawDescData = file_EntityFightPropChangeReasonNotify_proto_rawDesc
)

func file_EntityFightPropChangeReasonNotify_proto_rawDescGZIP() []byte {
	file_EntityFightPropChangeReasonNotify_proto_rawDescOnce.Do(func() {
		file_EntityFightPropChangeReasonNotify_proto_rawDescData = protoimpl.X.CompressGZIP(file_EntityFightPropChangeReasonNotify_proto_rawDescData)
	})
	return file_EntityFightPropChangeReasonNotify_proto_rawDescData
}

var file_EntityFightPropChangeReasonNotify_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_EntityFightPropChangeReasonNotify_proto_goTypes = []interface{}{
	(*EntityFightPropChangeReasonNotify)(nil), // 0: EntityFightPropChangeReasonNotify
	(ChangeHpReason)(0),                       // 1: ChangeHpReason
	(ChangeEnergyReason)(0),                   // 2: ChangeEnergyReason
	(*FAFPLBDIGDH)(nil),                       // 3: FAFPLBDIGDH
	(OFDEHFOCIFP)(0),                          // 4: OFDEHFOCIFP
	(PropChangeReason)(0),                     // 5: PropChangeReason
}
var file_EntityFightPropChangeReasonNotify_proto_depIdxs = []int32{
	1, // 0: EntityFightPropChangeReasonNotify.changeHpReason:type_name -> ChangeHpReason
	2, // 1: EntityFightPropChangeReasonNotify.changeEnergyReason:type_name -> ChangeEnergyReason
	3, // 2: EntityFightPropChangeReasonNotify.detail_info:type_name -> FAFPLBDIGDH
	4, // 3: EntityFightPropChangeReasonNotify.AEFJJGCHIJH:type_name -> OFDEHFOCIFP
	5, // 4: EntityFightPropChangeReasonNotify.reason:type_name -> PropChangeReason
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_EntityFightPropChangeReasonNotify_proto_init() }
func file_EntityFightPropChangeReasonNotify_proto_init() {
	if File_EntityFightPropChangeReasonNotify_proto != nil {
		return
	}
	file_ChangeHpReason_proto_init()
	file_ChangeEnergyReason_proto_init()
	file_FAFPLBDIGDH_proto_init()
	file_OFDEHFOCIFP_proto_init()
	file_PropChangeReason_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_EntityFightPropChangeReasonNotify_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EntityFightPropChangeReasonNotify); i {
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
			RawDescriptor: file_EntityFightPropChangeReasonNotify_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_EntityFightPropChangeReasonNotify_proto_goTypes,
		DependencyIndexes: file_EntityFightPropChangeReasonNotify_proto_depIdxs,
		MessageInfos:      file_EntityFightPropChangeReasonNotify_proto_msgTypes,
	}.Build()
	File_EntityFightPropChangeReasonNotify_proto = out.File
	file_EntityFightPropChangeReasonNotify_proto_rawDesc = nil
	file_EntityFightPropChangeReasonNotify_proto_goTypes = nil
	file_EntityFightPropChangeReasonNotify_proto_depIdxs = nil
}
