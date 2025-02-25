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
// source: BreakoutPhysicalObject.proto

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

// Obf: NFMHCAILCIF
type BreakoutPhysicalObject struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id                  uint32                            `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Index               uint32                            `protobuf:"varint,2,opt,name=index,proto3" json:"index,omitempty"`
	IsActive            bool                              `protobuf:"varint,3,opt,name=is_active,json=isActive,proto3" json:"is_active,omitempty"`
	Pos                 *BreakoutVector2                  `protobuf:"bytes,4,opt,name=pos,proto3" json:"pos,omitempty"`
	MoveDir             *BreakoutVector2                  `protobuf:"bytes,5,opt,name=move_dir,json=moveDir,proto3" json:"move_dir,omitempty"`
	Speed               int32                             `protobuf:"varint,6,opt,name=speed,proto3" json:"speed,omitempty"`
	InitPeerId          uint32                            `protobuf:"varint,7,opt,name=init_peer_id,json=initPeerId,proto3" json:"init_peer_id,omitempty"`
	State               uint32                            `protobuf:"varint,8,opt,name=state,proto3" json:"state,omitempty"`
	ElementType         uint32                            `protobuf:"varint,9,opt,name=element_type,json=elementType,proto3" json:"element_type,omitempty"`
	ElementReactionBuff uint32                            `protobuf:"varint,10,opt,name=element_reaction_buff,json=elementReactionBuff,proto3" json:"element_reaction_buff,omitempty"`
	ModifierList        []*BreakoutPhysicalObjectModifier `protobuf:"bytes,11,rep,name=modifier_list,json=modifierList,proto3" json:"modifier_list,omitempty"`
	TotalRotation       int32                             `protobuf:"varint,12,opt,name=total_rotation,json=totalRotation,proto3" json:"total_rotation,omitempty"`
	InfoList            []*BreakoutBrickInfo              `protobuf:"bytes,13,rep,name=info_list,json=infoList,proto3" json:"info_list,omitempty"`
	LastHitPeerId       uint32                            `protobuf:"varint,14,opt,name=last_hit_peer_id,json=lastHitPeerId,proto3" json:"last_hit_peer_id,omitempty"`
	SpeedIncreaseCount  uint32                            `protobuf:"varint,15,opt,name=speed_increase_count,json=speedIncreaseCount,proto3" json:"speed_increase_count,omitempty"`
	Offset              int32                             `protobuf:"varint,16,opt,name=offset,proto3" json:"offset,omitempty"`
}

func (x *BreakoutPhysicalObject) Reset() {
	*x = BreakoutPhysicalObject{}
	if protoimpl.UnsafeEnabled {
		mi := &file_BreakoutPhysicalObject_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BreakoutPhysicalObject) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BreakoutPhysicalObject) ProtoMessage() {}

func (x *BreakoutPhysicalObject) ProtoReflect() protoreflect.Message {
	mi := &file_BreakoutPhysicalObject_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BreakoutPhysicalObject.ProtoReflect.Descriptor instead.
func (*BreakoutPhysicalObject) Descriptor() ([]byte, []int) {
	return file_BreakoutPhysicalObject_proto_rawDescGZIP(), []int{0}
}

func (x *BreakoutPhysicalObject) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetIsActive() bool {
	if x != nil {
		return x.IsActive
	}
	return false
}

func (x *BreakoutPhysicalObject) GetPos() *BreakoutVector2 {
	if x != nil {
		return x.Pos
	}
	return nil
}

func (x *BreakoutPhysicalObject) GetMoveDir() *BreakoutVector2 {
	if x != nil {
		return x.MoveDir
	}
	return nil
}

func (x *BreakoutPhysicalObject) GetSpeed() int32 {
	if x != nil {
		return x.Speed
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetInitPeerId() uint32 {
	if x != nil {
		return x.InitPeerId
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetState() uint32 {
	if x != nil {
		return x.State
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetElementType() uint32 {
	if x != nil {
		return x.ElementType
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetElementReactionBuff() uint32 {
	if x != nil {
		return x.ElementReactionBuff
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetModifierList() []*BreakoutPhysicalObjectModifier {
	if x != nil {
		return x.ModifierList
	}
	return nil
}

func (x *BreakoutPhysicalObject) GetTotalRotation() int32 {
	if x != nil {
		return x.TotalRotation
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetInfoList() []*BreakoutBrickInfo {
	if x != nil {
		return x.InfoList
	}
	return nil
}

func (x *BreakoutPhysicalObject) GetLastHitPeerId() uint32 {
	if x != nil {
		return x.LastHitPeerId
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetSpeedIncreaseCount() uint32 {
	if x != nil {
		return x.SpeedIncreaseCount
	}
	return 0
}

func (x *BreakoutPhysicalObject) GetOffset() int32 {
	if x != nil {
		return x.Offset
	}
	return 0
}

var File_BreakoutPhysicalObject_proto protoreflect.FileDescriptor

var file_BreakoutPhysicalObject_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x42, 0x72, 0x65, 0x61, 0x6b, 0x6f, 0x75, 0x74, 0x50, 0x68, 0x79, 0x73, 0x69, 0x63,
	0x61, 0x6c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x15,
	0x42, 0x72, 0x65, 0x61, 0x6b, 0x6f, 0x75, 0x74, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x32, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x24, 0x42, 0x72, 0x65, 0x61, 0x6b, 0x6f, 0x75, 0x74, 0x50,
	0x68, 0x79, 0x73, 0x69, 0x63, 0x61, 0x6c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x6f, 0x64,
	0x69, 0x66, 0x69, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x42, 0x72, 0x65,
	0x61, 0x6b, 0x6f, 0x75, 0x74, 0x42, 0x72, 0x69, 0x63, 0x6b, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe2, 0x04, 0x0a, 0x16, 0x42, 0x72, 0x65, 0x61, 0x6b, 0x6f, 0x75,
	0x74, 0x50, 0x68, 0x79, 0x73, 0x69, 0x63, 0x61, 0x6c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x12,
	0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12,
	0x14, 0x0a, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05,
	0x69, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x73, 0x5f, 0x61, 0x63, 0x74, 0x69,
	0x76, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x69, 0x73, 0x41, 0x63, 0x74, 0x69,
	0x76, 0x65, 0x12, 0x22, 0x0a, 0x03, 0x70, 0x6f, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x10, 0x2e, 0x42, 0x72, 0x65, 0x61, 0x6b, 0x6f, 0x75, 0x74, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72,
	0x32, 0x52, 0x03, 0x70, 0x6f, 0x73, 0x12, 0x2b, 0x0a, 0x08, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x64,
	0x69, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x42, 0x72, 0x65, 0x61, 0x6b,
	0x6f, 0x75, 0x74, 0x56, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x32, 0x52, 0x07, 0x6d, 0x6f, 0x76, 0x65,
	0x44, 0x69, 0x72, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x70, 0x65, 0x65, 0x64, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x05, 0x52, 0x05, 0x73, 0x70, 0x65, 0x65, 0x64, 0x12, 0x20, 0x0a, 0x0c, 0x69, 0x6e, 0x69,
	0x74, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x0a, 0x69, 0x6e, 0x69, 0x74, 0x50, 0x65, 0x65, 0x72, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x73,
	0x74, 0x61, 0x74, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74,
	0x65, 0x12, 0x21, 0x0a, 0x0c, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74,
	0x54, 0x79, 0x70, 0x65, 0x12, 0x32, 0x0a, 0x15, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x5f,
	0x72, 0x65, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x62, 0x75, 0x66, 0x66, 0x18, 0x0a, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x13, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x61, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x12, 0x44, 0x0a, 0x0d, 0x6d, 0x6f, 0x64, 0x69,
	0x66, 0x69, 0x65, 0x72, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0b, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1f, 0x2e, 0x42, 0x72, 0x65, 0x61, 0x6b, 0x6f, 0x75, 0x74, 0x50, 0x68, 0x79, 0x73, 0x69, 0x63,
	0x61, 0x6c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x72,
	0x52, 0x0c, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x25,
	0x0a, 0x0e, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x72, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x0c, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0d, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x52, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x2f, 0x0a, 0x09, 0x69, 0x6e, 0x66, 0x6f, 0x5f, 0x6c, 0x69,
	0x73, 0x74, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x42, 0x72, 0x65, 0x61, 0x6b,
	0x6f, 0x75, 0x74, 0x42, 0x72, 0x69, 0x63, 0x6b, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x08, 0x69, 0x6e,
	0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x27, 0x0a, 0x10, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x68,
	0x69, 0x74, 0x5f, 0x70, 0x65, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0d, 0x6c, 0x61, 0x73, 0x74, 0x48, 0x69, 0x74, 0x50, 0x65, 0x65, 0x72, 0x49, 0x64, 0x12,
	0x30, 0x0a, 0x14, 0x73, 0x70, 0x65, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x63, 0x72, 0x65, 0x61, 0x73,
	0x65, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x73,
	0x70, 0x65, 0x65, 0x64, 0x49, 0x6e, 0x63, 0x72, 0x65, 0x61, 0x73, 0x65, 0x43, 0x6f, 0x75, 0x6e,
	0x74, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x18, 0x10, 0x20, 0x01, 0x28,
	0x05, 0x52, 0x06, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65,
	0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_BreakoutPhysicalObject_proto_rawDescOnce sync.Once
	file_BreakoutPhysicalObject_proto_rawDescData = file_BreakoutPhysicalObject_proto_rawDesc
)

func file_BreakoutPhysicalObject_proto_rawDescGZIP() []byte {
	file_BreakoutPhysicalObject_proto_rawDescOnce.Do(func() {
		file_BreakoutPhysicalObject_proto_rawDescData = protoimpl.X.CompressGZIP(file_BreakoutPhysicalObject_proto_rawDescData)
	})
	return file_BreakoutPhysicalObject_proto_rawDescData
}

var file_BreakoutPhysicalObject_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_BreakoutPhysicalObject_proto_goTypes = []interface{}{
	(*BreakoutPhysicalObject)(nil),         // 0: BreakoutPhysicalObject
	(*BreakoutVector2)(nil),                // 1: BreakoutVector2
	(*BreakoutPhysicalObjectModifier)(nil), // 2: BreakoutPhysicalObjectModifier
	(*BreakoutBrickInfo)(nil),              // 3: BreakoutBrickInfo
}
var file_BreakoutPhysicalObject_proto_depIdxs = []int32{
	1, // 0: BreakoutPhysicalObject.pos:type_name -> BreakoutVector2
	1, // 1: BreakoutPhysicalObject.move_dir:type_name -> BreakoutVector2
	2, // 2: BreakoutPhysicalObject.modifier_list:type_name -> BreakoutPhysicalObjectModifier
	3, // 3: BreakoutPhysicalObject.info_list:type_name -> BreakoutBrickInfo
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_BreakoutPhysicalObject_proto_init() }
func file_BreakoutPhysicalObject_proto_init() {
	if File_BreakoutPhysicalObject_proto != nil {
		return
	}
	file_BreakoutVector2_proto_init()
	file_BreakoutPhysicalObjectModifier_proto_init()
	file_BreakoutBrickInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_BreakoutPhysicalObject_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BreakoutPhysicalObject); i {
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
			RawDescriptor: file_BreakoutPhysicalObject_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_BreakoutPhysicalObject_proto_goTypes,
		DependencyIndexes: file_BreakoutPhysicalObject_proto_depIdxs,
		MessageInfos:      file_BreakoutPhysicalObject_proto_msgTypes,
	}.Build()
	File_BreakoutPhysicalObject_proto = out.File
	file_BreakoutPhysicalObject_proto_rawDesc = nil
	file_BreakoutPhysicalObject_proto_goTypes = nil
	file_BreakoutPhysicalObject_proto_depIdxs = nil
}
