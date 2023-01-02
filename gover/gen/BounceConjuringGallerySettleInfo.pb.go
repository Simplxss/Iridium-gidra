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
// source: BounceConjuringGallerySettleInfo.proto

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

type BounceConjuringGallerySettleInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Unk3300_PELHBJDMKAE uint32                   `protobuf:"varint,6,opt,name=Unk3300_PELHBJDMKAE,json=Unk3300PELHBJDMKAE,proto3" json:"Unk3300_PELHBJDMKAE,omitempty"`
	Score               uint32                   `protobuf:"varint,15,opt,name=score,proto3" json:"score,omitempty"`
	GadgetCountMap      map[uint32]uint32        `protobuf:"bytes,3,rep,name=gadget_count_map,json=gadgetCountMap,proto3" json:"gadget_count_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	Unk3300_CNGOBOFDEOE uint32                   `protobuf:"varint,11,opt,name=Unk3300_CNGOBOFDEOE,json=Unk3300CNGOBOFDEOE,proto3" json:"Unk3300_CNGOBOFDEOE,omitempty"`
	Unk3300_NKGFKLGDFAC uint32                   `protobuf:"varint,1,opt,name=Unk3300_NKGFKLGDFAC,json=Unk3300NKGFKLGDFAC,proto3" json:"Unk3300_NKGFKLGDFAC,omitempty"`
	PlayerInfo          *OnlinePlayerInfo        `protobuf:"bytes,2,opt,name=player_info,json=playerInfo,proto3" json:"player_info,omitempty"`
	Damage              float32                  `protobuf:"fixed32,12,opt,name=damage,proto3" json:"damage,omitempty"`
	Unk3300_BJHCDKNFDFN uint32                   `protobuf:"varint,7,opt,name=Unk3300_BJHCDKNFDFN,json=Unk3300BJHCDKNFDFN,proto3" json:"Unk3300_BJHCDKNFDFN,omitempty"`
	CardList            []*ExhibitionDisplayInfo `protobuf:"bytes,9,rep,name=card_list,json=cardList,proto3" json:"card_list,omitempty"`
}

func (x *BounceConjuringGallerySettleInfo) Reset() {
	*x = BounceConjuringGallerySettleInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_BounceConjuringGallerySettleInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BounceConjuringGallerySettleInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BounceConjuringGallerySettleInfo) ProtoMessage() {}

func (x *BounceConjuringGallerySettleInfo) ProtoReflect() protoreflect.Message {
	mi := &file_BounceConjuringGallerySettleInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BounceConjuringGallerySettleInfo.ProtoReflect.Descriptor instead.
func (*BounceConjuringGallerySettleInfo) Descriptor() ([]byte, []int) {
	return file_BounceConjuringGallerySettleInfo_proto_rawDescGZIP(), []int{0}
}

func (x *BounceConjuringGallerySettleInfo) GetUnk3300_PELHBJDMKAE() uint32 {
	if x != nil {
		return x.Unk3300_PELHBJDMKAE
	}
	return 0
}

func (x *BounceConjuringGallerySettleInfo) GetScore() uint32 {
	if x != nil {
		return x.Score
	}
	return 0
}

func (x *BounceConjuringGallerySettleInfo) GetGadgetCountMap() map[uint32]uint32 {
	if x != nil {
		return x.GadgetCountMap
	}
	return nil
}

func (x *BounceConjuringGallerySettleInfo) GetUnk3300_CNGOBOFDEOE() uint32 {
	if x != nil {
		return x.Unk3300_CNGOBOFDEOE
	}
	return 0
}

func (x *BounceConjuringGallerySettleInfo) GetUnk3300_NKGFKLGDFAC() uint32 {
	if x != nil {
		return x.Unk3300_NKGFKLGDFAC
	}
	return 0
}

func (x *BounceConjuringGallerySettleInfo) GetPlayerInfo() *OnlinePlayerInfo {
	if x != nil {
		return x.PlayerInfo
	}
	return nil
}

func (x *BounceConjuringGallerySettleInfo) GetDamage() float32 {
	if x != nil {
		return x.Damage
	}
	return 0
}

func (x *BounceConjuringGallerySettleInfo) GetUnk3300_BJHCDKNFDFN() uint32 {
	if x != nil {
		return x.Unk3300_BJHCDKNFDFN
	}
	return 0
}

func (x *BounceConjuringGallerySettleInfo) GetCardList() []*ExhibitionDisplayInfo {
	if x != nil {
		return x.CardList
	}
	return nil
}

var File_BounceConjuringGallerySettleInfo_proto protoreflect.FileDescriptor

var file_BounceConjuringGallerySettleInfo_proto_rawDesc = []byte{
	0x0a, 0x26, 0x42, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x6a, 0x75, 0x72, 0x69, 0x6e,
	0x67, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e,
	0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x45, 0x78, 0x68, 0x69, 0x62, 0x69,
	0x74, 0x69, 0x6f, 0x6e, 0x44, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x4f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x50, 0x6c, 0x61,
	0x79, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa1, 0x04,
	0x0a, 0x20, 0x42, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x6a, 0x75, 0x72, 0x69, 0x6e,
	0x67, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x65, 0x74, 0x74, 0x6c, 0x65, 0x49, 0x6e,
	0x66, 0x6f, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x5f, 0x50, 0x45,
	0x4c, 0x48, 0x42, 0x4a, 0x44, 0x4d, 0x4b, 0x41, 0x45, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x12, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x50, 0x45, 0x4c, 0x48, 0x42, 0x4a, 0x44, 0x4d,
	0x4b, 0x41, 0x45, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x0f, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x12, 0x5f, 0x0a, 0x10, 0x67, 0x61, 0x64,
	0x67, 0x65, 0x74, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x5f, 0x6d, 0x61, 0x70, 0x18, 0x03, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x42, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x43, 0x6f, 0x6e, 0x6a,
	0x75, 0x72, 0x69, 0x6e, 0x67, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x65, 0x74, 0x74,
	0x6c, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x2e, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x43, 0x6f, 0x75,
	0x6e, 0x74, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0e, 0x67, 0x61, 0x64, 0x67,
	0x65, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x4d, 0x61, 0x70, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e,
	0x6b, 0x33, 0x33, 0x30, 0x30, 0x5f, 0x43, 0x4e, 0x47, 0x4f, 0x42, 0x4f, 0x46, 0x44, 0x45, 0x4f,
	0x45, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30,
	0x43, 0x4e, 0x47, 0x4f, 0x42, 0x4f, 0x46, 0x44, 0x45, 0x4f, 0x45, 0x12, 0x2f, 0x0a, 0x13, 0x55,
	0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x5f, 0x4e, 0x4b, 0x47, 0x46, 0x4b, 0x4c, 0x47, 0x44, 0x46,
	0x41, 0x43, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30,
	0x30, 0x4e, 0x4b, 0x47, 0x46, 0x4b, 0x4c, 0x47, 0x44, 0x46, 0x41, 0x43, 0x12, 0x32, 0x0a, 0x0b,
	0x70, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x11, 0x2e, 0x4f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72,
	0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0a, 0x70, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f,
	0x12, 0x16, 0x0a, 0x06, 0x64, 0x61, 0x6d, 0x61, 0x67, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x02,
	0x52, 0x06, 0x64, 0x61, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x2f, 0x0a, 0x13, 0x55, 0x6e, 0x6b, 0x33,
	0x33, 0x30, 0x30, 0x5f, 0x42, 0x4a, 0x48, 0x43, 0x44, 0x4b, 0x4e, 0x46, 0x44, 0x46, 0x4e, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x12, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x42, 0x4a,
	0x48, 0x43, 0x44, 0x4b, 0x4e, 0x46, 0x44, 0x46, 0x4e, 0x12, 0x33, 0x0a, 0x09, 0x63, 0x61, 0x72,
	0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x45,
	0x78, 0x68, 0x69, 0x62, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79,
	0x49, 0x6e, 0x66, 0x6f, 0x52, 0x08, 0x63, 0x61, 0x72, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x1a, 0x41,
	0x0a, 0x13, 0x47, 0x61, 0x64, 0x67, 0x65, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x4d, 0x61, 0x70,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_BounceConjuringGallerySettleInfo_proto_rawDescOnce sync.Once
	file_BounceConjuringGallerySettleInfo_proto_rawDescData = file_BounceConjuringGallerySettleInfo_proto_rawDesc
)

func file_BounceConjuringGallerySettleInfo_proto_rawDescGZIP() []byte {
	file_BounceConjuringGallerySettleInfo_proto_rawDescOnce.Do(func() {
		file_BounceConjuringGallerySettleInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_BounceConjuringGallerySettleInfo_proto_rawDescData)
	})
	return file_BounceConjuringGallerySettleInfo_proto_rawDescData
}

var file_BounceConjuringGallerySettleInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_BounceConjuringGallerySettleInfo_proto_goTypes = []interface{}{
	(*BounceConjuringGallerySettleInfo)(nil), // 0: BounceConjuringGallerySettleInfo
	nil,                                      // 1: BounceConjuringGallerySettleInfo.GadgetCountMapEntry
	(*OnlinePlayerInfo)(nil),                 // 2: OnlinePlayerInfo
	(*ExhibitionDisplayInfo)(nil),            // 3: ExhibitionDisplayInfo
}
var file_BounceConjuringGallerySettleInfo_proto_depIdxs = []int32{
	1, // 0: BounceConjuringGallerySettleInfo.gadget_count_map:type_name -> BounceConjuringGallerySettleInfo.GadgetCountMapEntry
	2, // 1: BounceConjuringGallerySettleInfo.player_info:type_name -> OnlinePlayerInfo
	3, // 2: BounceConjuringGallerySettleInfo.card_list:type_name -> ExhibitionDisplayInfo
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_BounceConjuringGallerySettleInfo_proto_init() }
func file_BounceConjuringGallerySettleInfo_proto_init() {
	if File_BounceConjuringGallerySettleInfo_proto != nil {
		return
	}
	file_ExhibitionDisplayInfo_proto_init()
	file_OnlinePlayerInfo_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_BounceConjuringGallerySettleInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BounceConjuringGallerySettleInfo); i {
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
			RawDescriptor: file_BounceConjuringGallerySettleInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_BounceConjuringGallerySettleInfo_proto_goTypes,
		DependencyIndexes: file_BounceConjuringGallerySettleInfo_proto_depIdxs,
		MessageInfos:      file_BounceConjuringGallerySettleInfo_proto_msgTypes,
	}.Build()
	File_BounceConjuringGallerySettleInfo_proto = out.File
	file_BounceConjuringGallerySettleInfo_proto_rawDesc = nil
	file_BounceConjuringGallerySettleInfo_proto_goTypes = nil
	file_BounceConjuringGallerySettleInfo_proto_depIdxs = nil
}
