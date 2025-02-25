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
// source: RechargeReq.proto

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

// CmdId: 3184
// Obf: JHDKPKJPMCK
type RechargeReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	McoinProduct   *ShopMcoinProduct   `protobuf:"bytes,4,opt,name=mcoin_product,json=mcoinProduct,proto3" json:"mcoin_product,omitempty"`
	PlayProduct    *PlayProduct        `protobuf:"bytes,11,opt,name=play_product,json=playProduct,proto3" json:"play_product,omitempty"`
	CardProduct    *ShopCardProduct    `protobuf:"bytes,2,opt,name=card_product,json=cardProduct,proto3" json:"card_product,omitempty"`
	ConcertProduct *ShopConcertProduct `protobuf:"bytes,8,opt,name=concert_product,json=concertProduct,proto3" json:"concert_product,omitempty"`
}

func (x *RechargeReq) Reset() {
	*x = RechargeReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_RechargeReq_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RechargeReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RechargeReq) ProtoMessage() {}

func (x *RechargeReq) ProtoReflect() protoreflect.Message {
	mi := &file_RechargeReq_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RechargeReq.ProtoReflect.Descriptor instead.
func (*RechargeReq) Descriptor() ([]byte, []int) {
	return file_RechargeReq_proto_rawDescGZIP(), []int{0}
}

func (x *RechargeReq) GetMcoinProduct() *ShopMcoinProduct {
	if x != nil {
		return x.McoinProduct
	}
	return nil
}

func (x *RechargeReq) GetPlayProduct() *PlayProduct {
	if x != nil {
		return x.PlayProduct
	}
	return nil
}

func (x *RechargeReq) GetCardProduct() *ShopCardProduct {
	if x != nil {
		return x.CardProduct
	}
	return nil
}

func (x *RechargeReq) GetConcertProduct() *ShopConcertProduct {
	if x != nil {
		return x.ConcertProduct
	}
	return nil
}

var File_RechargeReq_proto protoreflect.FileDescriptor

var file_RechargeReq_proto_rawDesc = []byte{
	0x0a, 0x11, 0x52, 0x65, 0x63, 0x68, 0x61, 0x72, 0x67, 0x65, 0x52, 0x65, 0x71, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x53, 0x68, 0x6f, 0x70, 0x4d, 0x63, 0x6f, 0x69, 0x6e, 0x50, 0x72,
	0x6f, 0x64, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x11, 0x50, 0x6c, 0x61,
	0x79, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x15,
	0x53, 0x68, 0x6f, 0x70, 0x43, 0x61, 0x72, 0x64, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x53, 0x68, 0x6f, 0x70, 0x43, 0x6f, 0x6e, 0x63, 0x65,
	0x72, 0x74, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xe9, 0x01, 0x0a, 0x0b, 0x52, 0x65, 0x63, 0x68, 0x61, 0x72, 0x67, 0x65, 0x52, 0x65, 0x71, 0x12,
	0x36, 0x0a, 0x0d, 0x6d, 0x63, 0x6f, 0x69, 0x6e, 0x5f, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x53, 0x68, 0x6f, 0x70, 0x4d, 0x63, 0x6f,
	0x69, 0x6e, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x52, 0x0c, 0x6d, 0x63, 0x6f, 0x69, 0x6e,
	0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x12, 0x2f, 0x0a, 0x0c, 0x70, 0x6c, 0x61, 0x79, 0x5f,
	0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0c, 0x2e,
	0x50, 0x6c, 0x61, 0x79, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x52, 0x0b, 0x70, 0x6c, 0x61,
	0x79, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x12, 0x33, 0x0a, 0x0c, 0x63, 0x61, 0x72, 0x64,
	0x5f, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10,
	0x2e, 0x53, 0x68, 0x6f, 0x70, 0x43, 0x61, 0x72, 0x64, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74,
	0x52, 0x0b, 0x63, 0x61, 0x72, 0x64, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x12, 0x3c, 0x0a,
	0x0f, 0x63, 0x6f, 0x6e, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x53, 0x68, 0x6f, 0x70, 0x43, 0x6f, 0x6e,
	0x63, 0x65, 0x72, 0x74, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x52, 0x0e, 0x63, 0x6f, 0x6e,
	0x63, 0x65, 0x72, 0x74, 0x50, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x42, 0x06, 0x5a, 0x04, 0x2f,
	0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_RechargeReq_proto_rawDescOnce sync.Once
	file_RechargeReq_proto_rawDescData = file_RechargeReq_proto_rawDesc
)

func file_RechargeReq_proto_rawDescGZIP() []byte {
	file_RechargeReq_proto_rawDescOnce.Do(func() {
		file_RechargeReq_proto_rawDescData = protoimpl.X.CompressGZIP(file_RechargeReq_proto_rawDescData)
	})
	return file_RechargeReq_proto_rawDescData
}

var file_RechargeReq_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_RechargeReq_proto_goTypes = []interface{}{
	(*RechargeReq)(nil),        // 0: RechargeReq
	(*ShopMcoinProduct)(nil),   // 1: ShopMcoinProduct
	(*PlayProduct)(nil),        // 2: PlayProduct
	(*ShopCardProduct)(nil),    // 3: ShopCardProduct
	(*ShopConcertProduct)(nil), // 4: ShopConcertProduct
}
var file_RechargeReq_proto_depIdxs = []int32{
	1, // 0: RechargeReq.mcoin_product:type_name -> ShopMcoinProduct
	2, // 1: RechargeReq.play_product:type_name -> PlayProduct
	3, // 2: RechargeReq.card_product:type_name -> ShopCardProduct
	4, // 3: RechargeReq.concert_product:type_name -> ShopConcertProduct
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_RechargeReq_proto_init() }
func file_RechargeReq_proto_init() {
	if File_RechargeReq_proto != nil {
		return
	}
	file_ShopMcoinProduct_proto_init()
	file_PlayProduct_proto_init()
	file_ShopCardProduct_proto_init()
	file_ShopConcertProduct_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_RechargeReq_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RechargeReq); i {
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
			RawDescriptor: file_RechargeReq_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_RechargeReq_proto_goTypes,
		DependencyIndexes: file_RechargeReq_proto_depIdxs,
		MessageInfos:      file_RechargeReq_proto_msgTypes,
	}.Build()
	File_RechargeReq_proto = out.File
	file_RechargeReq_proto_rawDesc = nil
	file_RechargeReq_proto_goTypes = nil
	file_RechargeReq_proto_depIdxs = nil
}
