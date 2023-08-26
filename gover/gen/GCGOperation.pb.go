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
// source: GCGOperation.proto

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

// Obf: KMHPEHOILKJ
type GCGOperation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Op:
	//
	//	*GCGOperation_OpRedraw
	//	*GCGOperation_OpSelectOnStage
	//	*GCGOperation_OpReroll
	//	*GCGOperation_OpAttack
	//	*GCGOperation_OpPass
	//	*GCGOperation_OpPlayCard
	//	*GCGOperation_OpReboot
	//	*GCGOperation_OpSurrender
	Op isGCGOperation_Op `protobuf_oneof:"op"`
}

func (x *GCGOperation) Reset() {
	*x = GCGOperation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_GCGOperation_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GCGOperation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GCGOperation) ProtoMessage() {}

func (x *GCGOperation) ProtoReflect() protoreflect.Message {
	mi := &file_GCGOperation_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GCGOperation.ProtoReflect.Descriptor instead.
func (*GCGOperation) Descriptor() ([]byte, []int) {
	return file_GCGOperation_proto_rawDescGZIP(), []int{0}
}

func (m *GCGOperation) GetOp() isGCGOperation_Op {
	if m != nil {
		return m.Op
	}
	return nil
}

func (x *GCGOperation) GetOpRedraw() *GCGOperationRedraw {
	if x, ok := x.GetOp().(*GCGOperation_OpRedraw); ok {
		return x.OpRedraw
	}
	return nil
}

func (x *GCGOperation) GetOpSelectOnStage() *GCGOperationOnStageSelect {
	if x, ok := x.GetOp().(*GCGOperation_OpSelectOnStage); ok {
		return x.OpSelectOnStage
	}
	return nil
}

func (x *GCGOperation) GetOpReroll() *GCGOperationReroll {
	if x, ok := x.GetOp().(*GCGOperation_OpReroll); ok {
		return x.OpReroll
	}
	return nil
}

func (x *GCGOperation) GetOpAttack() *GCGOperationAttack {
	if x, ok := x.GetOp().(*GCGOperation_OpAttack); ok {
		return x.OpAttack
	}
	return nil
}

func (x *GCGOperation) GetOpPass() *GCGOperationPass {
	if x, ok := x.GetOp().(*GCGOperation_OpPass); ok {
		return x.OpPass
	}
	return nil
}

func (x *GCGOperation) GetOpPlayCard() *GCGOperationPlayCard {
	if x, ok := x.GetOp().(*GCGOperation_OpPlayCard); ok {
		return x.OpPlayCard
	}
	return nil
}

func (x *GCGOperation) GetOpReboot() *GCGOperationReboot {
	if x, ok := x.GetOp().(*GCGOperation_OpReboot); ok {
		return x.OpReboot
	}
	return nil
}

func (x *GCGOperation) GetOpSurrender() *GCGOperationSurrender {
	if x, ok := x.GetOp().(*GCGOperation_OpSurrender); ok {
		return x.OpSurrender
	}
	return nil
}

type isGCGOperation_Op interface {
	isGCGOperation_Op()
}

type GCGOperation_OpRedraw struct {
	OpRedraw *GCGOperationRedraw `protobuf:"bytes,9,opt,name=op_redraw,json=opRedraw,proto3,oneof"`
}

type GCGOperation_OpSelectOnStage struct {
	OpSelectOnStage *GCGOperationOnStageSelect `protobuf:"bytes,14,opt,name=op_select_on_stage,json=opSelectOnStage,proto3,oneof"`
}

type GCGOperation_OpReroll struct {
	OpReroll *GCGOperationReroll `protobuf:"bytes,3,opt,name=op_reroll,json=opReroll,proto3,oneof"`
}

type GCGOperation_OpAttack struct {
	OpAttack *GCGOperationAttack `protobuf:"bytes,4,opt,name=op_attack,json=opAttack,proto3,oneof"`
}

type GCGOperation_OpPass struct {
	OpPass *GCGOperationPass `protobuf:"bytes,13,opt,name=op_pass,json=opPass,proto3,oneof"`
}

type GCGOperation_OpPlayCard struct {
	OpPlayCard *GCGOperationPlayCard `protobuf:"bytes,1,opt,name=op_play_card,json=opPlayCard,proto3,oneof"`
}

type GCGOperation_OpReboot struct {
	OpReboot *GCGOperationReboot `protobuf:"bytes,12,opt,name=op_reboot,json=opReboot,proto3,oneof"`
}

type GCGOperation_OpSurrender struct {
	OpSurrender *GCGOperationSurrender `protobuf:"bytes,10,opt,name=op_surrender,json=opSurrender,proto3,oneof"`
}

func (*GCGOperation_OpRedraw) isGCGOperation_Op() {}

func (*GCGOperation_OpSelectOnStage) isGCGOperation_Op() {}

func (*GCGOperation_OpReroll) isGCGOperation_Op() {}

func (*GCGOperation_OpAttack) isGCGOperation_Op() {}

func (*GCGOperation_OpPass) isGCGOperation_Op() {}

func (*GCGOperation_OpPlayCard) isGCGOperation_Op() {}

func (*GCGOperation_OpReboot) isGCGOperation_Op() {}

func (*GCGOperation_OpSurrender) isGCGOperation_Op() {}

var File_GCGOperation_proto protoreflect.FileDescriptor

var file_GCGOperation_proto_rawDesc = []byte{
	0x0a, 0x12, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x64, 0x72, 0x61, 0x77, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x6e, 0x53, 0x74,
	0x61, 0x67, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x18, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x72,
	0x6f, 0x6c, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x47, 0x43, 0x47, 0x4f, 0x70,
	0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x50, 0x61, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x47, 0x43, 0x47,
	0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6c, 0x61, 0x79, 0x43, 0x61, 0x72,
	0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x62, 0x6f, 0x6f, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1b, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53,
	0x75, 0x72, 0x72, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xd5,
	0x03, 0x0a, 0x0c, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x32, 0x0a, 0x09, 0x6f, 0x70, 0x5f, 0x72, 0x65, 0x64, 0x72, 0x61, 0x77, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x13, 0x2e, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x65, 0x64, 0x72, 0x61, 0x77, 0x48, 0x00, 0x52, 0x08, 0x6f, 0x70, 0x52, 0x65, 0x64,
	0x72, 0x61, 0x77, 0x12, 0x49, 0x0a, 0x12, 0x6f, 0x70, 0x5f, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74,
	0x5f, 0x6f, 0x6e, 0x5f, 0x73, 0x74, 0x61, 0x67, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4f, 0x6e,
	0x53, 0x74, 0x61, 0x67, 0x65, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x48, 0x00, 0x52, 0x0f, 0x6f,
	0x70, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x4f, 0x6e, 0x53, 0x74, 0x61, 0x67, 0x65, 0x12, 0x32,
	0x0a, 0x09, 0x6f, 0x70, 0x5f, 0x72, 0x65, 0x72, 0x6f, 0x6c, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x13, 0x2e, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x72, 0x6f, 0x6c, 0x6c, 0x48, 0x00, 0x52, 0x08, 0x6f, 0x70, 0x52, 0x65, 0x72, 0x6f,
	0x6c, 0x6c, 0x12, 0x32, 0x0a, 0x09, 0x6f, 0x70, 0x5f, 0x61, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x41, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x48, 0x00, 0x52, 0x08, 0x6f, 0x70,
	0x41, 0x74, 0x74, 0x61, 0x63, 0x6b, 0x12, 0x2c, 0x0a, 0x07, 0x6f, 0x70, 0x5f, 0x70, 0x61, 0x73,
	0x73, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x61, 0x73, 0x73, 0x48, 0x00, 0x52, 0x06, 0x6f, 0x70,
	0x50, 0x61, 0x73, 0x73, 0x12, 0x39, 0x0a, 0x0c, 0x6f, 0x70, 0x5f, 0x70, 0x6c, 0x61, 0x79, 0x5f,
	0x63, 0x61, 0x72, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x47, 0x43, 0x47,
	0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6c, 0x61, 0x79, 0x43, 0x61, 0x72,
	0x64, 0x48, 0x00, 0x52, 0x0a, 0x6f, 0x70, 0x50, 0x6c, 0x61, 0x79, 0x43, 0x61, 0x72, 0x64, 0x12,
	0x32, 0x0a, 0x09, 0x6f, 0x70, 0x5f, 0x72, 0x65, 0x62, 0x6f, 0x6f, 0x74, 0x18, 0x0c, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x13, 0x2e, 0x47, 0x43, 0x47, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x65, 0x62, 0x6f, 0x6f, 0x74, 0x48, 0x00, 0x52, 0x08, 0x6f, 0x70, 0x52, 0x65, 0x62,
	0x6f, 0x6f, 0x74, 0x12, 0x3b, 0x0a, 0x0c, 0x6f, 0x70, 0x5f, 0x73, 0x75, 0x72, 0x72, 0x65, 0x6e,
	0x64, 0x65, 0x72, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x47, 0x43, 0x47, 0x4f,
	0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x64, 0x65,
	0x72, 0x48, 0x00, 0x52, 0x0b, 0x6f, 0x70, 0x53, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x64, 0x65, 0x72,
	0x42, 0x04, 0x0a, 0x02, 0x6f, 0x70, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GCGOperation_proto_rawDescOnce sync.Once
	file_GCGOperation_proto_rawDescData = file_GCGOperation_proto_rawDesc
)

func file_GCGOperation_proto_rawDescGZIP() []byte {
	file_GCGOperation_proto_rawDescOnce.Do(func() {
		file_GCGOperation_proto_rawDescData = protoimpl.X.CompressGZIP(file_GCGOperation_proto_rawDescData)
	})
	return file_GCGOperation_proto_rawDescData
}

var file_GCGOperation_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_GCGOperation_proto_goTypes = []interface{}{
	(*GCGOperation)(nil),              // 0: GCGOperation
	(*GCGOperationRedraw)(nil),        // 1: GCGOperationRedraw
	(*GCGOperationOnStageSelect)(nil), // 2: GCGOperationOnStageSelect
	(*GCGOperationReroll)(nil),        // 3: GCGOperationReroll
	(*GCGOperationAttack)(nil),        // 4: GCGOperationAttack
	(*GCGOperationPass)(nil),          // 5: GCGOperationPass
	(*GCGOperationPlayCard)(nil),      // 6: GCGOperationPlayCard
	(*GCGOperationReboot)(nil),        // 7: GCGOperationReboot
	(*GCGOperationSurrender)(nil),     // 8: GCGOperationSurrender
}
var file_GCGOperation_proto_depIdxs = []int32{
	1, // 0: GCGOperation.op_redraw:type_name -> GCGOperationRedraw
	2, // 1: GCGOperation.op_select_on_stage:type_name -> GCGOperationOnStageSelect
	3, // 2: GCGOperation.op_reroll:type_name -> GCGOperationReroll
	4, // 3: GCGOperation.op_attack:type_name -> GCGOperationAttack
	5, // 4: GCGOperation.op_pass:type_name -> GCGOperationPass
	6, // 5: GCGOperation.op_play_card:type_name -> GCGOperationPlayCard
	7, // 6: GCGOperation.op_reboot:type_name -> GCGOperationReboot
	8, // 7: GCGOperation.op_surrender:type_name -> GCGOperationSurrender
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_GCGOperation_proto_init() }
func file_GCGOperation_proto_init() {
	if File_GCGOperation_proto != nil {
		return
	}
	file_GCGOperationRedraw_proto_init()
	file_GCGOperationOnStageSelect_proto_init()
	file_GCGOperationReroll_proto_init()
	file_GCGOperationAttack_proto_init()
	file_GCGOperationPass_proto_init()
	file_GCGOperationPlayCard_proto_init()
	file_GCGOperationReboot_proto_init()
	file_GCGOperationSurrender_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_GCGOperation_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GCGOperation); i {
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
	file_GCGOperation_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*GCGOperation_OpRedraw)(nil),
		(*GCGOperation_OpSelectOnStage)(nil),
		(*GCGOperation_OpReroll)(nil),
		(*GCGOperation_OpAttack)(nil),
		(*GCGOperation_OpPass)(nil),
		(*GCGOperation_OpPlayCard)(nil),
		(*GCGOperation_OpReboot)(nil),
		(*GCGOperation_OpSurrender)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_GCGOperation_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GCGOperation_proto_goTypes,
		DependencyIndexes: file_GCGOperation_proto_depIdxs,
		MessageInfos:      file_GCGOperation_proto_msgTypes,
	}.Build()
	File_GCGOperation_proto = out.File
	file_GCGOperation_proto_rawDesc = nil
	file_GCGOperation_proto_goTypes = nil
	file_GCGOperation_proto_depIdxs = nil
}
