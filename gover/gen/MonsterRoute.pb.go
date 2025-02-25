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
// source: MonsterRoute.proto

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

// Obf: OKAKLDGDFDP
type MonsterRoute struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RoutePoints []*RoutePoint `protobuf:"bytes,1,rep,name=route_points,json=routePoints,proto3" json:"route_points,omitempty"`
	SpeedLevel  uint32        `protobuf:"varint,2,opt,name=speed_level,json=speedLevel,proto3" json:"speed_level,omitempty"`
	RouteType   uint32        `protobuf:"varint,3,opt,name=route_type,json=routeType,proto3" json:"route_type,omitempty"`
	ArriveRange float32       `protobuf:"fixed32,4,opt,name=arrive_range,json=arriveRange,proto3" json:"arrive_range,omitempty"`
}

func (x *MonsterRoute) Reset() {
	*x = MonsterRoute{}
	if protoimpl.UnsafeEnabled {
		mi := &file_MonsterRoute_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MonsterRoute) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MonsterRoute) ProtoMessage() {}

func (x *MonsterRoute) ProtoReflect() protoreflect.Message {
	mi := &file_MonsterRoute_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MonsterRoute.ProtoReflect.Descriptor instead.
func (*MonsterRoute) Descriptor() ([]byte, []int) {
	return file_MonsterRoute_proto_rawDescGZIP(), []int{0}
}

func (x *MonsterRoute) GetRoutePoints() []*RoutePoint {
	if x != nil {
		return x.RoutePoints
	}
	return nil
}

func (x *MonsterRoute) GetSpeedLevel() uint32 {
	if x != nil {
		return x.SpeedLevel
	}
	return 0
}

func (x *MonsterRoute) GetRouteType() uint32 {
	if x != nil {
		return x.RouteType
	}
	return 0
}

func (x *MonsterRoute) GetArriveRange() float32 {
	if x != nil {
		return x.ArriveRange
	}
	return 0
}

var File_MonsterRoute_proto protoreflect.FileDescriptor

var file_MonsterRoute_proto_rawDesc = []byte{
	0x0a, 0x12, 0x4d, 0x6f, 0x6e, 0x73, 0x74, 0x65, 0x72, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x10, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x6f, 0x69, 0x6e, 0x74,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa1, 0x01, 0x0a, 0x0c, 0x4d, 0x6f, 0x6e, 0x73, 0x74,
	0x65, 0x72, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x2e, 0x0a, 0x0c, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0b, 0x2e,
	0x52, 0x6f, 0x75, 0x74, 0x65, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x0b, 0x72, 0x6f, 0x75, 0x74,
	0x65, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x70, 0x65, 0x65, 0x64,
	0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x73, 0x70,
	0x65, 0x65, 0x64, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x6f, 0x75, 0x74,
	0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x72, 0x72, 0x69, 0x76,
	0x65, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x02, 0x52, 0x0b, 0x61,
	0x72, 0x72, 0x69, 0x76, 0x65, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_MonsterRoute_proto_rawDescOnce sync.Once
	file_MonsterRoute_proto_rawDescData = file_MonsterRoute_proto_rawDesc
)

func file_MonsterRoute_proto_rawDescGZIP() []byte {
	file_MonsterRoute_proto_rawDescOnce.Do(func() {
		file_MonsterRoute_proto_rawDescData = protoimpl.X.CompressGZIP(file_MonsterRoute_proto_rawDescData)
	})
	return file_MonsterRoute_proto_rawDescData
}

var file_MonsterRoute_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_MonsterRoute_proto_goTypes = []interface{}{
	(*MonsterRoute)(nil), // 0: MonsterRoute
	(*RoutePoint)(nil),   // 1: RoutePoint
}
var file_MonsterRoute_proto_depIdxs = []int32{
	1, // 0: MonsterRoute.route_points:type_name -> RoutePoint
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_MonsterRoute_proto_init() }
func file_MonsterRoute_proto_init() {
	if File_MonsterRoute_proto != nil {
		return
	}
	file_RoutePoint_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_MonsterRoute_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MonsterRoute); i {
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
			RawDescriptor: file_MonsterRoute_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_MonsterRoute_proto_goTypes,
		DependencyIndexes: file_MonsterRoute_proto_depIdxs,
		MessageInfos:      file_MonsterRoute_proto_msgTypes,
	}.Build()
	File_MonsterRoute_proto = out.File
	file_MonsterRoute_proto_rawDesc = nil
	file_MonsterRoute_proto_goTypes = nil
	file_MonsterRoute_proto_depIdxs = nil
}
