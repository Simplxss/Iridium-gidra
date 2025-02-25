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
// source: SceneGalleryIslandPartySailInfo.proto

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

// Obf: GBGEALIJHNE
type SceneGalleryIslandPartySailInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Coin        uint32               `protobuf:"varint,1,opt,name=coin,proto3" json:"coin,omitempty"`
	CGEHJNCLFIH uint32               `protobuf:"varint,7,opt,name=CGEHJNCLFIH,proto3" json:"CGEHJNCLFIH,omitempty"`
	GHJGNKKLNED uint32               `protobuf:"varint,11,opt,name=GHJGNKKLNED,proto3" json:"GHJGNKKLNED,omitempty"`
	StartSource GalleryStartSource   `protobuf:"varint,13,opt,name=start_source,json=startSource,proto3,enum=GalleryStartSource" json:"start_source,omitempty"`
	KAGPALOPJHK uint32               `protobuf:"varint,10,opt,name=KAGPALOPJHK,proto3" json:"KAGPALOPJHK,omitempty"`
	FIBKEJGKANH uint32               `protobuf:"varint,4,opt,name=FIBKEJGKANH,proto3" json:"FIBKEJGKANH,omitempty"`
	Stage       IslandPartySailStage `protobuf:"varint,6,opt,name=stage,proto3,enum=IslandPartySailStage" json:"stage,omitempty"`
}

func (x *SceneGalleryIslandPartySailInfo) Reset() {
	*x = SceneGalleryIslandPartySailInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SceneGalleryIslandPartySailInfo_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SceneGalleryIslandPartySailInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SceneGalleryIslandPartySailInfo) ProtoMessage() {}

func (x *SceneGalleryIslandPartySailInfo) ProtoReflect() protoreflect.Message {
	mi := &file_SceneGalleryIslandPartySailInfo_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SceneGalleryIslandPartySailInfo.ProtoReflect.Descriptor instead.
func (*SceneGalleryIslandPartySailInfo) Descriptor() ([]byte, []int) {
	return file_SceneGalleryIslandPartySailInfo_proto_rawDescGZIP(), []int{0}
}

func (x *SceneGalleryIslandPartySailInfo) GetCoin() uint32 {
	if x != nil {
		return x.Coin
	}
	return 0
}

func (x *SceneGalleryIslandPartySailInfo) GetCGEHJNCLFIH() uint32 {
	if x != nil {
		return x.CGEHJNCLFIH
	}
	return 0
}

func (x *SceneGalleryIslandPartySailInfo) GetGHJGNKKLNED() uint32 {
	if x != nil {
		return x.GHJGNKKLNED
	}
	return 0
}

func (x *SceneGalleryIslandPartySailInfo) GetStartSource() GalleryStartSource {
	if x != nil {
		return x.StartSource
	}
	return GalleryStartSource_GALLERY_START_BY_NONE
}

func (x *SceneGalleryIslandPartySailInfo) GetKAGPALOPJHK() uint32 {
	if x != nil {
		return x.KAGPALOPJHK
	}
	return 0
}

func (x *SceneGalleryIslandPartySailInfo) GetFIBKEJGKANH() uint32 {
	if x != nil {
		return x.FIBKEJGKANH
	}
	return 0
}

func (x *SceneGalleryIslandPartySailInfo) GetStage() IslandPartySailStage {
	if x != nil {
		return x.Stage
	}
	return IslandPartySailStage_ISLAND_PARTY_SAIL_STAGE_NONE
}

var File_SceneGalleryIslandPartySailInfo_proto protoreflect.FileDescriptor

var file_SceneGalleryIslandPartySailInfo_proto_rawDesc = []byte{
	0x0a, 0x25, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x49, 0x73,
	0x6c, 0x61, 0x6e, 0x64, 0x50, 0x61, 0x72, 0x74, 0x79, 0x53, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66,
	0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x18, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79,
	0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1a, 0x49, 0x73, 0x6c, 0x61, 0x6e, 0x64, 0x50, 0x61, 0x72, 0x74, 0x79, 0x53, 0x61,
	0x69, 0x6c, 0x53, 0x74, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa2, 0x02,
	0x0a, 0x1f, 0x53, 0x63, 0x65, 0x6e, 0x65, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x49, 0x73,
	0x6c, 0x61, 0x6e, 0x64, 0x50, 0x61, 0x72, 0x74, 0x79, 0x53, 0x61, 0x69, 0x6c, 0x49, 0x6e, 0x66,
	0x6f, 0x12, 0x12, 0x0a, 0x04, 0x63, 0x6f, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x04, 0x63, 0x6f, 0x69, 0x6e, 0x12, 0x20, 0x0a, 0x0b, 0x43, 0x47, 0x45, 0x48, 0x4a, 0x4e, 0x43,
	0x4c, 0x46, 0x49, 0x48, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x43, 0x47, 0x45, 0x48,
	0x4a, 0x4e, 0x43, 0x4c, 0x46, 0x49, 0x48, 0x12, 0x20, 0x0a, 0x0b, 0x47, 0x48, 0x4a, 0x47, 0x4e,
	0x4b, 0x4b, 0x4c, 0x4e, 0x45, 0x44, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x47, 0x48,
	0x4a, 0x47, 0x4e, 0x4b, 0x4b, 0x4c, 0x4e, 0x45, 0x44, 0x12, 0x36, 0x0a, 0x0c, 0x73, 0x74, 0x61,
	0x72, 0x74, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x13, 0x2e, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x52, 0x0b, 0x73, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6f, 0x75, 0x72, 0x63,
	0x65, 0x12, 0x20, 0x0a, 0x0b, 0x4b, 0x41, 0x47, 0x50, 0x41, 0x4c, 0x4f, 0x50, 0x4a, 0x48, 0x4b,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4b, 0x41, 0x47, 0x50, 0x41, 0x4c, 0x4f, 0x50,
	0x4a, 0x48, 0x4b, 0x12, 0x20, 0x0a, 0x0b, 0x46, 0x49, 0x42, 0x4b, 0x45, 0x4a, 0x47, 0x4b, 0x41,
	0x4e, 0x48, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x46, 0x49, 0x42, 0x4b, 0x45, 0x4a,
	0x47, 0x4b, 0x41, 0x4e, 0x48, 0x12, 0x2b, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x67, 0x65, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x49, 0x73, 0x6c, 0x61, 0x6e, 0x64, 0x50, 0x61, 0x72,
	0x74, 0x79, 0x53, 0x61, 0x69, 0x6c, 0x53, 0x74, 0x61, 0x67, 0x65, 0x52, 0x05, 0x73, 0x74, 0x61,
	0x67, 0x65, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_SceneGalleryIslandPartySailInfo_proto_rawDescOnce sync.Once
	file_SceneGalleryIslandPartySailInfo_proto_rawDescData = file_SceneGalleryIslandPartySailInfo_proto_rawDesc
)

func file_SceneGalleryIslandPartySailInfo_proto_rawDescGZIP() []byte {
	file_SceneGalleryIslandPartySailInfo_proto_rawDescOnce.Do(func() {
		file_SceneGalleryIslandPartySailInfo_proto_rawDescData = protoimpl.X.CompressGZIP(file_SceneGalleryIslandPartySailInfo_proto_rawDescData)
	})
	return file_SceneGalleryIslandPartySailInfo_proto_rawDescData
}

var file_SceneGalleryIslandPartySailInfo_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SceneGalleryIslandPartySailInfo_proto_goTypes = []interface{}{
	(*SceneGalleryIslandPartySailInfo)(nil), // 0: SceneGalleryIslandPartySailInfo
	(GalleryStartSource)(0),                 // 1: GalleryStartSource
	(IslandPartySailStage)(0),               // 2: IslandPartySailStage
}
var file_SceneGalleryIslandPartySailInfo_proto_depIdxs = []int32{
	1, // 0: SceneGalleryIslandPartySailInfo.start_source:type_name -> GalleryStartSource
	2, // 1: SceneGalleryIslandPartySailInfo.stage:type_name -> IslandPartySailStage
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_SceneGalleryIslandPartySailInfo_proto_init() }
func file_SceneGalleryIslandPartySailInfo_proto_init() {
	if File_SceneGalleryIslandPartySailInfo_proto != nil {
		return
	}
	file_GalleryStartSource_proto_init()
	file_IslandPartySailStage_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SceneGalleryIslandPartySailInfo_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SceneGalleryIslandPartySailInfo); i {
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
			RawDescriptor: file_SceneGalleryIslandPartySailInfo_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SceneGalleryIslandPartySailInfo_proto_goTypes,
		DependencyIndexes: file_SceneGalleryIslandPartySailInfo_proto_depIdxs,
		MessageInfos:      file_SceneGalleryIslandPartySailInfo_proto_msgTypes,
	}.Build()
	File_SceneGalleryIslandPartySailInfo_proto = out.File
	file_SceneGalleryIslandPartySailInfo_proto_rawDesc = nil
	file_SceneGalleryIslandPartySailInfo_proto_goTypes = nil
	file_SceneGalleryIslandPartySailInfo_proto_depIdxs = nil
}
