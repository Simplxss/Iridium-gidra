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
// source: GalleryStopReason.proto

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

type GalleryStopReason int32

const (
	GalleryStopReason_GALLERY_STOP_REASON_NONE                  GalleryStopReason = 0
	GalleryStopReason_GALLERY_STOP_REASON_TIMEUP                GalleryStopReason = 1
	GalleryStopReason_GALLERY_STOP_REASON_CLIENT_INTERRUPT      GalleryStopReason = 2
	GalleryStopReason_GALLERY_STOP_REASON_LUA_INTERRUPT_SUCCESS GalleryStopReason = 3
	GalleryStopReason_GALLERY_STOP_REASON_LUA_INTERRUPT_FAIL    GalleryStopReason = 4
	GalleryStopReason_GALLERY_STOP_REASON_OWNER_LEAVE_SCENE     GalleryStopReason = 5
	GalleryStopReason_GALLERY_STOP_REASON_PLAY_INIT_FAILED      GalleryStopReason = 6
	GalleryStopReason_GALLERY_STOP_REASON_OTHER_PLAYER_ENTER    GalleryStopReason = 7
	GalleryStopReason_GALLERY_STOP_REASON_AVATAR_DIE            GalleryStopReason = 8
	GalleryStopReason_GALLERY_STOP_REASON_FINISHED              GalleryStopReason = 9
	GalleryStopReason_GALLERY_STOP_REASON_FUNGUS_ALL_DIE        GalleryStopReason = 10
	GalleryStopReason_GALLERY_STOP_REASON_LIFE_COUNT_ZERO       GalleryStopReason = 11
	GalleryStopReason_GALLERY_STOP_REASON_Unk3300_DFPLGCGIIDM   GalleryStopReason = 12
)

// Enum value maps for GalleryStopReason.
var (
	GalleryStopReason_name = map[int32]string{
		0:  "GALLERY_STOP_REASON_NONE",
		1:  "GALLERY_STOP_REASON_TIMEUP",
		2:  "GALLERY_STOP_REASON_CLIENT_INTERRUPT",
		3:  "GALLERY_STOP_REASON_LUA_INTERRUPT_SUCCESS",
		4:  "GALLERY_STOP_REASON_LUA_INTERRUPT_FAIL",
		5:  "GALLERY_STOP_REASON_OWNER_LEAVE_SCENE",
		6:  "GALLERY_STOP_REASON_PLAY_INIT_FAILED",
		7:  "GALLERY_STOP_REASON_OTHER_PLAYER_ENTER",
		8:  "GALLERY_STOP_REASON_AVATAR_DIE",
		9:  "GALLERY_STOP_REASON_FINISHED",
		10: "GALLERY_STOP_REASON_FUNGUS_ALL_DIE",
		11: "GALLERY_STOP_REASON_LIFE_COUNT_ZERO",
		12: "GALLERY_STOP_REASON_Unk3300_DFPLGCGIIDM",
	}
	GalleryStopReason_value = map[string]int32{
		"GALLERY_STOP_REASON_NONE":                  0,
		"GALLERY_STOP_REASON_TIMEUP":                1,
		"GALLERY_STOP_REASON_CLIENT_INTERRUPT":      2,
		"GALLERY_STOP_REASON_LUA_INTERRUPT_SUCCESS": 3,
		"GALLERY_STOP_REASON_LUA_INTERRUPT_FAIL":    4,
		"GALLERY_STOP_REASON_OWNER_LEAVE_SCENE":     5,
		"GALLERY_STOP_REASON_PLAY_INIT_FAILED":      6,
		"GALLERY_STOP_REASON_OTHER_PLAYER_ENTER":    7,
		"GALLERY_STOP_REASON_AVATAR_DIE":            8,
		"GALLERY_STOP_REASON_FINISHED":              9,
		"GALLERY_STOP_REASON_FUNGUS_ALL_DIE":        10,
		"GALLERY_STOP_REASON_LIFE_COUNT_ZERO":       11,
		"GALLERY_STOP_REASON_Unk3300_DFPLGCGIIDM":   12,
	}
)

func (x GalleryStopReason) Enum() *GalleryStopReason {
	p := new(GalleryStopReason)
	*p = x
	return p
}

func (x GalleryStopReason) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (GalleryStopReason) Descriptor() protoreflect.EnumDescriptor {
	return file_GalleryStopReason_proto_enumTypes[0].Descriptor()
}

func (GalleryStopReason) Type() protoreflect.EnumType {
	return &file_GalleryStopReason_proto_enumTypes[0]
}

func (x GalleryStopReason) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use GalleryStopReason.Descriptor instead.
func (GalleryStopReason) EnumDescriptor() ([]byte, []int) {
	return file_GalleryStopReason_proto_rawDescGZIP(), []int{0}
}

var File_GalleryStopReason_proto protoreflect.FileDescriptor

var file_GalleryStopReason_proto_rawDesc = []byte{
	0x0a, 0x17, 0x47, 0x61, 0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x61,
	0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a, 0x9b, 0x04, 0x0a, 0x11, 0x47, 0x61,
	0x6c, 0x6c, 0x65, 0x72, 0x79, 0x53, 0x74, 0x6f, 0x70, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12,
	0x1c, 0x0a, 0x18, 0x47, 0x41, 0x4c, 0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f,
	0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x1e, 0x0a,
	0x1a, 0x47, 0x41, 0x4c, 0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45,
	0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x54, 0x49, 0x4d, 0x45, 0x55, 0x50, 0x10, 0x01, 0x12, 0x28, 0x0a,
	0x24, 0x47, 0x41, 0x4c, 0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45,
	0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x43, 0x4c, 0x49, 0x45, 0x4e, 0x54, 0x5f, 0x49, 0x4e, 0x54, 0x45,
	0x52, 0x52, 0x55, 0x50, 0x54, 0x10, 0x02, 0x12, 0x2d, 0x0a, 0x29, 0x47, 0x41, 0x4c, 0x4c, 0x45,
	0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x4c,
	0x55, 0x41, 0x5f, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x52, 0x55, 0x50, 0x54, 0x5f, 0x53, 0x55, 0x43,
	0x43, 0x45, 0x53, 0x53, 0x10, 0x03, 0x12, 0x2a, 0x0a, 0x26, 0x47, 0x41, 0x4c, 0x4c, 0x45, 0x52,
	0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x4c, 0x55,
	0x41, 0x5f, 0x49, 0x4e, 0x54, 0x45, 0x52, 0x52, 0x55, 0x50, 0x54, 0x5f, 0x46, 0x41, 0x49, 0x4c,
	0x10, 0x04, 0x12, 0x29, 0x0a, 0x25, 0x47, 0x41, 0x4c, 0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53, 0x54,
	0x4f, 0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x4f, 0x57, 0x4e, 0x45, 0x52, 0x5f,
	0x4c, 0x45, 0x41, 0x56, 0x45, 0x5f, 0x53, 0x43, 0x45, 0x4e, 0x45, 0x10, 0x05, 0x12, 0x28, 0x0a,
	0x24, 0x47, 0x41, 0x4c, 0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45,
	0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x50, 0x4c, 0x41, 0x59, 0x5f, 0x49, 0x4e, 0x49, 0x54, 0x5f, 0x46,
	0x41, 0x49, 0x4c, 0x45, 0x44, 0x10, 0x06, 0x12, 0x2a, 0x0a, 0x26, 0x47, 0x41, 0x4c, 0x4c, 0x45,
	0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x4f,
	0x54, 0x48, 0x45, 0x52, 0x5f, 0x50, 0x4c, 0x41, 0x59, 0x45, 0x52, 0x5f, 0x45, 0x4e, 0x54, 0x45,
	0x52, 0x10, 0x07, 0x12, 0x22, 0x0a, 0x1e, 0x47, 0x41, 0x4c, 0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53,
	0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x41, 0x56, 0x41, 0x54, 0x41,
	0x52, 0x5f, 0x44, 0x49, 0x45, 0x10, 0x08, 0x12, 0x20, 0x0a, 0x1c, 0x47, 0x41, 0x4c, 0x4c, 0x45,
	0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x46,
	0x49, 0x4e, 0x49, 0x53, 0x48, 0x45, 0x44, 0x10, 0x09, 0x12, 0x26, 0x0a, 0x22, 0x47, 0x41, 0x4c,
	0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e,
	0x5f, 0x46, 0x55, 0x4e, 0x47, 0x55, 0x53, 0x5f, 0x41, 0x4c, 0x4c, 0x5f, 0x44, 0x49, 0x45, 0x10,
	0x0a, 0x12, 0x27, 0x0a, 0x23, 0x47, 0x41, 0x4c, 0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f,
	0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x4c, 0x49, 0x46, 0x45, 0x5f, 0x43, 0x4f,
	0x55, 0x4e, 0x54, 0x5f, 0x5a, 0x45, 0x52, 0x4f, 0x10, 0x0b, 0x12, 0x2b, 0x0a, 0x27, 0x47, 0x41,
	0x4c, 0x4c, 0x45, 0x52, 0x59, 0x5f, 0x53, 0x54, 0x4f, 0x50, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f,
	0x4e, 0x5f, 0x55, 0x6e, 0x6b, 0x33, 0x33, 0x30, 0x30, 0x5f, 0x44, 0x46, 0x50, 0x4c, 0x47, 0x43,
	0x47, 0x49, 0x49, 0x44, 0x4d, 0x10, 0x0c, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_GalleryStopReason_proto_rawDescOnce sync.Once
	file_GalleryStopReason_proto_rawDescData = file_GalleryStopReason_proto_rawDesc
)

func file_GalleryStopReason_proto_rawDescGZIP() []byte {
	file_GalleryStopReason_proto_rawDescOnce.Do(func() {
		file_GalleryStopReason_proto_rawDescData = protoimpl.X.CompressGZIP(file_GalleryStopReason_proto_rawDescData)
	})
	return file_GalleryStopReason_proto_rawDescData
}

var file_GalleryStopReason_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_GalleryStopReason_proto_goTypes = []interface{}{
	(GalleryStopReason)(0), // 0: GalleryStopReason
}
var file_GalleryStopReason_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_GalleryStopReason_proto_init() }
func file_GalleryStopReason_proto_init() {
	if File_GalleryStopReason_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_GalleryStopReason_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_GalleryStopReason_proto_goTypes,
		DependencyIndexes: file_GalleryStopReason_proto_depIdxs,
		EnumInfos:         file_GalleryStopReason_proto_enumTypes,
	}.Build()
	File_GalleryStopReason_proto = out.File
	file_GalleryStopReason_proto_rawDesc = nil
	file_GalleryStopReason_proto_goTypes = nil
	file_GalleryStopReason_proto_depIdxs = nil
}
