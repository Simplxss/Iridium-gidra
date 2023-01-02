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
// source: DungeonCandidateTeamPlayerDismissReason.proto

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

type DungeonCandidateTeamPlayerDismissReason int32

const (
	DungeonCandidateTeamPlayerDismissReason_DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_NORMAL     DungeonCandidateTeamPlayerDismissReason = 0
	DungeonCandidateTeamPlayerDismissReason_DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_DIE        DungeonCandidateTeamPlayerDismissReason = 1
	DungeonCandidateTeamPlayerDismissReason_DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_DISCONNECT DungeonCandidateTeamPlayerDismissReason = 2
)

// Enum value maps for DungeonCandidateTeamPlayerDismissReason.
var (
	DungeonCandidateTeamPlayerDismissReason_name = map[int32]string{
		0: "DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_NORMAL",
		1: "DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_DIE",
		2: "DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_DISCONNECT",
	}
	DungeonCandidateTeamPlayerDismissReason_value = map[string]int32{
		"DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_NORMAL":     0,
		"DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_DIE":        1,
		"DUNGEON_CANDIDATE_TEAM_PLAYER_DISMISS_REASON_TPDR_DISCONNECT": 2,
	}
)

func (x DungeonCandidateTeamPlayerDismissReason) Enum() *DungeonCandidateTeamPlayerDismissReason {
	p := new(DungeonCandidateTeamPlayerDismissReason)
	*p = x
	return p
}

func (x DungeonCandidateTeamPlayerDismissReason) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DungeonCandidateTeamPlayerDismissReason) Descriptor() protoreflect.EnumDescriptor {
	return file_DungeonCandidateTeamPlayerDismissReason_proto_enumTypes[0].Descriptor()
}

func (DungeonCandidateTeamPlayerDismissReason) Type() protoreflect.EnumType {
	return &file_DungeonCandidateTeamPlayerDismissReason_proto_enumTypes[0]
}

func (x DungeonCandidateTeamPlayerDismissReason) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DungeonCandidateTeamPlayerDismissReason.Descriptor instead.
func (DungeonCandidateTeamPlayerDismissReason) EnumDescriptor() ([]byte, []int) {
	return file_DungeonCandidateTeamPlayerDismissReason_proto_rawDescGZIP(), []int{0}
}

var File_DungeonCandidateTeamPlayerDismissReason_proto protoreflect.FileDescriptor

var file_DungeonCandidateTeamPlayerDismissReason_proto_rawDesc = []byte{
	0x0a, 0x2d, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x44, 0x69, 0x73, 0x6d,
	0x69, 0x73, 0x73, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2a,
	0xe4, 0x01, 0x0a, 0x27, 0x44, 0x75, 0x6e, 0x67, 0x65, 0x6f, 0x6e, 0x43, 0x61, 0x6e, 0x64, 0x69,
	0x64, 0x61, 0x74, 0x65, 0x54, 0x65, 0x61, 0x6d, 0x50, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x44, 0x69,
	0x73, 0x6d, 0x69, 0x73, 0x73, 0x52, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x3c, 0x0a, 0x38, 0x44,
	0x55, 0x4e, 0x47, 0x45, 0x4f, 0x4e, 0x5f, 0x43, 0x41, 0x4e, 0x44, 0x49, 0x44, 0x41, 0x54, 0x45,
	0x5f, 0x54, 0x45, 0x41, 0x4d, 0x5f, 0x50, 0x4c, 0x41, 0x59, 0x45, 0x52, 0x5f, 0x44, 0x49, 0x53,
	0x4d, 0x49, 0x53, 0x53, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x54, 0x50, 0x44, 0x52,
	0x5f, 0x4e, 0x4f, 0x52, 0x4d, 0x41, 0x4c, 0x10, 0x00, 0x12, 0x39, 0x0a, 0x35, 0x44, 0x55, 0x4e,
	0x47, 0x45, 0x4f, 0x4e, 0x5f, 0x43, 0x41, 0x4e, 0x44, 0x49, 0x44, 0x41, 0x54, 0x45, 0x5f, 0x54,
	0x45, 0x41, 0x4d, 0x5f, 0x50, 0x4c, 0x41, 0x59, 0x45, 0x52, 0x5f, 0x44, 0x49, 0x53, 0x4d, 0x49,
	0x53, 0x53, 0x5f, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x54, 0x50, 0x44, 0x52, 0x5f, 0x44,
	0x49, 0x45, 0x10, 0x01, 0x12, 0x40, 0x0a, 0x3c, 0x44, 0x55, 0x4e, 0x47, 0x45, 0x4f, 0x4e, 0x5f,
	0x43, 0x41, 0x4e, 0x44, 0x49, 0x44, 0x41, 0x54, 0x45, 0x5f, 0x54, 0x45, 0x41, 0x4d, 0x5f, 0x50,
	0x4c, 0x41, 0x59, 0x45, 0x52, 0x5f, 0x44, 0x49, 0x53, 0x4d, 0x49, 0x53, 0x53, 0x5f, 0x52, 0x45,
	0x41, 0x53, 0x4f, 0x4e, 0x5f, 0x54, 0x50, 0x44, 0x52, 0x5f, 0x44, 0x49, 0x53, 0x43, 0x4f, 0x4e,
	0x4e, 0x45, 0x43, 0x54, 0x10, 0x02, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_DungeonCandidateTeamPlayerDismissReason_proto_rawDescOnce sync.Once
	file_DungeonCandidateTeamPlayerDismissReason_proto_rawDescData = file_DungeonCandidateTeamPlayerDismissReason_proto_rawDesc
)

func file_DungeonCandidateTeamPlayerDismissReason_proto_rawDescGZIP() []byte {
	file_DungeonCandidateTeamPlayerDismissReason_proto_rawDescOnce.Do(func() {
		file_DungeonCandidateTeamPlayerDismissReason_proto_rawDescData = protoimpl.X.CompressGZIP(file_DungeonCandidateTeamPlayerDismissReason_proto_rawDescData)
	})
	return file_DungeonCandidateTeamPlayerDismissReason_proto_rawDescData
}

var file_DungeonCandidateTeamPlayerDismissReason_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_DungeonCandidateTeamPlayerDismissReason_proto_goTypes = []interface{}{
	(DungeonCandidateTeamPlayerDismissReason)(0), // 0: DungeonCandidateTeamPlayerDismissReason
}
var file_DungeonCandidateTeamPlayerDismissReason_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_DungeonCandidateTeamPlayerDismissReason_proto_init() }
func file_DungeonCandidateTeamPlayerDismissReason_proto_init() {
	if File_DungeonCandidateTeamPlayerDismissReason_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_DungeonCandidateTeamPlayerDismissReason_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_DungeonCandidateTeamPlayerDismissReason_proto_goTypes,
		DependencyIndexes: file_DungeonCandidateTeamPlayerDismissReason_proto_depIdxs,
		EnumInfos:         file_DungeonCandidateTeamPlayerDismissReason_proto_enumTypes,
	}.Build()
	File_DungeonCandidateTeamPlayerDismissReason_proto = out.File
	file_DungeonCandidateTeamPlayerDismissReason_proto_rawDesc = nil
	file_DungeonCandidateTeamPlayerDismissReason_proto_goTypes = nil
	file_DungeonCandidateTeamPlayerDismissReason_proto_depIdxs = nil
}
