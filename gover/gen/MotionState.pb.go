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
// source: MotionState.proto

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

type MotionState int32

const (
	MotionState_MOTION_STATE_NONE                     MotionState = 0
	MotionState_MOTION_STATE_RESET                    MotionState = 1
	MotionState_MOTION_STATE_STANDBY                  MotionState = 2
	MotionState_MOTION_STATE_STANDBY_MOVE             MotionState = 3
	MotionState_MOTION_STATE_WALK                     MotionState = 4
	MotionState_MOTION_STATE_RUN                      MotionState = 5
	MotionState_MOTION_STATE_DASH                     MotionState = 6
	MotionState_MOTION_STATE_CLIMB                    MotionState = 7
	MotionState_MOTION_STATE_CLIMB_JUMP               MotionState = 8
	MotionState_MOTION_STATE_STANDBY_TO_CLIMB         MotionState = 9
	MotionState_MOTION_STATE_FIGHT                    MotionState = 10
	MotionState_MOTION_STATE_JUMP                     MotionState = 11
	MotionState_MOTION_STATE_DROP                     MotionState = 12
	MotionState_MOTION_STATE_FLY                      MotionState = 13
	MotionState_MOTION_STATE_SWIM_MOVE                MotionState = 14
	MotionState_MOTION_STATE_SWIM_IDLE                MotionState = 15
	MotionState_MOTION_STATE_SWIM_DASH                MotionState = 16
	MotionState_MOTION_STATE_SWIM_JUMP                MotionState = 17
	MotionState_MOTION_STATE_SLIP                     MotionState = 18
	MotionState_MOTION_STATE_GO_UPSTAIRS              MotionState = 19
	MotionState_MOTION_STATE_FALL_ON_GROUND           MotionState = 20
	MotionState_MOTION_STATE_JUMP_UP_WALL_FOR_STANDBY MotionState = 21
	MotionState_MOTION_STATE_JUMP_OFF_WALL            MotionState = 22
	MotionState_MOTION_STATE_POWERED_FLY              MotionState = 23
	MotionState_MOTION_STATE_LADDER_IDLE              MotionState = 24
	MotionState_MOTION_STATE_LADDER_MOVE              MotionState = 25
	MotionState_MOTION_STATE_LADDER_SLIP              MotionState = 26
	MotionState_MOTION_STATE_STANDBY_TO_LADDER        MotionState = 27
	MotionState_MOTION_STATE_LADDER_TO_STANDBY        MotionState = 28
	MotionState_MOTION_STATE_DANGER_STANDBY           MotionState = 29
	MotionState_MOTION_STATE_DANGER_STANDBY_MOVE      MotionState = 30
	MotionState_MOTION_STATE_DANGER_WALK              MotionState = 31
	MotionState_MOTION_STATE_DANGER_RUN               MotionState = 32
	MotionState_MOTION_STATE_DANGER_DASH              MotionState = 33
	MotionState_MOTION_STATE_CROUCH_IDLE              MotionState = 34
	MotionState_MOTION_STATE_CROUCH_MOVE              MotionState = 35
	MotionState_MOTION_STATE_CROUCH_ROLL              MotionState = 36
	MotionState_MOTION_STATE_NOTIFY                   MotionState = 37
	MotionState_MOTION_STATE_LAND_SPEED               MotionState = 38
	MotionState_MOTION_STATE_MOVE_FAIL_ACK            MotionState = 39
	MotionState_MOTION_STATE_WATERFALL                MotionState = 40
	MotionState_MOTION_STATE_DASH_BEFORE_SHAKE        MotionState = 41
	MotionState_MOTION_STATE_SIT_IDLE                 MotionState = 42
	MotionState_MOTION_STATE_FORCE_SET_POS            MotionState = 43
	MotionState_MOTION_STATE_QUEST_FORCE_DRAG         MotionState = 44
	MotionState_MOTION_STATE_FOLLOW_ROUTE             MotionState = 45
	MotionState_MOTION_STATE_SKIFF_BOARDING           MotionState = 46
	MotionState_MOTION_STATE_SKIFF_NORMAL             MotionState = 47
	MotionState_MOTION_STATE_SKIFF_DASH               MotionState = 48
	MotionState_MOTION_STATE_SKIFF_POWERED_DASH       MotionState = 49
	MotionState_MOTION_STATE_DESTROY_VEHICLE          MotionState = 50
	MotionState_MOTION_STATE_FLY_IDLE                 MotionState = 51
	MotionState_MOTION_STATE_FLY_SLOW                 MotionState = 52
	MotionState_MOTION_STATE_FLY_FAST                 MotionState = 53
	MotionState_MOTION_STATE_AIM_MOVE                 MotionState = 54
	MotionState_MOTION_STATE_AIR_COMPENSATION         MotionState = 55
	MotionState_MOTION_STATE_NUM                      MotionState = 56
)

// Enum value maps for MotionState.
var (
	MotionState_name = map[int32]string{
		0:  "MOTION_STATE_NONE",
		1:  "MOTION_STATE_RESET",
		2:  "MOTION_STATE_STANDBY",
		3:  "MOTION_STATE_STANDBY_MOVE",
		4:  "MOTION_STATE_WALK",
		5:  "MOTION_STATE_RUN",
		6:  "MOTION_STATE_DASH",
		7:  "MOTION_STATE_CLIMB",
		8:  "MOTION_STATE_CLIMB_JUMP",
		9:  "MOTION_STATE_STANDBY_TO_CLIMB",
		10: "MOTION_STATE_FIGHT",
		11: "MOTION_STATE_JUMP",
		12: "MOTION_STATE_DROP",
		13: "MOTION_STATE_FLY",
		14: "MOTION_STATE_SWIM_MOVE",
		15: "MOTION_STATE_SWIM_IDLE",
		16: "MOTION_STATE_SWIM_DASH",
		17: "MOTION_STATE_SWIM_JUMP",
		18: "MOTION_STATE_SLIP",
		19: "MOTION_STATE_GO_UPSTAIRS",
		20: "MOTION_STATE_FALL_ON_GROUND",
		21: "MOTION_STATE_JUMP_UP_WALL_FOR_STANDBY",
		22: "MOTION_STATE_JUMP_OFF_WALL",
		23: "MOTION_STATE_POWERED_FLY",
		24: "MOTION_STATE_LADDER_IDLE",
		25: "MOTION_STATE_LADDER_MOVE",
		26: "MOTION_STATE_LADDER_SLIP",
		27: "MOTION_STATE_STANDBY_TO_LADDER",
		28: "MOTION_STATE_LADDER_TO_STANDBY",
		29: "MOTION_STATE_DANGER_STANDBY",
		30: "MOTION_STATE_DANGER_STANDBY_MOVE",
		31: "MOTION_STATE_DANGER_WALK",
		32: "MOTION_STATE_DANGER_RUN",
		33: "MOTION_STATE_DANGER_DASH",
		34: "MOTION_STATE_CROUCH_IDLE",
		35: "MOTION_STATE_CROUCH_MOVE",
		36: "MOTION_STATE_CROUCH_ROLL",
		37: "MOTION_STATE_NOTIFY",
		38: "MOTION_STATE_LAND_SPEED",
		39: "MOTION_STATE_MOVE_FAIL_ACK",
		40: "MOTION_STATE_WATERFALL",
		41: "MOTION_STATE_DASH_BEFORE_SHAKE",
		42: "MOTION_STATE_SIT_IDLE",
		43: "MOTION_STATE_FORCE_SET_POS",
		44: "MOTION_STATE_QUEST_FORCE_DRAG",
		45: "MOTION_STATE_FOLLOW_ROUTE",
		46: "MOTION_STATE_SKIFF_BOARDING",
		47: "MOTION_STATE_SKIFF_NORMAL",
		48: "MOTION_STATE_SKIFF_DASH",
		49: "MOTION_STATE_SKIFF_POWERED_DASH",
		50: "MOTION_STATE_DESTROY_VEHICLE",
		51: "MOTION_STATE_FLY_IDLE",
		52: "MOTION_STATE_FLY_SLOW",
		53: "MOTION_STATE_FLY_FAST",
		54: "MOTION_STATE_AIM_MOVE",
		55: "MOTION_STATE_AIR_COMPENSATION",
		56: "MOTION_STATE_NUM",
	}
	MotionState_value = map[string]int32{
		"MOTION_STATE_NONE":                     0,
		"MOTION_STATE_RESET":                    1,
		"MOTION_STATE_STANDBY":                  2,
		"MOTION_STATE_STANDBY_MOVE":             3,
		"MOTION_STATE_WALK":                     4,
		"MOTION_STATE_RUN":                      5,
		"MOTION_STATE_DASH":                     6,
		"MOTION_STATE_CLIMB":                    7,
		"MOTION_STATE_CLIMB_JUMP":               8,
		"MOTION_STATE_STANDBY_TO_CLIMB":         9,
		"MOTION_STATE_FIGHT":                    10,
		"MOTION_STATE_JUMP":                     11,
		"MOTION_STATE_DROP":                     12,
		"MOTION_STATE_FLY":                      13,
		"MOTION_STATE_SWIM_MOVE":                14,
		"MOTION_STATE_SWIM_IDLE":                15,
		"MOTION_STATE_SWIM_DASH":                16,
		"MOTION_STATE_SWIM_JUMP":                17,
		"MOTION_STATE_SLIP":                     18,
		"MOTION_STATE_GO_UPSTAIRS":              19,
		"MOTION_STATE_FALL_ON_GROUND":           20,
		"MOTION_STATE_JUMP_UP_WALL_FOR_STANDBY": 21,
		"MOTION_STATE_JUMP_OFF_WALL":            22,
		"MOTION_STATE_POWERED_FLY":              23,
		"MOTION_STATE_LADDER_IDLE":              24,
		"MOTION_STATE_LADDER_MOVE":              25,
		"MOTION_STATE_LADDER_SLIP":              26,
		"MOTION_STATE_STANDBY_TO_LADDER":        27,
		"MOTION_STATE_LADDER_TO_STANDBY":        28,
		"MOTION_STATE_DANGER_STANDBY":           29,
		"MOTION_STATE_DANGER_STANDBY_MOVE":      30,
		"MOTION_STATE_DANGER_WALK":              31,
		"MOTION_STATE_DANGER_RUN":               32,
		"MOTION_STATE_DANGER_DASH":              33,
		"MOTION_STATE_CROUCH_IDLE":              34,
		"MOTION_STATE_CROUCH_MOVE":              35,
		"MOTION_STATE_CROUCH_ROLL":              36,
		"MOTION_STATE_NOTIFY":                   37,
		"MOTION_STATE_LAND_SPEED":               38,
		"MOTION_STATE_MOVE_FAIL_ACK":            39,
		"MOTION_STATE_WATERFALL":                40,
		"MOTION_STATE_DASH_BEFORE_SHAKE":        41,
		"MOTION_STATE_SIT_IDLE":                 42,
		"MOTION_STATE_FORCE_SET_POS":            43,
		"MOTION_STATE_QUEST_FORCE_DRAG":         44,
		"MOTION_STATE_FOLLOW_ROUTE":             45,
		"MOTION_STATE_SKIFF_BOARDING":           46,
		"MOTION_STATE_SKIFF_NORMAL":             47,
		"MOTION_STATE_SKIFF_DASH":               48,
		"MOTION_STATE_SKIFF_POWERED_DASH":       49,
		"MOTION_STATE_DESTROY_VEHICLE":          50,
		"MOTION_STATE_FLY_IDLE":                 51,
		"MOTION_STATE_FLY_SLOW":                 52,
		"MOTION_STATE_FLY_FAST":                 53,
		"MOTION_STATE_AIM_MOVE":                 54,
		"MOTION_STATE_AIR_COMPENSATION":         55,
		"MOTION_STATE_NUM":                      56,
	}
)

func (x MotionState) Enum() *MotionState {
	p := new(MotionState)
	*p = x
	return p
}

func (x MotionState) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (MotionState) Descriptor() protoreflect.EnumDescriptor {
	return file_MotionState_proto_enumTypes[0].Descriptor()
}

func (MotionState) Type() protoreflect.EnumType {
	return &file_MotionState_proto_enumTypes[0]
}

func (x MotionState) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use MotionState.Descriptor instead.
func (MotionState) EnumDescriptor() ([]byte, []int) {
	return file_MotionState_proto_rawDescGZIP(), []int{0}
}

var File_MotionState_proto protoreflect.FileDescriptor

var file_MotionState_proto_rawDesc = []byte{
	0x0a, 0x11, 0x4d, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2a, 0x94, 0x0d, 0x0a, 0x0b, 0x4d, 0x6f, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x12, 0x15, 0x0a, 0x11, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x16, 0x0a, 0x12, 0x4d, 0x4f,
	0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x52, 0x45, 0x53, 0x45, 0x54,
	0x10, 0x01, 0x12, 0x18, 0x0a, 0x14, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x53, 0x54, 0x41, 0x4e, 0x44, 0x42, 0x59, 0x10, 0x02, 0x12, 0x1d, 0x0a, 0x19,
	0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x53, 0x54, 0x41,
	0x4e, 0x44, 0x42, 0x59, 0x5f, 0x4d, 0x4f, 0x56, 0x45, 0x10, 0x03, 0x12, 0x15, 0x0a, 0x11, 0x4d,
	0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x57, 0x41, 0x4c, 0x4b,
	0x10, 0x04, 0x12, 0x14, 0x0a, 0x10, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x52, 0x55, 0x4e, 0x10, 0x05, 0x12, 0x15, 0x0a, 0x11, 0x4d, 0x4f, 0x54, 0x49,
	0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x41, 0x53, 0x48, 0x10, 0x06, 0x12,
	0x16, 0x0a, 0x12, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f,
	0x43, 0x4c, 0x49, 0x4d, 0x42, 0x10, 0x07, 0x12, 0x1b, 0x0a, 0x17, 0x4d, 0x4f, 0x54, 0x49, 0x4f,
	0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x43, 0x4c, 0x49, 0x4d, 0x42, 0x5f, 0x4a, 0x55,
	0x4d, 0x50, 0x10, 0x08, 0x12, 0x21, 0x0a, 0x1d, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x53, 0x54, 0x41, 0x4e, 0x44, 0x42, 0x59, 0x5f, 0x54, 0x4f, 0x5f,
	0x43, 0x4c, 0x49, 0x4d, 0x42, 0x10, 0x09, 0x12, 0x16, 0x0a, 0x12, 0x4d, 0x4f, 0x54, 0x49, 0x4f,
	0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x46, 0x49, 0x47, 0x48, 0x54, 0x10, 0x0a, 0x12,
	0x15, 0x0a, 0x11, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f,
	0x4a, 0x55, 0x4d, 0x50, 0x10, 0x0b, 0x12, 0x15, 0x0a, 0x11, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e,
	0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x52, 0x4f, 0x50, 0x10, 0x0c, 0x12, 0x14, 0x0a,
	0x10, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x46, 0x4c,
	0x59, 0x10, 0x0d, 0x12, 0x1a, 0x0a, 0x16, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x53, 0x57, 0x49, 0x4d, 0x5f, 0x4d, 0x4f, 0x56, 0x45, 0x10, 0x0e, 0x12,
	0x1a, 0x0a, 0x16, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f,
	0x53, 0x57, 0x49, 0x4d, 0x5f, 0x49, 0x44, 0x4c, 0x45, 0x10, 0x0f, 0x12, 0x1a, 0x0a, 0x16, 0x4d,
	0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x53, 0x57, 0x49, 0x4d,
	0x5f, 0x44, 0x41, 0x53, 0x48, 0x10, 0x10, 0x12, 0x1a, 0x0a, 0x16, 0x4d, 0x4f, 0x54, 0x49, 0x4f,
	0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x53, 0x57, 0x49, 0x4d, 0x5f, 0x4a, 0x55, 0x4d,
	0x50, 0x10, 0x11, 0x12, 0x15, 0x0a, 0x11, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x53, 0x4c, 0x49, 0x50, 0x10, 0x12, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4f,
	0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x47, 0x4f, 0x5f, 0x55, 0x50,
	0x53, 0x54, 0x41, 0x49, 0x52, 0x53, 0x10, 0x13, 0x12, 0x1f, 0x0a, 0x1b, 0x4d, 0x4f, 0x54, 0x49,
	0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x46, 0x41, 0x4c, 0x4c, 0x5f, 0x4f, 0x4e,
	0x5f, 0x47, 0x52, 0x4f, 0x55, 0x4e, 0x44, 0x10, 0x14, 0x12, 0x29, 0x0a, 0x25, 0x4d, 0x4f, 0x54,
	0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x4a, 0x55, 0x4d, 0x50, 0x5f, 0x55,
	0x50, 0x5f, 0x57, 0x41, 0x4c, 0x4c, 0x5f, 0x46, 0x4f, 0x52, 0x5f, 0x53, 0x54, 0x41, 0x4e, 0x44,
	0x42, 0x59, 0x10, 0x15, 0x12, 0x1e, 0x0a, 0x1a, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x4a, 0x55, 0x4d, 0x50, 0x5f, 0x4f, 0x46, 0x46, 0x5f, 0x57, 0x41,
	0x4c, 0x4c, 0x10, 0x16, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x50, 0x4f, 0x57, 0x45, 0x52, 0x45, 0x44, 0x5f, 0x46, 0x4c, 0x59,
	0x10, 0x17, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x4c, 0x41, 0x44, 0x44, 0x45, 0x52, 0x5f, 0x49, 0x44, 0x4c, 0x45, 0x10, 0x18,
	0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45,
	0x5f, 0x4c, 0x41, 0x44, 0x44, 0x45, 0x52, 0x5f, 0x4d, 0x4f, 0x56, 0x45, 0x10, 0x19, 0x12, 0x1c,
	0x0a, 0x18, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x4c,
	0x41, 0x44, 0x44, 0x45, 0x52, 0x5f, 0x53, 0x4c, 0x49, 0x50, 0x10, 0x1a, 0x12, 0x22, 0x0a, 0x1e,
	0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x53, 0x54, 0x41,
	0x4e, 0x44, 0x42, 0x59, 0x5f, 0x54, 0x4f, 0x5f, 0x4c, 0x41, 0x44, 0x44, 0x45, 0x52, 0x10, 0x1b,
	0x12, 0x22, 0x0a, 0x1e, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45,
	0x5f, 0x4c, 0x41, 0x44, 0x44, 0x45, 0x52, 0x5f, 0x54, 0x4f, 0x5f, 0x53, 0x54, 0x41, 0x4e, 0x44,
	0x42, 0x59, 0x10, 0x1c, 0x12, 0x1f, 0x0a, 0x1b, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x41, 0x4e, 0x47, 0x45, 0x52, 0x5f, 0x53, 0x54, 0x41, 0x4e,
	0x44, 0x42, 0x59, 0x10, 0x1d, 0x12, 0x24, 0x0a, 0x20, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f,
	0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x41, 0x4e, 0x47, 0x45, 0x52, 0x5f, 0x53, 0x54, 0x41,
	0x4e, 0x44, 0x42, 0x59, 0x5f, 0x4d, 0x4f, 0x56, 0x45, 0x10, 0x1e, 0x12, 0x1c, 0x0a, 0x18, 0x4d,
	0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x41, 0x4e, 0x47,
	0x45, 0x52, 0x5f, 0x57, 0x41, 0x4c, 0x4b, 0x10, 0x1f, 0x12, 0x1b, 0x0a, 0x17, 0x4d, 0x4f, 0x54,
	0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x41, 0x4e, 0x47, 0x45, 0x52,
	0x5f, 0x52, 0x55, 0x4e, 0x10, 0x20, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e,
	0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x44, 0x41, 0x4e, 0x47, 0x45, 0x52, 0x5f, 0x44, 0x41,
	0x53, 0x48, 0x10, 0x21, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x43, 0x52, 0x4f, 0x55, 0x43, 0x48, 0x5f, 0x49, 0x44, 0x4c, 0x45,
	0x10, 0x22, 0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x43, 0x52, 0x4f, 0x55, 0x43, 0x48, 0x5f, 0x4d, 0x4f, 0x56, 0x45, 0x10, 0x23,
	0x12, 0x1c, 0x0a, 0x18, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45,
	0x5f, 0x43, 0x52, 0x4f, 0x55, 0x43, 0x48, 0x5f, 0x52, 0x4f, 0x4c, 0x4c, 0x10, 0x24, 0x12, 0x17,
	0x0a, 0x13, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x4e,
	0x4f, 0x54, 0x49, 0x46, 0x59, 0x10, 0x25, 0x12, 0x1b, 0x0a, 0x17, 0x4d, 0x4f, 0x54, 0x49, 0x4f,
	0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x4c, 0x41, 0x4e, 0x44, 0x5f, 0x53, 0x50, 0x45,
	0x45, 0x44, 0x10, 0x26, 0x12, 0x1e, 0x0a, 0x1a, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x4d, 0x4f, 0x56, 0x45, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x5f, 0x41,
	0x43, 0x4b, 0x10, 0x27, 0x12, 0x1a, 0x0a, 0x16, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x57, 0x41, 0x54, 0x45, 0x52, 0x46, 0x41, 0x4c, 0x4c, 0x10, 0x28,
	0x12, 0x22, 0x0a, 0x1e, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45,
	0x5f, 0x44, 0x41, 0x53, 0x48, 0x5f, 0x42, 0x45, 0x46, 0x4f, 0x52, 0x45, 0x5f, 0x53, 0x48, 0x41,
	0x4b, 0x45, 0x10, 0x29, 0x12, 0x19, 0x0a, 0x15, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x53, 0x49, 0x54, 0x5f, 0x49, 0x44, 0x4c, 0x45, 0x10, 0x2a, 0x12,
	0x1e, 0x0a, 0x1a, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f,
	0x46, 0x4f, 0x52, 0x43, 0x45, 0x5f, 0x53, 0x45, 0x54, 0x5f, 0x50, 0x4f, 0x53, 0x10, 0x2b, 0x12,
	0x21, 0x0a, 0x1d, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f,
	0x51, 0x55, 0x45, 0x53, 0x54, 0x5f, 0x46, 0x4f, 0x52, 0x43, 0x45, 0x5f, 0x44, 0x52, 0x41, 0x47,
	0x10, 0x2c, 0x12, 0x1d, 0x0a, 0x19, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x46, 0x4f, 0x4c, 0x4c, 0x4f, 0x57, 0x5f, 0x52, 0x4f, 0x55, 0x54, 0x45, 0x10,
	0x2d, 0x12, 0x1f, 0x0a, 0x1b, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54,
	0x45, 0x5f, 0x53, 0x4b, 0x49, 0x46, 0x46, 0x5f, 0x42, 0x4f, 0x41, 0x52, 0x44, 0x49, 0x4e, 0x47,
	0x10, 0x2e, 0x12, 0x1d, 0x0a, 0x19, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41,
	0x54, 0x45, 0x5f, 0x53, 0x4b, 0x49, 0x46, 0x46, 0x5f, 0x4e, 0x4f, 0x52, 0x4d, 0x41, 0x4c, 0x10,
	0x2f, 0x12, 0x1b, 0x0a, 0x17, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54,
	0x45, 0x5f, 0x53, 0x4b, 0x49, 0x46, 0x46, 0x5f, 0x44, 0x41, 0x53, 0x48, 0x10, 0x30, 0x12, 0x23,
	0x0a, 0x1f, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x53,
	0x4b, 0x49, 0x46, 0x46, 0x5f, 0x50, 0x4f, 0x57, 0x45, 0x52, 0x45, 0x44, 0x5f, 0x44, 0x41, 0x53,
	0x48, 0x10, 0x31, 0x12, 0x20, 0x0a, 0x1c, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54,
	0x41, 0x54, 0x45, 0x5f, 0x44, 0x45, 0x53, 0x54, 0x52, 0x4f, 0x59, 0x5f, 0x56, 0x45, 0x48, 0x49,
	0x43, 0x4c, 0x45, 0x10, 0x32, 0x12, 0x19, 0x0a, 0x15, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f,
	0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x46, 0x4c, 0x59, 0x5f, 0x49, 0x44, 0x4c, 0x45, 0x10, 0x33,
	0x12, 0x19, 0x0a, 0x15, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45,
	0x5f, 0x46, 0x4c, 0x59, 0x5f, 0x53, 0x4c, 0x4f, 0x57, 0x10, 0x34, 0x12, 0x19, 0x0a, 0x15, 0x4d,
	0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x46, 0x4c, 0x59, 0x5f,
	0x46, 0x41, 0x53, 0x54, 0x10, 0x35, 0x12, 0x19, 0x0a, 0x15, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e,
	0x5f, 0x53, 0x54, 0x41, 0x54, 0x45, 0x5f, 0x41, 0x49, 0x4d, 0x5f, 0x4d, 0x4f, 0x56, 0x45, 0x10,
	0x36, 0x12, 0x21, 0x0a, 0x1d, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x41, 0x54,
	0x45, 0x5f, 0x41, 0x49, 0x52, 0x5f, 0x43, 0x4f, 0x4d, 0x50, 0x45, 0x4e, 0x53, 0x41, 0x54, 0x49,
	0x4f, 0x4e, 0x10, 0x37, 0x12, 0x14, 0x0a, 0x10, 0x4d, 0x4f, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53,
	0x54, 0x41, 0x54, 0x45, 0x5f, 0x4e, 0x55, 0x4d, 0x10, 0x38, 0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67,
	0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_MotionState_proto_rawDescOnce sync.Once
	file_MotionState_proto_rawDescData = file_MotionState_proto_rawDesc
)

func file_MotionState_proto_rawDescGZIP() []byte {
	file_MotionState_proto_rawDescOnce.Do(func() {
		file_MotionState_proto_rawDescData = protoimpl.X.CompressGZIP(file_MotionState_proto_rawDescData)
	})
	return file_MotionState_proto_rawDescData
}

var file_MotionState_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_MotionState_proto_goTypes = []interface{}{
	(MotionState)(0), // 0: MotionState
}
var file_MotionState_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_MotionState_proto_init() }
func file_MotionState_proto_init() {
	if File_MotionState_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_MotionState_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_MotionState_proto_goTypes,
		DependencyIndexes: file_MotionState_proto_depIdxs,
		EnumInfos:         file_MotionState_proto_enumTypes,
	}.Build()
	File_MotionState_proto = out.File
	file_MotionState_proto_rawDesc = nil
	file_MotionState_proto_goTypes = nil
	file_MotionState_proto_depIdxs = nil
}
