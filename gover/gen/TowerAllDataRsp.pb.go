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
// source: TowerAllDataRsp.proto

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

// CmdId: 3897
// Obf: BDPBFJJNCKK
type TowerAllDataRsp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IsFinishedEntranceFloor       bool                 `protobuf:"varint,12,opt,name=is_finished_entrance_floor,json=isFinishedEntranceFloor,proto3" json:"is_finished_entrance_floor,omitempty"`
	ScheduleStartTime             uint32               `protobuf:"varint,1168,opt,name=schedule_start_time,json=scheduleStartTime,proto3" json:"schedule_start_time,omitempty"`
	FEOKMKFLOFI                   uint32               `protobuf:"varint,6,opt,name=FEOKMKFLOFI,proto3" json:"FEOKMKFLOFI,omitempty"`
	CFHPLJKKOFG                   uint32               `protobuf:"varint,15,opt,name=CFHPLJKKOFG,proto3" json:"CFHPLJKKOFG,omitempty"`
	NFLJLHDCPFJ                   uint32               `protobuf:"varint,5,opt,name=NFLJLHDCPFJ,proto3" json:"NFLJLHDCPFJ,omitempty"`
	TowerFloorRecordList          []*TowerFloorRecord  `protobuf:"bytes,14,rep,name=tower_floor_record_list,json=towerFloorRecordList,proto3" json:"tower_floor_record_list,omitempty"`
	JJJCPHMBMLG                   uint32               `protobuf:"varint,9,opt,name=JJJCPHMBMLG,proto3" json:"JJJCPHMBMLG,omitempty"`
	IsFirstInteract               bool                 `protobuf:"varint,7,opt,name=is_first_interact,json=isFirstInteract,proto3" json:"is_first_interact,omitempty"`
	CurLevelRecord                *TowerCurLevelRecord `protobuf:"bytes,10,opt,name=cur_level_record,json=curLevelRecord,proto3" json:"cur_level_record,omitempty"`
	LastScheduleMonthlyBrief      *TowerMonthlyBrief   `protobuf:"bytes,4,opt,name=last_schedule_monthly_brief,json=lastScheduleMonthlyBrief,proto3" json:"last_schedule_monthly_brief,omitempty"`
	FloorOpenTimeMap              map[uint32]uint32    `protobuf:"bytes,13,rep,name=floor_open_time_map,json=floorOpenTimeMap,proto3" json:"floor_open_time_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	MonthlyBrief                  *TowerMonthlyBrief   `protobuf:"bytes,120,opt,name=monthly_brief,json=monthlyBrief,proto3" json:"monthly_brief,omitempty"`
	NextScheduleChangeTime        uint32               `protobuf:"varint,11,opt,name=next_schedule_change_time,json=nextScheduleChangeTime,proto3" json:"next_schedule_change_time,omitempty"`
	TowerScheduleId               uint32               `protobuf:"varint,3,opt,name=tower_schedule_id,json=towerScheduleId,proto3" json:"tower_schedule_id,omitempty"`
	SkipFloorGrantedRewardItemMap map[uint32]uint32    `protobuf:"bytes,8,rep,name=skip_floor_granted_reward_item_map,json=skipFloorGrantedRewardItemMap,proto3" json:"skip_floor_granted_reward_item_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	Retcode                       int32                `protobuf:"varint,2,opt,name=retcode,proto3" json:"retcode,omitempty"`
	MOOJNLEAKFC                   uint32               `protobuf:"varint,1,opt,name=MOOJNLEAKFC,proto3" json:"MOOJNLEAKFC,omitempty"`
}

func (x *TowerAllDataRsp) Reset() {
	*x = TowerAllDataRsp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_TowerAllDataRsp_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TowerAllDataRsp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TowerAllDataRsp) ProtoMessage() {}

func (x *TowerAllDataRsp) ProtoReflect() protoreflect.Message {
	mi := &file_TowerAllDataRsp_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TowerAllDataRsp.ProtoReflect.Descriptor instead.
func (*TowerAllDataRsp) Descriptor() ([]byte, []int) {
	return file_TowerAllDataRsp_proto_rawDescGZIP(), []int{0}
}

func (x *TowerAllDataRsp) GetIsFinishedEntranceFloor() bool {
	if x != nil {
		return x.IsFinishedEntranceFloor
	}
	return false
}

func (x *TowerAllDataRsp) GetScheduleStartTime() uint32 {
	if x != nil {
		return x.ScheduleStartTime
	}
	return 0
}

func (x *TowerAllDataRsp) GetFEOKMKFLOFI() uint32 {
	if x != nil {
		return x.FEOKMKFLOFI
	}
	return 0
}

func (x *TowerAllDataRsp) GetCFHPLJKKOFG() uint32 {
	if x != nil {
		return x.CFHPLJKKOFG
	}
	return 0
}

func (x *TowerAllDataRsp) GetNFLJLHDCPFJ() uint32 {
	if x != nil {
		return x.NFLJLHDCPFJ
	}
	return 0
}

func (x *TowerAllDataRsp) GetTowerFloorRecordList() []*TowerFloorRecord {
	if x != nil {
		return x.TowerFloorRecordList
	}
	return nil
}

func (x *TowerAllDataRsp) GetJJJCPHMBMLG() uint32 {
	if x != nil {
		return x.JJJCPHMBMLG
	}
	return 0
}

func (x *TowerAllDataRsp) GetIsFirstInteract() bool {
	if x != nil {
		return x.IsFirstInteract
	}
	return false
}

func (x *TowerAllDataRsp) GetCurLevelRecord() *TowerCurLevelRecord {
	if x != nil {
		return x.CurLevelRecord
	}
	return nil
}

func (x *TowerAllDataRsp) GetLastScheduleMonthlyBrief() *TowerMonthlyBrief {
	if x != nil {
		return x.LastScheduleMonthlyBrief
	}
	return nil
}

func (x *TowerAllDataRsp) GetFloorOpenTimeMap() map[uint32]uint32 {
	if x != nil {
		return x.FloorOpenTimeMap
	}
	return nil
}

func (x *TowerAllDataRsp) GetMonthlyBrief() *TowerMonthlyBrief {
	if x != nil {
		return x.MonthlyBrief
	}
	return nil
}

func (x *TowerAllDataRsp) GetNextScheduleChangeTime() uint32 {
	if x != nil {
		return x.NextScheduleChangeTime
	}
	return 0
}

func (x *TowerAllDataRsp) GetTowerScheduleId() uint32 {
	if x != nil {
		return x.TowerScheduleId
	}
	return 0
}

func (x *TowerAllDataRsp) GetSkipFloorGrantedRewardItemMap() map[uint32]uint32 {
	if x != nil {
		return x.SkipFloorGrantedRewardItemMap
	}
	return nil
}

func (x *TowerAllDataRsp) GetRetcode() int32 {
	if x != nil {
		return x.Retcode
	}
	return 0
}

func (x *TowerAllDataRsp) GetMOOJNLEAKFC() uint32 {
	if x != nil {
		return x.MOOJNLEAKFC
	}
	return 0
}

var File_TowerAllDataRsp_proto protoreflect.FileDescriptor

var file_TowerAllDataRsp_proto_rawDesc = []byte{
	0x0a, 0x15, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x41, 0x6c, 0x6c, 0x44, 0x61, 0x74, 0x61, 0x52, 0x73,
	0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x46, 0x6c,
	0x6f, 0x6f, 0x72, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a,
	0x19, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x43, 0x75, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x52, 0x65,
	0x63, 0x6f, 0x72, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x54, 0x6f, 0x77, 0x65,
	0x72, 0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x42, 0x72, 0x69, 0x65, 0x66, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xda, 0x08, 0x0a, 0x0f, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x41, 0x6c, 0x6c,
	0x44, 0x61, 0x74, 0x61, 0x52, 0x73, 0x70, 0x12, 0x3b, 0x0a, 0x1a, 0x69, 0x73, 0x5f, 0x66, 0x69,
	0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x5f, 0x65, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x5f,
	0x66, 0x6c, 0x6f, 0x6f, 0x72, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x08, 0x52, 0x17, 0x69, 0x73, 0x46,
	0x69, 0x6e, 0x69, 0x73, 0x68, 0x65, 0x64, 0x45, 0x6e, 0x74, 0x72, 0x61, 0x6e, 0x63, 0x65, 0x46,
	0x6c, 0x6f, 0x6f, 0x72, 0x12, 0x2f, 0x0a, 0x13, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65,
	0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x90, 0x09, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x11, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x53, 0x74, 0x61, 0x72,
	0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x46, 0x45, 0x4f, 0x4b, 0x4d, 0x4b, 0x46,
	0x4c, 0x4f, 0x46, 0x49, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x46, 0x45, 0x4f, 0x4b,
	0x4d, 0x4b, 0x46, 0x4c, 0x4f, 0x46, 0x49, 0x12, 0x20, 0x0a, 0x0b, 0x43, 0x46, 0x48, 0x50, 0x4c,
	0x4a, 0x4b, 0x4b, 0x4f, 0x46, 0x47, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x43, 0x46,
	0x48, 0x50, 0x4c, 0x4a, 0x4b, 0x4b, 0x4f, 0x46, 0x47, 0x12, 0x20, 0x0a, 0x0b, 0x4e, 0x46, 0x4c,
	0x4a, 0x4c, 0x48, 0x44, 0x43, 0x50, 0x46, 0x4a, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b,
	0x4e, 0x46, 0x4c, 0x4a, 0x4c, 0x48, 0x44, 0x43, 0x50, 0x46, 0x4a, 0x12, 0x48, 0x0a, 0x17, 0x74,
	0x6f, 0x77, 0x65, 0x72, 0x5f, 0x66, 0x6c, 0x6f, 0x6f, 0x72, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72,
	0x64, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0e, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x54,
	0x6f, 0x77, 0x65, 0x72, 0x46, 0x6c, 0x6f, 0x6f, 0x72, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x52,
	0x14, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x46, 0x6c, 0x6f, 0x6f, 0x72, 0x52, 0x65, 0x63, 0x6f, 0x72,
	0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x4a, 0x4a, 0x4a, 0x43, 0x50, 0x48, 0x4d,
	0x42, 0x4d, 0x4c, 0x47, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4a, 0x4a, 0x4a, 0x43,
	0x50, 0x48, 0x4d, 0x42, 0x4d, 0x4c, 0x47, 0x12, 0x2a, 0x0a, 0x11, 0x69, 0x73, 0x5f, 0x66, 0x69,
	0x72, 0x73, 0x74, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x61, 0x63, 0x74, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0f, 0x69, 0x73, 0x46, 0x69, 0x72, 0x73, 0x74, 0x49, 0x6e, 0x74, 0x65, 0x72,
	0x61, 0x63, 0x74, 0x12, 0x3e, 0x0a, 0x10, 0x63, 0x75, 0x72, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c,
	0x5f, 0x72, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x54, 0x6f, 0x77, 0x65, 0x72, 0x43, 0x75, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x52, 0x65, 0x63,
	0x6f, 0x72, 0x64, 0x52, 0x0e, 0x63, 0x75, 0x72, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x52, 0x65, 0x63,
	0x6f, 0x72, 0x64, 0x12, 0x51, 0x0a, 0x1b, 0x6c, 0x61, 0x73, 0x74, 0x5f, 0x73, 0x63, 0x68, 0x65,
	0x64, 0x75, 0x6c, 0x65, 0x5f, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x5f, 0x62, 0x72, 0x69,
	0x65, 0x66, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x54, 0x6f, 0x77, 0x65, 0x72,
	0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x42, 0x72, 0x69, 0x65, 0x66, 0x52, 0x18, 0x6c, 0x61,
	0x73, 0x74, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x4d, 0x6f, 0x6e, 0x74, 0x68, 0x6c,
	0x79, 0x42, 0x72, 0x69, 0x65, 0x66, 0x12, 0x55, 0x0a, 0x13, 0x66, 0x6c, 0x6f, 0x6f, 0x72, 0x5f,
	0x6f, 0x70, 0x65, 0x6e, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x6d, 0x61, 0x70, 0x18, 0x0d, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x41, 0x6c, 0x6c, 0x44, 0x61,
	0x74, 0x61, 0x52, 0x73, 0x70, 0x2e, 0x46, 0x6c, 0x6f, 0x6f, 0x72, 0x4f, 0x70, 0x65, 0x6e, 0x54,
	0x69, 0x6d, 0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x10, 0x66, 0x6c, 0x6f,
	0x6f, 0x72, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x4d, 0x61, 0x70, 0x12, 0x37, 0x0a,
	0x0d, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c, 0x79, 0x5f, 0x62, 0x72, 0x69, 0x65, 0x66, 0x18, 0x78,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x54, 0x6f, 0x77, 0x65, 0x72, 0x4d, 0x6f, 0x6e, 0x74,
	0x68, 0x6c, 0x79, 0x42, 0x72, 0x69, 0x65, 0x66, 0x52, 0x0c, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x6c,
	0x79, 0x42, 0x72, 0x69, 0x65, 0x66, 0x12, 0x39, 0x0a, 0x19, 0x6e, 0x65, 0x78, 0x74, 0x5f, 0x73,
	0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x5f, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x74,
	0x69, 0x6d, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x16, 0x6e, 0x65, 0x78, 0x74, 0x53,
	0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x43, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x54, 0x69, 0x6d,
	0x65, 0x12, 0x2a, 0x0a, 0x11, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x5f, 0x73, 0x63, 0x68, 0x65, 0x64,
	0x75, 0x6c, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x74, 0x6f,
	0x77, 0x65, 0x72, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x49, 0x64, 0x12, 0x7e, 0x0a,
	0x22, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x66, 0x6c, 0x6f, 0x6f, 0x72, 0x5f, 0x67, 0x72, 0x61, 0x6e,
	0x74, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x77, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x74, 0x65, 0x6d, 0x5f,
	0x6d, 0x61, 0x70, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x33, 0x2e, 0x54, 0x6f, 0x77, 0x65,
	0x72, 0x41, 0x6c, 0x6c, 0x44, 0x61, 0x74, 0x61, 0x52, 0x73, 0x70, 0x2e, 0x53, 0x6b, 0x69, 0x70,
	0x46, 0x6c, 0x6f, 0x6f, 0x72, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x65, 0x64, 0x52, 0x65, 0x77, 0x61,
	0x72, 0x64, 0x49, 0x74, 0x65, 0x6d, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x1d,
	0x73, 0x6b, 0x69, 0x70, 0x46, 0x6c, 0x6f, 0x6f, 0x72, 0x47, 0x72, 0x61, 0x6e, 0x74, 0x65, 0x64,
	0x52, 0x65, 0x77, 0x61, 0x72, 0x64, 0x49, 0x74, 0x65, 0x6d, 0x4d, 0x61, 0x70, 0x12, 0x18, 0x0a,
	0x07, 0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x07,
	0x72, 0x65, 0x74, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x4d, 0x4f, 0x4f, 0x4a, 0x4e,
	0x4c, 0x45, 0x41, 0x4b, 0x46, 0x43, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x4d, 0x4f,
	0x4f, 0x4a, 0x4e, 0x4c, 0x45, 0x41, 0x4b, 0x46, 0x43, 0x1a, 0x43, 0x0a, 0x15, 0x46, 0x6c, 0x6f,
	0x6f, 0x72, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x50,
	0x0a, 0x22, 0x53, 0x6b, 0x69, 0x70, 0x46, 0x6c, 0x6f, 0x6f, 0x72, 0x47, 0x72, 0x61, 0x6e, 0x74,
	0x65, 0x64, 0x52, 0x65, 0x77, 0x61, 0x72, 0x64, 0x49, 0x74, 0x65, 0x6d, 0x4d, 0x61, 0x70, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x42, 0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_TowerAllDataRsp_proto_rawDescOnce sync.Once
	file_TowerAllDataRsp_proto_rawDescData = file_TowerAllDataRsp_proto_rawDesc
)

func file_TowerAllDataRsp_proto_rawDescGZIP() []byte {
	file_TowerAllDataRsp_proto_rawDescOnce.Do(func() {
		file_TowerAllDataRsp_proto_rawDescData = protoimpl.X.CompressGZIP(file_TowerAllDataRsp_proto_rawDescData)
	})
	return file_TowerAllDataRsp_proto_rawDescData
}

var file_TowerAllDataRsp_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_TowerAllDataRsp_proto_goTypes = []interface{}{
	(*TowerAllDataRsp)(nil),     // 0: TowerAllDataRsp
	nil,                         // 1: TowerAllDataRsp.FloorOpenTimeMapEntry
	nil,                         // 2: TowerAllDataRsp.SkipFloorGrantedRewardItemMapEntry
	(*TowerFloorRecord)(nil),    // 3: TowerFloorRecord
	(*TowerCurLevelRecord)(nil), // 4: TowerCurLevelRecord
	(*TowerMonthlyBrief)(nil),   // 5: TowerMonthlyBrief
}
var file_TowerAllDataRsp_proto_depIdxs = []int32{
	3, // 0: TowerAllDataRsp.tower_floor_record_list:type_name -> TowerFloorRecord
	4, // 1: TowerAllDataRsp.cur_level_record:type_name -> TowerCurLevelRecord
	5, // 2: TowerAllDataRsp.last_schedule_monthly_brief:type_name -> TowerMonthlyBrief
	1, // 3: TowerAllDataRsp.floor_open_time_map:type_name -> TowerAllDataRsp.FloorOpenTimeMapEntry
	5, // 4: TowerAllDataRsp.monthly_brief:type_name -> TowerMonthlyBrief
	2, // 5: TowerAllDataRsp.skip_floor_granted_reward_item_map:type_name -> TowerAllDataRsp.SkipFloorGrantedRewardItemMapEntry
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_TowerAllDataRsp_proto_init() }
func file_TowerAllDataRsp_proto_init() {
	if File_TowerAllDataRsp_proto != nil {
		return
	}
	file_TowerFloorRecord_proto_init()
	file_TowerCurLevelRecord_proto_init()
	file_TowerMonthlyBrief_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_TowerAllDataRsp_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TowerAllDataRsp); i {
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
			RawDescriptor: file_TowerAllDataRsp_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_TowerAllDataRsp_proto_goTypes,
		DependencyIndexes: file_TowerAllDataRsp_proto_depIdxs,
		MessageInfos:      file_TowerAllDataRsp_proto_msgTypes,
	}.Build()
	File_TowerAllDataRsp_proto = out.File
	file_TowerAllDataRsp_proto_rawDesc = nil
	file_TowerAllDataRsp_proto_goTypes = nil
	file_TowerAllDataRsp_proto_depIdxs = nil
}
