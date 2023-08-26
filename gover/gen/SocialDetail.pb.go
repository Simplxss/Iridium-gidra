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
// source: SocialDetail.proto

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

// Obf: NBNCHDGBFEC
type SocialDetail struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Uid                   uint32                  `protobuf:"varint,1,opt,name=uid,proto3" json:"uid,omitempty"`
	Nickname              string                  `protobuf:"bytes,2,opt,name=nickname,proto3" json:"nickname,omitempty"`
	Level                 uint32                  `protobuf:"varint,3,opt,name=level,proto3" json:"level,omitempty"`
	AvatarId              uint32                  `protobuf:"varint,4,opt,name=avatar_id,json=avatarId,proto3" json:"avatar_id,omitempty"`
	Signature             string                  `protobuf:"bytes,5,opt,name=signature,proto3" json:"signature,omitempty"`
	Birthday              *Birthday               `protobuf:"bytes,6,opt,name=birthday,proto3" json:"birthday,omitempty"`
	WorldLevel            uint32                  `protobuf:"varint,7,opt,name=world_level,json=worldLevel,proto3" json:"world_level,omitempty"`
	ReservedList          []uint32                `protobuf:"varint,8,rep,packed,name=reserved_list,json=reservedList,proto3" json:"reserved_list,omitempty"`
	OnlineState           FriendOnlineState       `protobuf:"varint,9,opt,name=online_state,json=onlineState,proto3,enum=FriendOnlineState" json:"online_state,omitempty"`
	Param                 uint32                  `protobuf:"varint,10,opt,name=param,proto3" json:"param,omitempty"`
	IsFriend              bool                    `protobuf:"varint,11,opt,name=is_friend,json=isFriend,proto3" json:"is_friend,omitempty"`
	IsMpModeAvailable     bool                    `protobuf:"varint,12,opt,name=is_mp_mode_available,json=isMpModeAvailable,proto3" json:"is_mp_mode_available,omitempty"`
	OnlineId              string                  `protobuf:"bytes,13,opt,name=online_id,json=onlineId,proto3" json:"online_id,omitempty"`
	NameCardId            uint32                  `protobuf:"varint,14,opt,name=name_card_id,json=nameCardId,proto3" json:"name_card_id,omitempty"`
	IsInBlacklist         bool                    `protobuf:"varint,15,opt,name=is_in_blacklist,json=isInBlacklist,proto3" json:"is_in_blacklist,omitempty"`
	IsChatNoDisturb       bool                    `protobuf:"varint,16,opt,name=is_chat_no_disturb,json=isChatNoDisturb,proto3" json:"is_chat_no_disturb,omitempty"`
	RemarkName            string                  `protobuf:"bytes,17,opt,name=remark_name,json=remarkName,proto3" json:"remark_name,omitempty"`
	FinishAchievementNum  uint32                  `protobuf:"varint,18,opt,name=finish_achievement_num,json=finishAchievementNum,proto3" json:"finish_achievement_num,omitempty"`
	TowerFloorIndex       uint32                  `protobuf:"varint,19,opt,name=tower_floor_index,json=towerFloorIndex,proto3" json:"tower_floor_index,omitempty"`
	TowerLevelIndex       uint32                  `protobuf:"varint,20,opt,name=tower_level_index,json=towerLevelIndex,proto3" json:"tower_level_index,omitempty"`
	IsShowAvatar          bool                    `protobuf:"varint,21,opt,name=is_show_avatar,json=isShowAvatar,proto3" json:"is_show_avatar,omitempty"`
	ShowAvatarInfoList    []*SocialShowAvatarInfo `protobuf:"bytes,22,rep,name=show_avatar_info_list,json=showAvatarInfoList,proto3" json:"show_avatar_info_list,omitempty"`
	ShowNameCardIdList    []uint32                `protobuf:"varint,23,rep,packed,name=show_name_card_id_list,json=showNameCardIdList,proto3" json:"show_name_card_id_list,omitempty"`
	FriendEnterHomeOption FriendEnterHomeOption   `protobuf:"varint,24,opt,name=friend_enter_home_option,json=friendEnterHomeOption,proto3,enum=FriendEnterHomeOption" json:"friend_enter_home_option,omitempty"`
	ProfilePicture        *ProfilePicture         `protobuf:"bytes,25,opt,name=profile_picture,json=profilePicture,proto3" json:"profile_picture,omitempty"`
	IpCode                string                  `protobuf:"bytes,26,opt,name=ip_code,json=ipCode,proto3" json:"ip_code,omitempty"`
}

func (x *SocialDetail) Reset() {
	*x = SocialDetail{}
	if protoimpl.UnsafeEnabled {
		mi := &file_SocialDetail_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SocialDetail) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SocialDetail) ProtoMessage() {}

func (x *SocialDetail) ProtoReflect() protoreflect.Message {
	mi := &file_SocialDetail_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SocialDetail.ProtoReflect.Descriptor instead.
func (*SocialDetail) Descriptor() ([]byte, []int) {
	return file_SocialDetail_proto_rawDescGZIP(), []int{0}
}

func (x *SocialDetail) GetUid() uint32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

func (x *SocialDetail) GetNickname() string {
	if x != nil {
		return x.Nickname
	}
	return ""
}

func (x *SocialDetail) GetLevel() uint32 {
	if x != nil {
		return x.Level
	}
	return 0
}

func (x *SocialDetail) GetAvatarId() uint32 {
	if x != nil {
		return x.AvatarId
	}
	return 0
}

func (x *SocialDetail) GetSignature() string {
	if x != nil {
		return x.Signature
	}
	return ""
}

func (x *SocialDetail) GetBirthday() *Birthday {
	if x != nil {
		return x.Birthday
	}
	return nil
}

func (x *SocialDetail) GetWorldLevel() uint32 {
	if x != nil {
		return x.WorldLevel
	}
	return 0
}

func (x *SocialDetail) GetReservedList() []uint32 {
	if x != nil {
		return x.ReservedList
	}
	return nil
}

func (x *SocialDetail) GetOnlineState() FriendOnlineState {
	if x != nil {
		return x.OnlineState
	}
	return FriendOnlineState_FRIEND_ONLINE_STATE_DISCONNECT
}

func (x *SocialDetail) GetParam() uint32 {
	if x != nil {
		return x.Param
	}
	return 0
}

func (x *SocialDetail) GetIsFriend() bool {
	if x != nil {
		return x.IsFriend
	}
	return false
}

func (x *SocialDetail) GetIsMpModeAvailable() bool {
	if x != nil {
		return x.IsMpModeAvailable
	}
	return false
}

func (x *SocialDetail) GetOnlineId() string {
	if x != nil {
		return x.OnlineId
	}
	return ""
}

func (x *SocialDetail) GetNameCardId() uint32 {
	if x != nil {
		return x.NameCardId
	}
	return 0
}

func (x *SocialDetail) GetIsInBlacklist() bool {
	if x != nil {
		return x.IsInBlacklist
	}
	return false
}

func (x *SocialDetail) GetIsChatNoDisturb() bool {
	if x != nil {
		return x.IsChatNoDisturb
	}
	return false
}

func (x *SocialDetail) GetRemarkName() string {
	if x != nil {
		return x.RemarkName
	}
	return ""
}

func (x *SocialDetail) GetFinishAchievementNum() uint32 {
	if x != nil {
		return x.FinishAchievementNum
	}
	return 0
}

func (x *SocialDetail) GetTowerFloorIndex() uint32 {
	if x != nil {
		return x.TowerFloorIndex
	}
	return 0
}

func (x *SocialDetail) GetTowerLevelIndex() uint32 {
	if x != nil {
		return x.TowerLevelIndex
	}
	return 0
}

func (x *SocialDetail) GetIsShowAvatar() bool {
	if x != nil {
		return x.IsShowAvatar
	}
	return false
}

func (x *SocialDetail) GetShowAvatarInfoList() []*SocialShowAvatarInfo {
	if x != nil {
		return x.ShowAvatarInfoList
	}
	return nil
}

func (x *SocialDetail) GetShowNameCardIdList() []uint32 {
	if x != nil {
		return x.ShowNameCardIdList
	}
	return nil
}

func (x *SocialDetail) GetFriendEnterHomeOption() FriendEnterHomeOption {
	if x != nil {
		return x.FriendEnterHomeOption
	}
	return FriendEnterHomeOption_FRIEND_ENTER_HOME_OPTION_NEED_CONFIRM
}

func (x *SocialDetail) GetProfilePicture() *ProfilePicture {
	if x != nil {
		return x.ProfilePicture
	}
	return nil
}

func (x *SocialDetail) GetIpCode() string {
	if x != nil {
		return x.IpCode
	}
	return ""
}

var File_SocialDetail_proto protoreflect.FileDescriptor

var file_SocialDetail_proto_rawDesc = []byte{
	0x0a, 0x12, 0x53, 0x6f, 0x63, 0x69, 0x61, 0x6c, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0e, 0x42, 0x69, 0x72, 0x74, 0x68, 0x64, 0x61, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x46, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x4f, 0x6e, 0x6c, 0x69,
	0x6e, 0x65, 0x53, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x53,
	0x6f, 0x63, 0x69, 0x61, 0x6c, 0x53, 0x68, 0x6f, 0x77, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49,
	0x6e, 0x66, 0x6f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1b, 0x46, 0x72, 0x69, 0x65, 0x6e,
	0x64, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x48, 0x6f, 0x6d, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x50,
	0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa0, 0x08, 0x0a,
	0x0c, 0x53, 0x6f, 0x63, 0x69, 0x61, 0x6c, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x12, 0x10, 0x0a,
	0x03, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x75, 0x69, 0x64, 0x12,
	0x1a, 0x0a, 0x08, 0x6e, 0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x6e, 0x69, 0x63, 0x6b, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6c, 0x65, 0x76, 0x65,
	0x6c, 0x12, 0x1b, 0x0a, 0x09, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49, 0x64, 0x12, 0x1c,
	0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x25, 0x0a, 0x08,
	0x62, 0x69, 0x72, 0x74, 0x68, 0x64, 0x61, 0x79, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x09,
	0x2e, 0x42, 0x69, 0x72, 0x74, 0x68, 0x64, 0x61, 0x79, 0x52, 0x08, 0x62, 0x69, 0x72, 0x74, 0x68,
	0x64, 0x61, 0x79, 0x12, 0x1f, 0x0a, 0x0b, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x5f, 0x6c, 0x65, 0x76,
	0x65, 0x6c, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x4c,
	0x65, 0x76, 0x65, 0x6c, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x64,
	0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0c, 0x72, 0x65, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x35, 0x0a, 0x0c, 0x6f, 0x6e, 0x6c,
	0x69, 0x6e, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x12, 0x2e, 0x46, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x4f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x52, 0x0b, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x12, 0x14, 0x0a, 0x05, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x05, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x73, 0x5f, 0x66, 0x72, 0x69,
	0x65, 0x6e, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x69, 0x73, 0x46, 0x72, 0x69,
	0x65, 0x6e, 0x64, 0x12, 0x2f, 0x0a, 0x14, 0x69, 0x73, 0x5f, 0x6d, 0x70, 0x5f, 0x6d, 0x6f, 0x64,
	0x65, 0x5f, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x11, 0x69, 0x73, 0x4d, 0x70, 0x4d, 0x6f, 0x64, 0x65, 0x41, 0x76, 0x61, 0x69, 0x6c,
	0x61, 0x62, 0x6c, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x69,
	0x64, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x6f, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x49,
	0x64, 0x12, 0x20, 0x0a, 0x0c, 0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x69,
	0x64, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x6e, 0x61, 0x6d, 0x65, 0x43, 0x61, 0x72,
	0x64, 0x49, 0x64, 0x12, 0x26, 0x0a, 0x0f, 0x69, 0x73, 0x5f, 0x69, 0x6e, 0x5f, 0x62, 0x6c, 0x61,
	0x63, 0x6b, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0d, 0x69, 0x73,
	0x49, 0x6e, 0x42, 0x6c, 0x61, 0x63, 0x6b, 0x6c, 0x69, 0x73, 0x74, 0x12, 0x2b, 0x0a, 0x12, 0x69,
	0x73, 0x5f, 0x63, 0x68, 0x61, 0x74, 0x5f, 0x6e, 0x6f, 0x5f, 0x64, 0x69, 0x73, 0x74, 0x75, 0x72,
	0x62, 0x18, 0x10, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0f, 0x69, 0x73, 0x43, 0x68, 0x61, 0x74, 0x4e,
	0x6f, 0x44, 0x69, 0x73, 0x74, 0x75, 0x72, 0x62, 0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x6d, 0x61,
	0x72, 0x6b, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x11, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x72,
	0x65, 0x6d, 0x61, 0x72, 0x6b, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x34, 0x0a, 0x16, 0x66, 0x69, 0x6e,
	0x69, 0x73, 0x68, 0x5f, 0x61, 0x63, 0x68, 0x69, 0x65, 0x76, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x5f,
	0x6e, 0x75, 0x6d, 0x18, 0x12, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x14, 0x66, 0x69, 0x6e, 0x69, 0x73,
	0x68, 0x41, 0x63, 0x68, 0x69, 0x65, 0x76, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x4e, 0x75, 0x6d, 0x12,
	0x2a, 0x0a, 0x11, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x5f, 0x66, 0x6c, 0x6f, 0x6f, 0x72, 0x5f, 0x69,
	0x6e, 0x64, 0x65, 0x78, 0x18, 0x13, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x74, 0x6f, 0x77, 0x65,
	0x72, 0x46, 0x6c, 0x6f, 0x6f, 0x72, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x2a, 0x0a, 0x11, 0x74,
	0x6f, 0x77, 0x65, 0x72, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78,
	0x18, 0x14, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x74, 0x6f, 0x77, 0x65, 0x72, 0x4c, 0x65, 0x76,
	0x65, 0x6c, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x24, 0x0a, 0x0e, 0x69, 0x73, 0x5f, 0x73, 0x68,
	0x6f, 0x77, 0x5f, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x18, 0x15, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0c, 0x69, 0x73, 0x53, 0x68, 0x6f, 0x77, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x12, 0x48, 0x0a,
	0x15, 0x73, 0x68, 0x6f, 0x77, 0x5f, 0x61, 0x76, 0x61, 0x74, 0x61, 0x72, 0x5f, 0x69, 0x6e, 0x66,
	0x6f, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x16, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x53,
	0x6f, 0x63, 0x69, 0x61, 0x6c, 0x53, 0x68, 0x6f, 0x77, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x12, 0x73, 0x68, 0x6f, 0x77, 0x41, 0x76, 0x61, 0x74, 0x61, 0x72, 0x49,
	0x6e, 0x66, 0x6f, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x32, 0x0a, 0x16, 0x73, 0x68, 0x6f, 0x77, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x69, 0x64, 0x5f, 0x6c, 0x69, 0x73,
	0x74, 0x18, 0x17, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x12, 0x73, 0x68, 0x6f, 0x77, 0x4e, 0x61, 0x6d,
	0x65, 0x43, 0x61, 0x72, 0x64, 0x49, 0x64, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x4f, 0x0a, 0x18, 0x66,
	0x72, 0x69, 0x65, 0x6e, 0x64, 0x5f, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x5f, 0x68, 0x6f, 0x6d, 0x65,
	0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x18, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e,
	0x46, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x48, 0x6f, 0x6d, 0x65, 0x4f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x15, 0x66, 0x72, 0x69, 0x65, 0x6e, 0x64, 0x45, 0x6e, 0x74,
	0x65, 0x72, 0x48, 0x6f, 0x6d, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x38, 0x0a, 0x0f,
	0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x70, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x18,
	0x19, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x50,
	0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x52, 0x0e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x50,
	0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x69, 0x70, 0x5f, 0x63, 0x6f, 0x64,
	0x65, 0x18, 0x1a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x69, 0x70, 0x43, 0x6f, 0x64, 0x65, 0x42,
	0x06, 0x5a, 0x04, 0x2f, 0x67, 0x65, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_SocialDetail_proto_rawDescOnce sync.Once
	file_SocialDetail_proto_rawDescData = file_SocialDetail_proto_rawDesc
)

func file_SocialDetail_proto_rawDescGZIP() []byte {
	file_SocialDetail_proto_rawDescOnce.Do(func() {
		file_SocialDetail_proto_rawDescData = protoimpl.X.CompressGZIP(file_SocialDetail_proto_rawDescData)
	})
	return file_SocialDetail_proto_rawDescData
}

var file_SocialDetail_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_SocialDetail_proto_goTypes = []interface{}{
	(*SocialDetail)(nil),         // 0: SocialDetail
	(*Birthday)(nil),             // 1: Birthday
	(FriendOnlineState)(0),       // 2: FriendOnlineState
	(*SocialShowAvatarInfo)(nil), // 3: SocialShowAvatarInfo
	(FriendEnterHomeOption)(0),   // 4: FriendEnterHomeOption
	(*ProfilePicture)(nil),       // 5: ProfilePicture
}
var file_SocialDetail_proto_depIdxs = []int32{
	1, // 0: SocialDetail.birthday:type_name -> Birthday
	2, // 1: SocialDetail.online_state:type_name -> FriendOnlineState
	3, // 2: SocialDetail.show_avatar_info_list:type_name -> SocialShowAvatarInfo
	4, // 3: SocialDetail.friend_enter_home_option:type_name -> FriendEnterHomeOption
	5, // 4: SocialDetail.profile_picture:type_name -> ProfilePicture
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_SocialDetail_proto_init() }
func file_SocialDetail_proto_init() {
	if File_SocialDetail_proto != nil {
		return
	}
	file_Birthday_proto_init()
	file_FriendOnlineState_proto_init()
	file_SocialShowAvatarInfo_proto_init()
	file_FriendEnterHomeOption_proto_init()
	file_ProfilePicture_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_SocialDetail_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SocialDetail); i {
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
			RawDescriptor: file_SocialDetail_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_SocialDetail_proto_goTypes,
		DependencyIndexes: file_SocialDetail_proto_depIdxs,
		MessageInfos:      file_SocialDetail_proto_msgTypes,
	}.Build()
	File_SocialDetail_proto = out.File
	file_SocialDetail_proto_rawDesc = nil
	file_SocialDetail_proto_goTypes = nil
	file_SocialDetail_proto_depIdxs = nil
}
