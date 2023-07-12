//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.23.4
// source: pkg/collectsub/collectsub/collectsub.proto

package collectsub

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

type CollectDataType int32

const (
	CollectDataType_DATATYPE_UNKNOWN        CollectDataType = 0
	CollectDataType_DATATYPE_GIT            CollectDataType = 1
	CollectDataType_DATATYPE_OCI            CollectDataType = 2
	CollectDataType_DATATYPE_PURL           CollectDataType = 3
	CollectDataType_DATATYPE_GITHUB_RELEASE CollectDataType = 4
)

// Enum value maps for CollectDataType.
var (
	CollectDataType_name = map[int32]string{
		0: "DATATYPE_UNKNOWN",
		1: "DATATYPE_GIT",
		2: "DATATYPE_OCI",
		3: "DATATYPE_PURL",
		4: "DATATYPE_GITHUB_RELEASE",
	}
	CollectDataType_value = map[string]int32{
		"DATATYPE_UNKNOWN":        0,
		"DATATYPE_GIT":            1,
		"DATATYPE_OCI":            2,
		"DATATYPE_PURL":           3,
		"DATATYPE_GITHUB_RELEASE": 4,
	}
)

func (x CollectDataType) Enum() *CollectDataType {
	p := new(CollectDataType)
	*p = x
	return p
}

func (x CollectDataType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (CollectDataType) Descriptor() protoreflect.EnumDescriptor {
	return file_pkg_collectsub_collectsub_collectsub_proto_enumTypes[0].Descriptor()
}

func (CollectDataType) Type() protoreflect.EnumType {
	return &file_pkg_collectsub_collectsub_collectsub_proto_enumTypes[0]
}

func (x CollectDataType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use CollectDataType.Descriptor instead.
func (CollectDataType) EnumDescriptor() ([]byte, []int) {
	return file_pkg_collectsub_collectsub_collectsub_proto_rawDescGZIP(), []int{0}
}

// Generic types
type CollectEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type  CollectDataType `protobuf:"varint,1,opt,name=type,proto3,enum=guacsec.guac.collect_subscriber.schema.CollectDataType" json:"type,omitempty"`
	Value string          `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *CollectEntry) Reset() {
	*x = CollectEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CollectEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CollectEntry) ProtoMessage() {}

func (x *CollectEntry) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CollectEntry.ProtoReflect.Descriptor instead.
func (*CollectEntry) Descriptor() ([]byte, []int) {
	return file_pkg_collectsub_collectsub_collectsub_proto_rawDescGZIP(), []int{0}
}

func (x *CollectEntry) GetType() CollectDataType {
	if x != nil {
		return x.Type
	}
	return CollectDataType_DATATYPE_UNKNOWN
}

func (x *CollectEntry) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

// rpc AddCollectEntry
type AddCollectEntriesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Entries []*CollectEntry `protobuf:"bytes,1,rep,name=entries,proto3" json:"entries,omitempty"`
}

func (x *AddCollectEntriesRequest) Reset() {
	*x = AddCollectEntriesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddCollectEntriesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddCollectEntriesRequest) ProtoMessage() {}

func (x *AddCollectEntriesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddCollectEntriesRequest.ProtoReflect.Descriptor instead.
func (*AddCollectEntriesRequest) Descriptor() ([]byte, []int) {
	return file_pkg_collectsub_collectsub_collectsub_proto_rawDescGZIP(), []int{1}
}

func (x *AddCollectEntriesRequest) GetEntries() []*CollectEntry {
	if x != nil {
		return x.Entries
	}
	return nil
}

type AddCollectEntriesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Success bool `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
}

func (x *AddCollectEntriesResponse) Reset() {
	*x = AddCollectEntriesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddCollectEntriesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddCollectEntriesResponse) ProtoMessage() {}

func (x *AddCollectEntriesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddCollectEntriesResponse.ProtoReflect.Descriptor instead.
func (*AddCollectEntriesResponse) Descriptor() ([]byte, []int) {
	return file_pkg_collectsub_collectsub_collectsub_proto_rawDescGZIP(), []int{2}
}

func (x *AddCollectEntriesResponse) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

// rpc GetCollectEntries
type CollectEntryFilter struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type CollectDataType `protobuf:"varint,1,opt,name=type,proto3,enum=guacsec.guac.collect_subscriber.schema.CollectDataType" json:"type,omitempty"`
	Glob string          `protobuf:"bytes,2,opt,name=glob,proto3" json:"glob,omitempty"`
}

func (x *CollectEntryFilter) Reset() {
	*x = CollectEntryFilter{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CollectEntryFilter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CollectEntryFilter) ProtoMessage() {}

func (x *CollectEntryFilter) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CollectEntryFilter.ProtoReflect.Descriptor instead.
func (*CollectEntryFilter) Descriptor() ([]byte, []int) {
	return file_pkg_collectsub_collectsub_collectsub_proto_rawDescGZIP(), []int{3}
}

func (x *CollectEntryFilter) GetType() CollectDataType {
	if x != nil {
		return x.Type
	}
	return CollectDataType_DATATYPE_UNKNOWN
}

func (x *CollectEntryFilter) GetGlob() string {
	if x != nil {
		return x.Glob
	}
	return ""
}

type GetCollectEntriesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filters []*CollectEntryFilter `protobuf:"bytes,1,rep,name=filters,proto3" json:"filters,omitempty"`
	// since_time in unix epoch
	SinceTime int64 `protobuf:"varint,2,opt,name=since_time,json=sinceTime,proto3" json:"since_time,omitempty"`
}

func (x *GetCollectEntriesRequest) Reset() {
	*x = GetCollectEntriesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCollectEntriesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCollectEntriesRequest) ProtoMessage() {}

func (x *GetCollectEntriesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCollectEntriesRequest.ProtoReflect.Descriptor instead.
func (*GetCollectEntriesRequest) Descriptor() ([]byte, []int) {
	return file_pkg_collectsub_collectsub_collectsub_proto_rawDescGZIP(), []int{4}
}

func (x *GetCollectEntriesRequest) GetFilters() []*CollectEntryFilter {
	if x != nil {
		return x.Filters
	}
	return nil
}

func (x *GetCollectEntriesRequest) GetSinceTime() int64 {
	if x != nil {
		return x.SinceTime
	}
	return 0
}

type GetCollectEntriesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Entries []*CollectEntry `protobuf:"bytes,1,rep,name=entries,proto3" json:"entries,omitempty"`
}

func (x *GetCollectEntriesResponse) Reset() {
	*x = GetCollectEntriesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCollectEntriesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCollectEntriesResponse) ProtoMessage() {}

func (x *GetCollectEntriesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCollectEntriesResponse.ProtoReflect.Descriptor instead.
func (*GetCollectEntriesResponse) Descriptor() ([]byte, []int) {
	return file_pkg_collectsub_collectsub_collectsub_proto_rawDescGZIP(), []int{5}
}

func (x *GetCollectEntriesResponse) GetEntries() []*CollectEntry {
	if x != nil {
		return x.Entries
	}
	return nil
}

var File_pkg_collectsub_collectsub_collectsub_proto protoreflect.FileDescriptor

var file_pkg_collectsub_collectsub_collectsub_proto_rawDesc = []byte{
	0x0a, 0x2a, 0x70, 0x6b, 0x67, 0x2f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x73, 0x75, 0x62,
	0x2f, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x73, 0x75, 0x62, 0x2f, 0x63, 0x6f, 0x6c, 0x6c,
	0x65, 0x63, 0x74, 0x73, 0x75, 0x62, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x26, 0x67, 0x75,
	0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65,
	0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x72, 0x2e, 0x73, 0x63,
	0x68, 0x65, 0x6d, 0x61, 0x22, 0x71, 0x0a, 0x0c, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x4b, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x37, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61,
	0x63, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72,
	0x69, 0x62, 0x65, 0x72, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x43, 0x6f, 0x6c, 0x6c,
	0x65, 0x63, 0x74, 0x44, 0x61, 0x74, 0x61, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x6a, 0x0a, 0x18, 0x41, 0x64, 0x64, 0x43, 0x6f,
	0x6c, 0x6c, 0x65, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x4e, 0x0a, 0x07, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x34, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67,
	0x75, 0x61, 0x63, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73,
	0x63, 0x72, 0x69, 0x62, 0x65, 0x72, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x43, 0x6f,
	0x6c, 0x6c, 0x65, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x65, 0x6e, 0x74, 0x72,
	0x69, 0x65, 0x73, 0x22, 0x35, 0x0a, 0x19, 0x41, 0x64, 0x64, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63,
	0x74, 0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x75, 0x0a, 0x12, 0x43, 0x6f,
	0x6c, 0x6c, 0x65, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x12, 0x4b, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x37,
	0x2e, 0x67, 0x75, 0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x2e, 0x63, 0x6f,
	0x6c, 0x6c, 0x65, 0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x72,
	0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x44,
	0x61, 0x74, 0x61, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a,
	0x04, 0x67, 0x6c, 0x6f, 0x62, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x67, 0x6c, 0x6f,
	0x62, 0x22, 0x8f, 0x01, 0x0a, 0x18, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74,
	0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x54,
	0x0a, 0x07, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x3a, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x2e, 0x63,
	0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65,
	0x72, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x52, 0x07, 0x66, 0x69, 0x6c,
	0x74, 0x65, 0x72, 0x73, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x69, 0x6e, 0x63, 0x65, 0x5f, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x73, 0x69, 0x6e, 0x63, 0x65, 0x54,
	0x69, 0x6d, 0x65, 0x22, 0x6b, 0x0a, 0x19, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63,
	0x74, 0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x4e, 0x0a, 0x07, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x34, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61, 0x63,
	0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69,
	0x62, 0x65, 0x72, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x43, 0x6f, 0x6c, 0x6c, 0x65,
	0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73,
	0x2a, 0x7b, 0x0a, 0x0f, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x44, 0x61, 0x74, 0x61, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x10, 0x44, 0x41, 0x54, 0x41, 0x54, 0x59, 0x50, 0x45, 0x5f,
	0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x10, 0x0a, 0x0c, 0x44, 0x41, 0x54,
	0x41, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x47, 0x49, 0x54, 0x10, 0x01, 0x12, 0x10, 0x0a, 0x0c, 0x44,
	0x41, 0x54, 0x41, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x4f, 0x43, 0x49, 0x10, 0x02, 0x12, 0x11, 0x0a,
	0x0d, 0x44, 0x41, 0x54, 0x41, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x50, 0x55, 0x52, 0x4c, 0x10, 0x03,
	0x12, 0x1b, 0x0a, 0x17, 0x44, 0x41, 0x54, 0x41, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x47, 0x49, 0x54,
	0x48, 0x55, 0x42, 0x5f, 0x52, 0x45, 0x4c, 0x45, 0x41, 0x53, 0x45, 0x10, 0x04, 0x32, 0xcf, 0x02,
	0x0a, 0x17, 0x43, 0x6f, 0x6c, 0x65, 0x63, 0x74, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62,
	0x65, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x98, 0x01, 0x0a, 0x11, 0x41, 0x64,
	0x64, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x12,
	0x40, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x2e, 0x63,
	0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65,
	0x72, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x41, 0x64, 0x64, 0x43, 0x6f, 0x6c, 0x6c,
	0x65, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x41, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61, 0x63,
	0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69,
	0x62, 0x65, 0x72, 0x2e, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x41, 0x64, 0x64, 0x43, 0x6f,
	0x6c, 0x6c, 0x65, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x98, 0x01, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6c, 0x6c,
	0x65, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x12, 0x40, 0x2e, 0x67, 0x75, 0x61,
	0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x2e, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63,
	0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x72, 0x2e, 0x73, 0x63, 0x68,
	0x65, 0x6d, 0x61, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x45, 0x6e,
	0x74, 0x72, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x41, 0x2e, 0x67,
	0x75, 0x61, 0x63, 0x73, 0x65, 0x63, 0x2e, 0x67, 0x75, 0x61, 0x63, 0x2e, 0x63, 0x6f, 0x6c, 0x6c,
	0x65, 0x63, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x72, 0x2e, 0x73,
	0x63, 0x68, 0x65, 0x6d, 0x61, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74,
	0x45, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42,
	0x28, 0x5a, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x75,
	0x61, 0x63, 0x73, 0x65, 0x63, 0x2f, 0x67, 0x75, 0x61, 0x63, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x63,
	0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x73, 0x75, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_pkg_collectsub_collectsub_collectsub_proto_rawDescOnce sync.Once
	file_pkg_collectsub_collectsub_collectsub_proto_rawDescData = file_pkg_collectsub_collectsub_collectsub_proto_rawDesc
)

func file_pkg_collectsub_collectsub_collectsub_proto_rawDescGZIP() []byte {
	file_pkg_collectsub_collectsub_collectsub_proto_rawDescOnce.Do(func() {
		file_pkg_collectsub_collectsub_collectsub_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_collectsub_collectsub_collectsub_proto_rawDescData)
	})
	return file_pkg_collectsub_collectsub_collectsub_proto_rawDescData
}

var file_pkg_collectsub_collectsub_collectsub_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_pkg_collectsub_collectsub_collectsub_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_pkg_collectsub_collectsub_collectsub_proto_goTypes = []interface{}{
	(CollectDataType)(0),              // 0: guacsec.guac.collect_subscriber.schema.CollectDataType
	(*CollectEntry)(nil),              // 1: guacsec.guac.collect_subscriber.schema.CollectEntry
	(*AddCollectEntriesRequest)(nil),  // 2: guacsec.guac.collect_subscriber.schema.AddCollectEntriesRequest
	(*AddCollectEntriesResponse)(nil), // 3: guacsec.guac.collect_subscriber.schema.AddCollectEntriesResponse
	(*CollectEntryFilter)(nil),        // 4: guacsec.guac.collect_subscriber.schema.CollectEntryFilter
	(*GetCollectEntriesRequest)(nil),  // 5: guacsec.guac.collect_subscriber.schema.GetCollectEntriesRequest
	(*GetCollectEntriesResponse)(nil), // 6: guacsec.guac.collect_subscriber.schema.GetCollectEntriesResponse
}
var file_pkg_collectsub_collectsub_collectsub_proto_depIdxs = []int32{
	0, // 0: guacsec.guac.collect_subscriber.schema.CollectEntry.type:type_name -> guacsec.guac.collect_subscriber.schema.CollectDataType
	1, // 1: guacsec.guac.collect_subscriber.schema.AddCollectEntriesRequest.entries:type_name -> guacsec.guac.collect_subscriber.schema.CollectEntry
	0, // 2: guacsec.guac.collect_subscriber.schema.CollectEntryFilter.type:type_name -> guacsec.guac.collect_subscriber.schema.CollectDataType
	4, // 3: guacsec.guac.collect_subscriber.schema.GetCollectEntriesRequest.filters:type_name -> guacsec.guac.collect_subscriber.schema.CollectEntryFilter
	1, // 4: guacsec.guac.collect_subscriber.schema.GetCollectEntriesResponse.entries:type_name -> guacsec.guac.collect_subscriber.schema.CollectEntry
	2, // 5: guacsec.guac.collect_subscriber.schema.ColectSubscriberService.AddCollectEntries:input_type -> guacsec.guac.collect_subscriber.schema.AddCollectEntriesRequest
	5, // 6: guacsec.guac.collect_subscriber.schema.ColectSubscriberService.GetCollectEntries:input_type -> guacsec.guac.collect_subscriber.schema.GetCollectEntriesRequest
	3, // 7: guacsec.guac.collect_subscriber.schema.ColectSubscriberService.AddCollectEntries:output_type -> guacsec.guac.collect_subscriber.schema.AddCollectEntriesResponse
	6, // 8: guacsec.guac.collect_subscriber.schema.ColectSubscriberService.GetCollectEntries:output_type -> guacsec.guac.collect_subscriber.schema.GetCollectEntriesResponse
	7, // [7:9] is the sub-list for method output_type
	5, // [5:7] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_pkg_collectsub_collectsub_collectsub_proto_init() }
func file_pkg_collectsub_collectsub_collectsub_proto_init() {
	if File_pkg_collectsub_collectsub_collectsub_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CollectEntry); i {
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
		file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddCollectEntriesRequest); i {
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
		file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AddCollectEntriesResponse); i {
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
		file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CollectEntryFilter); i {
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
		file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCollectEntriesRequest); i {
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
		file_pkg_collectsub_collectsub_collectsub_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCollectEntriesResponse); i {
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
			RawDescriptor: file_pkg_collectsub_collectsub_collectsub_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pkg_collectsub_collectsub_collectsub_proto_goTypes,
		DependencyIndexes: file_pkg_collectsub_collectsub_collectsub_proto_depIdxs,
		EnumInfos:         file_pkg_collectsub_collectsub_collectsub_proto_enumTypes,
		MessageInfos:      file_pkg_collectsub_collectsub_collectsub_proto_msgTypes,
	}.Build()
	File_pkg_collectsub_collectsub_collectsub_proto = out.File
	file_pkg_collectsub_collectsub_collectsub_proto_rawDesc = nil
	file_pkg_collectsub_collectsub_collectsub_proto_goTypes = nil
	file_pkg_collectsub_collectsub_collectsub_proto_depIdxs = nil
}
