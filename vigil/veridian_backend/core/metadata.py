from __future__ import annotations

from construct import (
    Bytes,
    IfThenElse,
    Int16ul,
    Int32ul,
    Int64ul,
    Int8ul,
    Struct,
    this,
)

# -------------------------
# NTFS Binary Declarations
# -------------------------

MFTRecord = Struct(
    "signature" / Bytes(4),  # "FILE"
    "fixup_array_offset" / Int16ul,
    "fixup_array_count" / Int16ul,
    "lsn" / Int64ul,  # CRITICAL — LogFile LSN
    "sequence_number" / Int16ul,
    "hard_link_count" / Int16ul,
    "first_attr_offset" / Int16ul,
    "flags" / Int16ul,
    "used_size" / Int32ul,
    "allocated_size" / Int32ul,
    "file_reference" / Int64ul,
    "next_attr_id" / Int16ul,
    "record_number" / Int32ul,
)

StandardInformation = Struct(
    "created" / Int64ul,  # FILETIME
    "modified" / Int64ul,  # FILETIME
    "mft_modified" / Int64ul,  # FILETIME — EntryModified
    "accessed" / Int64ul,  # FILETIME
    "attributes" / Int32ul,
    "max_versions" / Int32ul,
    "version" / Int32ul,
    "class_id" / Int32ul,
    "owner_id" / Int32ul,
    "security_id" / Int32ul,
    "quota_charged" / Int64ul,
    "last_usn" / Int64ul,  # CRITICAL for Rules 5, 6, 8
)

FileName = Struct(
    "parent_dir" / Int64ul,  # parent file reference
    "created" / Int64ul,  # FILETIME — ground truth
    "modified" / Int64ul,  # FILETIME — ground truth
    "mft_modified" / Int64ul,  # FILETIME
    "accessed" / Int64ul,  # FILETIME
    "alloc_size" / Int64ul,
    "real_size" / Int64ul,  # CRITICAL for Rule 4
    "flags" / Int32ul,
    "reparse_value" / Int32ul,
    "name_length" / Int8ul,
    "namespace" / Int8ul,  # 0=POSIX 1=Win32 2=DOS 3=Win32&DOS
    "filename"
    / IfThenElse(
        this.name_length > 0,
        Bytes(this.name_length * 2),
        Bytes(0),
    ),
)

USNRecordV2 = Struct(
    "record_length" / Int32ul,
    "major_version" / Int16ul,  # must be 2
    "minor_version" / Int16ul,  # must be 0
    "file_reference" / Int64ul,
    "parent_reference" / Int64ul,
    "usn" / Int64ul,  # sequence number
    "timestamp" / Int64ul,  # FILETIME
    "reason" / Int32ul,  # bitmask
    "source_info" / Int32ul,
    "security_id" / Int32ul,
    "file_attributes" / Int32ul,
    "filename_length" / Int16ul,
    "filename_offset" / Int16ul,  # always 60
)

# USN Reason Flag Constants
USN_REASON_DATA_OVERWRITE = 0x00000001
USN_REASON_DATA_EXTEND = 0x00000002
USN_REASON_DATA_TRUNCATION = 0x00000004
USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_RENAME_OLD_NAME = 0x00001000
USN_REASON_RENAME_NEW_NAME = 0x00002000
USN_REASON_BASIC_INFO_CHANGE = 0x00008000
USN_REASON_CLOSE = 0x80000000

LogPageHeader = Struct(
    "signature" / Bytes(4),  # "RCRD" or "RSTR"
    "usa_offset" / Int16ul,
    "usa_count" / Int16ul,
    "last_lsn" / Int64ul,  # LSN of last record on page
    "flags" / Int32ul,
    "page_count" / Int16ul,
    "page_position" / Int16ul,
    "next_record_offset" / Int16ul,
    "reserved" / Bytes(6),
    "last_end_lsn" / Int64ul,
)

