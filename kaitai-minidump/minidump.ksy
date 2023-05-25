# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

meta:
  id: minidump
  title: Minidump
  file-extension: dmp
  license: Apache-2.0
  endian: le
  bit-endian: le
seq:
  - id: signature
    -orig-id: Signature
    contents: MDMP
  - id: version
    -orig-id: Version
    type: u4
  - id: number_of_streams
    -orig-id: NumberOfStreams
    type: u4
  - id: stream_directory_rva
    -orig-id: StreamDirectoryRva
    type: u4
  - id: checksum
    -orig-id: CheckSum
    type: u4
  - id: time_date_stamp
    -orig-id: TimeDataStamp
    type: u4
  - id: flags
    -orig-id: Flags
    type: minidump_type
instances:
  minidump_directory_entries:
    io: _root._io
    pos: stream_directory_rva
    type: minidump_directory_entry
    repeat: expr
    repeat-expr: number_of_streams

types:
  minidump_type:
    -orig-id: MINIDUMP_TYPE
    seq:
      - id: with_data_segs
        -orig-id: WITH_DATA_SEGS #0x00000001
        type: b1
      - id: with_full_memory
        -orig-id: WITH_FULL_MEMORY #0x00000002
        type: b1
      - id: with_handle_data
        -orig-id: WITH_HANDLE_DATA #0x00000004
        type: b1
      - id: filter_memory
        -orig-id: FILTER_MEMORY #0x00000008
        type: b1
      - id: scan_memory
        -orig-id: SCAN_MEMORY #0x00000010
        type: b1
      - id: with_unloaded_modules
        -orig-id: WITH_UNLOADED_MODULES #0x00000020
        type: b1
      - id: with_indirectly_referenced_memory
        -orig-id: WITH_INDIRECTLY_REFERENCED_MEMORY #0x00000040
        type: b1
      - id: filter_module_paths
        -orig-id: FILTER_MODULE_PATHS #0x00000080
        type: b1
      - id: with_process_thread_data
        -orig-id: WITH_PROCESS_THREAD_DATA #0x00000100
        type: b1
      - id: with_private_read_write_memory
        -orig-id: WITH_PRIVATE_READ_WRITE_MEMORY #0x00000200
        type: b1
      - id: without_optional_data
        -orig-id: WITHOUT_OPTIONAL_DATA #0x00000400
        type: b1
      - id: with_full_memory_info
        -orig-id: WITH_FULL_MEMORY_INFO #0x00000800
        type: b1
      - id: with_thread_info
        -orig-id: WITH_THREAD_INFO #0x00001000
        type: b1
      - id: with_code_segs
        -orig-id: WITH_CODE_SEGS #0x00002000
        type: b1
      - id: without_auxilliary_segs
        -orig-id: WITHOUT_AUXILLIARY_SEGS #0x00004000
        type: b1
      - id: with_full_auxilliary_state
        -orig-id: WITH_FULL_AUXILLIARY_STATE #0x00008000
        type: b1
      - id: with_private_write_copy_memory
        -orig-id: WITH_PRIVATE_WRITE_COPY_MEMORY #0x00010000
        type: b1
      - id: ignore_inaccessible_memory
        -orig-id: IGNORE_INACCESSIBLE_MEMORY #0x00020000
        type: b1
      - id: with_token_information
        -orig-id: WITH_TOKEN_INFORMATION #0x00040000
        type: b1
      - id: reserved
        type: b13
      - id: reserved2
        type: u4

  minidump_directory_entry:
    -orig-id: MINIDUMP_DIRECTORY_ENTRY
    seq:
      - id: stream_type
        -orig-id: StreamType
        type: u4
        enum: minidump_stream_type
      - id: data_size
        -orig-id: DataSize
        type: u4
      - id: rva
        -orig-id: Rva
        type: u4
    instances:
      data:
        io: _root._io
        pos: rva
        size: data_size
        type:
          switch-on: stream_type
          cases:
            'minidump_stream_type::thread_list_stream': minidump_thread_list #3
            'minidump_stream_type::module_list_stream': minidump_module_list #4
            'minidump_stream_type::memory_list_stream': minidump_memory_list #5
            'minidump_stream_type::exception_stream': minidump_exception_stream #6
            'minidump_stream_type::system_info_stream': minidump_system_info #7
            'minidump_stream_type::handle_data_stream': minidump_handle_data_stream #12
            'minidump_stream_type::unloaded_module_list_stream': minidump_unloaded_module_list #14
            'minidump_stream_type::misc_info_stream': minidump_misc_info #15
            'minidump_stream_type::memory_info_list_stream': minidump_memory_info_list #16
            'minidump_stream_type::thread_names_stream': minidump_thread_names_list #24
            'minidump_stream_type::crashpad_info_stream': minidump_crashpad_info_stream #0x43500001

# ThreadListStream 3 ----------------------------------------------------------3
  minidump_thread_list:
    -orig-id: MINIDUMP_THREAD_LIST
    seq:
      - id: number_of_threads
        -orig-id: NumberOfThreads
        type: u4
      - id: threads
        -orig-id: Threads
        type: minidump_thread
        repeat: expr
        repeat-expr: number_of_threads
  minidump_thread:
    -orig-id: MINIDUMP_THREAD
    seq:
      - id: thread_id
        -orig-id: ThreadId
        type: u4
      - id: suspend_count
        -orig-id: SuspendCount
        type: u4
      - id: priority_class
        -orig-id: PriorityClass
        type: u4
      - id: priority
        -orig-id: Priority
        type: u4
      - id: teb
        -orig-id: Teb
        type: u8
      - id: stack
        -orig-id: Stack
        type: minidump_memory_descriptor
      - id: thread_context
        -orig-id: ThreadContext
        type: minidump_location_descriptor('minidump_thread_context')

# ModuleListStream 4 ----------------------------------------------------------4
  minidump_module_list:
    -orig-id: MINIDUMP_MODULE_LIST
    seq:
      - id: number_of_modules
        -orig-id: NumberOfModules
        type: u4
      - id: modules
        -orig-id: Modules
        type: minidump_module
        repeat: expr
        repeat-expr: number_of_modules
  minidump_module:
    -orig-id: MINIDUMP_MODULE
    seq:
      - id: base_of_image
        -orig-id: BaseOfImage
        type: u8
      - id: size_of_image
        -orig-id: SizeOfImage
        type: u4
      - id: checksum
        -orig-id: CheckSum
        type: u4
      - id: time_date_stamp
        -orig-id: TimeDateStamp
        type: u4
      - id: module_name_rva
        -orig-id: ModuleNameRva
        type: u4
      - id: version_info
        -orig-id: VersionInfo
        type: vs_fixed_file_info
      - id: cv_record
        -orig-id: CvRecord
        type: minidump_location_descriptor('minidump_cv_info')
      - id: misc_record
        -orig-id: MiscRecord
        type: minidump_location_descriptor('minidump_image_debug_misc')
      - id: reserved0
        -orig-id: Reserved0
        type: u8
      - id: reserved1
        -orig-id: Reserved1
        type: u8
    instances:
      module_name:
        io: _root._io
        pos: module_name_rva
        type: minidump_string
        if: module_name_rva > 0

  vs_fixed_file_info:
    -orig-id: VS_FIXEDFILEINFO
    seq:
      - id: signature
        -orig-id: Signature
        type: u4
      - id: struct_version
        -orig-id: StrucVersion
        type: u4
      - id: file_version_ms
        -orig-id: FileVersionMS
        type: u4
      - id: file_version_ls
        -orig-id: FileVersionLS
        type: u4
      - id: product_version_ms
        -orig-id: ProductVersionMS
        type: u4
      - id: product_version_ls
        -orig-id: ProductVersionLS
        type: u4
      - id: file_flags_mask
        -orig-id: FileFlagsMask
        type: u4
      - id: file_flags
        -orig-id: FileFlags
        type: u4
      - id: file_os
        -orig-id: FileOS
        type: u4
      - id: file_type
        -orig-id: FileType
        type: u4
      - id: file_subtype
        -orig-id: FileSubtype
        type: u4
      - id: file_date_ms
        -orig-id: FileDateMS
        type: u4
      - id: file_date_ls
        -orig-id: FileDateLS
        type: u4

  minidump_cv_info:
    -orig-id: CVInfo
    seq:
      - id: cv_signature
        -orig-id: CVSignature
        type: u4
      - id: info
        type:
          switch-on: cv_signature
          cases:
            0x3031424e: minidump_cv_info_pdb20 #01BN
            0x53445352: minidump_cv_info_pdb70 #SDSR
            0x4270454c: minidump_cv_info_elf   #BpEL
  minidump_cv_info_pdb20:
    -orig-id: CVInfoPDB20
    seq:
      - id: cv_offset
        -orig-id: CVOffset
        type: u4
      - id: signature
        -orig-id: Signature
        type: u4
      - id: age
        -orig-id: Age
        type: u4
      - id: pdb_file_name
        -orig-id: PDBFileName
        type: strz
        encoding: UTF-8
  minidump_cv_info_pdb70:
    -orig-id: CVInfoPDB70
    seq:
      - id: signature
        -orig-id: Signature
        type: minidump_guid
      - id: age
        -orig-id: Age
        type: u4
      - id: pdb_file_name
        -orig-id: PDBFileName
        type: strz
        encoding: UTF-8
  minidump_cv_info_elf:
    -orig-id: CVInfoELF
    seq:
      - id: signature
        -orig-id: Signature
        type: minidump_guid

  minidump_image_debug_misc:
    -orig-id: ImageDebugMisc
    seq:
      - id: data_type
        -orig-id: DataType
        type: u4
      - id: length
        -orig-id: Length
        type: u4
      - id: unicode
        -orig-id: Unicode
        type: u1
      - id: reserved
        -orig-id: Reserved
        type: u1
        repeat: expr
        repeat-expr: 3
      - id: data
        -orig-id: Data
        type:
          switch-on: unicode
          cases:
            0: string_utf8
            _: string_utf16

# MemoryListStream 5 ----------------------------------------------------------5
  minidump_memory_list:
    -orig-id: MINIDUMP_MEMORY_LIST
    seq:
      - id: number_of_memory_ranges
        -orig-id: NumberOfMemoryRanges
        type: u4
      - id: memory_ranges
        -orig-id: MemoryRanges
        type: minidump_memory_descriptor
        repeat: expr
        repeat-expr: number_of_memory_ranges

# ExceptionStream 6 -----------------------------------------------------------6
  minidump_exception_stream:
    -orig-id: MINIDUMP_EXCEPTION_STREAM
    seq:
      - id: thread_id
        -orig-id: ThreadId
        type: u4
      - id: alignment
        -orig-id: __alignment
        type: u4
      - id: exception_code
        -orig-id: ExceptionCode
        type: u4
      - id: exception_flags
        -orig-id: ExceptionFlags
        type: u4
      - id: exception_record
        -orig-id: ExceptionRecord
        type: u8
      - id: exception_address
        -orig-id: ExceptionAddress
        type: u8
      - id: number_parameters
        -orig-id: NumberParameters
        type: u4
      - id: unused_alignment
        -orig-id: __unusedAlignment
        type: u4
      - id: exception_information
        -orig-id: ExceptionInformation
        type: u8
        repeat: expr
        repeat-expr: 15
      - id: thread_context
        -orig-id: ThreadContext
        type: minidump_location_descriptor('minidump_thread_context')

# SystemInfoStream 7 ----------------------------------------------------------7
  minidump_system_info:
    -orig-id: MINIDUMP_SYSTEM_INFO
    seq:
      - id: processor_architecture
        -orig-id: ProcessorArchitecture
        type: u2
        enum: minidump_processor_architecture
      - id: processor_level
        -orig-id: ProcessorLevel
        type: u2
      - id: processor_revision
        -orig-id: ProcessorRevision
        type: u2
      - id: number_of_processors
        -orig-id: NumberOfProcessors
        type: u1
      - id: product_type
        -orig-id: ProductType
        type: u1
      - id: major_version
        -orig-id: MajorVersion
        type: u4
      - id: minor_version
        -orig-id: MinorVersion
        type: u4
      - id: build_number
        -orig-id: BuildNumber
        type: u4
      - id: platform_id
        -orig-id: PlatformId
        type: u4
        enum: minidump_platform_id
      - id: csd_version_rva
        -orig-id: CSDVersionRva
        type: u4
      - id: suite_mask
        -orig-id: SuiteMask
        type: u2
      - id: reserved2
        -orig-id: Reserved2
        type: u2
      - id: cpu
        -orig-id: Cpu
        type: u1
        repeat: expr
        repeat-expr: 24
    instances:
      csd_version:
        io: _root._io
        pos: csd_version_rva
        type: minidump_string

# HandleDataStream 12 --------------------------------------------------------12
  minidump_handle_data_stream:
    -orig-id: MINIDUMP_HANDLE_DATA_STREAM
    seq:
      - id: size_of_header
        -orig-id: SizeOfHeader
        type: u4
      - id: size_of_descriptor
        -orig-id: SizeOfDesciptor
        type: u4
      - id: number_of_descriptors
        -orig-id: NumberOfDescriptors
        type: u4
      - id: reserved
        -orig-id: Reserved
        type: u4
    instances:
      descriptors:
        -orig-id: Descriptors
        pos: size_of_header
        type: minidump_handle_descriptor
        size: size_of_descriptor
        repeat: expr
        repeat-expr: number_of_descriptors
  minidump_handle_descriptor:
    -orig-id: MINIDUMP_HANDLE_DESCRIPTOR_X
    seq:
      - id: handle
        -orig-id: Handle
        type: u8
      - id: type_name_rva
        -orig-id: TypeNameRva
        type: u4
      - id: object_name_rva
        -orig-id: ObjectNameRva
        type: u4
      - id: attributes
        -orig-id: Attributes
        type: u4
      - id: granted_access
        -orig-id: GrantedAccess
        type: u4
      - id: handle_count
        -orig-id: HandleCount
        type: u4
      - id: pointer_count
        -orig-id: PointerCount
        type: u4
      - id: object_info_rva
        -orig-id: ObjectInfoRva #Nullable MINIDUMP_HANDLE_OBJECT_INFORMATION
        type: u4
        if: _parent.size_of_descriptor >= 7*4 + 1*8
      - id: reserved0
        -orig-id: Reserved0
        type: u4
        if: _parent.size_of_descriptor >= 8*4 + 1*8
    instances:
      type_name:
        io: _root._io
        pos: type_name_rva
        type: minidump_string
        if: type_name_rva > 0
      object_name:
        io: _root._io
        pos: object_name_rva
        type: minidump_string
        if: object_name_rva > 0

# UnloadedModuleListStream 14 ------------------------------------------------14
  minidump_unloaded_module_list:
    -orig-id: MINIDUMP_UNLOADED_MODULE_LIST
    seq:
      - id: size_of_header
        -orig-id: SizeOfHeader
        type: u4
      - id: size_of_entry
        -orig-id: SizeOfEntry
        type: u4
      - id: number_of_entries
        -orig-id: NumberOfEntries
        type: u4
    instances:
      entries:
        -orig-id: Entries
        pos: size_of_header
        type: minidump_unloaded_module
        size: size_of_entry
        repeat: expr
        repeat-expr: number_of_entries
  minidump_unloaded_module:
    -orig-id: MINIDUMP_UNLOADED_MODULE
    seq:
      - id: base_of_image
        -orig-id: BaseOfImage
        type: u8
      - id: size_of_image
        -orig-id: SizeOfImage
        type: u4
      - id: checksum
        -orig-id: CheckSum
        type: u4
      - id: time_date_stamp
        -orig-id: TimeDateStamp
        type: u4
      - id: module_name_rva
        -orig-id: ModuleNameRva
        type: u4
    instances:
      module_name:
        io: _root._io
        pos: module_name_rva
        type: minidump_string
        if: module_name_rva > 0

# MiscInfoStream 15 ----------------------------------------------------------15
  minidump_misc_info:
    -orig-id: MINIDUMP_MISC_INFO_X
    seq:
      # MINIDUMP_MISC_INFO
      - id: size_of_info
        -orig-id: SizeOfInfo
        type: u4
      - id: flags1
        -orig-id: Flags1
        type: minidump_misc_info_flags
        if: 2*4 <= size_of_info
      - id: process_id
        -orig-id: ProcessId
        type: u4
        if: 3*4 <= size_of_info
        doc: Valid when Flags1::PROCESS_ID is set.
      - id: process_create_time
        -orig-id: ProcessCreateTime
        type: u4
        if: 4*4 <= size_of_info
        doc: Valid when Flags1::PROCESS_TIMES is set.
      - id: process_user_time
        -orig-id: ProcessUserTime
        type: u4
        if: 5*4 <= size_of_info
        doc: Valid when Flags1::PROCESS_TIMES is set.
      - id: process_kernel_time
        -orig-id: ProcessKernelTime
        type: u4
        if: 6*4 <= size_of_info
        doc: Valid when Flags1::PROCESS_TIMES is set.
      # MINIDUMP_MISC_INFO_2
      - id: processor_max_mhz
        -orig-id: ProcessorMaxMhz
        type: u4
        if: 7*4 <= size_of_info
        doc: Valid when Flags1::PROCESSOR_POWER_INFO is set.
      - id: processor_current_mhz
        -orig-id: ProcessorCurrentMhz
        type: u4
        if: 8*4 <= size_of_info
        doc: Valid when Flags1::PROCESSOR_POWER_INFO is set.
      - id: processor_mhz_limit
        -orig-id: ProcessorMhzLimit
        type: u4
        if: 9*4 <= size_of_info
        doc: Valid when Flags1::PROCESSOR_POWER_INFO is set.
      - id: processor_max_idle_state
        -orig-id: ProcessorMaxIdleState
        type: u4
        if: 10*4 <= size_of_info
        doc: Valid when Flags1::PROCESSOR_POWER_INFO is set.
      - id: processor_current_idle_state
        -orig-id: ProcessorCurrentIdleState
        type: u4
        if: 11*4 <= size_of_info
        doc: Valid when Flags1::PROCESSOR_POWER_INFO is set.
      # MINIDUMP_MISC_INFO_3
      - id: process_integrity_level
        -orig-id: ProcessIntegrityLevel
        type: u4
        if: 12*4  <= size_of_info
        doc: Valid when Flags1::PROCESS_INTEGRITY is set.
      - id: process_execute_flags
        -orig-id: ProcessExecuteFlags
        type: u4
        if: 13*4 <= size_of_info
        doc: Valid when Flags1::PROCESS_EXECUTE_FLAGS is set.
      - id: protected_process
        -orig-id: ProtectedProcess
        type: u4
        if: 14*4 <= size_of_info
        doc: Valid when Flags1::PROTECTED_PROCESS is set.
      - id: time_zone_id
        -orig-id: TimeZoneId
        type: u4
        if: 15*4 <= size_of_info
        doc: Valid when Flags1::TIMEZONE is set.
      - id: time_zone_information
        -orig-id: TimeZone
        type: minidump_time_zone_information
        if: 15*4 + 172 <= size_of_info
        doc: Valid when Flags1::TIMEZONE is set.
      # MINIDUMP_MISC_INFO_4
      - id: build_string
        -orig-id: BuildString
        size: 260 * 2
        type: str
        encoding: UTF-16
        #terminator: 0  # https://github.com/kaitai-io/kaitai_struct/issues/187
        if: 15*4 + 172 + (260 * 2) <= size_of_info
      - id: dbg_build_string
        -orig-id: DbgBldString
        size: 40 * 2
        type: str
        encoding: UTF-16
        #terminator: 0  # https://github.com/kaitai-io/kaitai_struct/issues/187
        if: 15*4 + 172 + (260 * 2) + (40 * 2) <= size_of_info
      # MINIDUMP_MISC_INFO_5
      - id: x_state_data
        -orig-id: XStateData
        type: minidump_xstate_config_feature_msc_info
        if: 15*4 + 172 + (260 * 2) + (40 * 2) + 544 <= size_of_info
      - id: process_cookie
        -orig-id: ProcessCookie
        type: u4
        if: 16*4 + 172 + (260 * 2) + (40 * 2) + 544 <= size_of_info
        doc: Valid when Flags1::PROCESS_COOKIE is set.

  minidump_misc_info_flags:
    seq:
      - id: process_id
        -orig-id: PROCESS_ID #0x00000001
        type: b1
      - id: process_times
        -orig-id: PROCESS_TIMES #0x00000002
        type: b1
      - id: processor_power_info
        -orig-id: PROCESSOR_POWER_INFO #0x00000004
        type: b1
      - id: reserved1
        type: b1
      - id: process_integrity
        -orig-id: PROCESS_INTEGRITY #0x00000010
        type: b1
      - id: process_execute_flags
        -orig-id: PROCESS_EXECUTE_FLAGS #0x00000020
        type: b1
      - id: timezone
        -orig-id: TIMEZONE #0x00000040
        type: b1
      - id: protected_process
        -orig-id: PROTECTED_PROCESS #0x00000080
        type: b1
      - id: buildstring
        -orig-id: BUILDSTRING #0x00000100
        type: b1
      - id: process_cookie
        -orig-id: PROCESS_COOKIE #0x00000200
        type: b1
      - id: reserved
        type: b22

  minidump_time_zone_information:
    -orig-id: TIME_ZONE_INFORMATION
    seq:
      - id: bias
        -orig-id: Bias
        type: s4
      - id: standard_name
        -orig-id: StandardName
        size: 32 * 2
        type: str
        encoding: UTF-16
        #terminator: 0  # https://github.com/kaitai-io/kaitai_struct/issues/187
      - id: standard_date
        -orig-id: StandardDate
        type: minidump_system_time
      - id: standard_bias
        -orig-id: StandardBias
        type: s4
      - id: daylight_name
        -orig-id: DaylightName
        size: 32 * 2
        type: str
        encoding: UTF-16
        #terminator: 0  # https://github.com/kaitai-io/kaitai_struct/issues/187
      - id: daylight_date
        -orig-id: DaylightDate
        type: minidump_system_time
      - id: daylight_bias
        -orig-id: DaylightBias
        type: s4

  minidump_system_time:
    -orig-id: SYSTEMTIME
    seq:
      - id: year
        -orig-id: Year
        type: u2
      - id: month
        -orig-id: Month
        type: u2
      - id: day_of_week
        -orig-id: DayOfWeek
        type: u2
      - id: day
        -orig-id: Day
        type: u2
      - id: hour
        -orig-id: Hour
        type: u2
      - id: minute
        -orig-id: Minute
        type: u2
      - id: second
        -orig-id: Second
        type: u2
      - id: milliseconds
        -orig-id: Milliseconds
        type: u2

  minidump_xstate_config_feature_msc_info:
    seq:
      - id: size_of_info
        -orig-id: SizeOfInfo
        type: u4
      - id: context_size
        -orig-id: ContextSize
        type: u4
      - id: enabled_features
        -orig-id: EnabledFeatures
        type: minidump_xstate_config_feature_msc_info_flags
      - id: features
        -orig-id: Features
        type: minidump_xstate_feature
        repeat: expr
        repeat-expr: 64

  minidump_xstate_config_feature_msc_info_flags:
    -orig-id: XSTATE_FEATURE_FLAG
    seq:
      - id: legacy_floting_point
        -orig-id: LEGACY_FLOATING_POINT #0x0000000000000001
        type: b1
      - id: legacy_sse
        -orig-id: LEGACY_SSE #0x0000000000000002
        type: b1
      - id: gsse_or_avx
        -orig-id: GSSE_or_AVX #0x0000000000000004
        type: b1
      - id: mpx_bndregs
        -orig-id: MPX_BNDREGS #0x0000000000000008
        type: b1
      - id: mpx_bndcsr
        -orig-id: MPX_BNDCSR #0x0000000000000010
        type: b1
      - id: avx512_kmask
        -orig-id: AVX512_KMASK #0x0000000000000020
        type: b1
      - id: avx512_zmm_h
        -orig-id: AVX512_ZMM_H #0x0000000000000040
        type: b1
      - id: avx512_zmm
        -orig-id: AVX512_ZMM #0x0000000000000080
        type: b1
      - id: ipt
        -orig-id: IPT #0x0000000000000100
        type: b1
      - id: reserved1 #(9, 32]
        type: b23
      - id: reserved2
        type: b30 #(32, 62]
      - id: lwp
        -orig-id: LWP #0x4000000000000000
        type: b1
      - id: reserved3
        type: b1 #(63, 64]

  minidump_xstate_feature:
    seq:
      - id: offset
        -orig-id: Offset
        type: u4
      - id: size
        -orig-id: Size
        type: u4

# MemoryInfoListStream 16 ----------------------------------------------------16
  minidump_memory_info_list:
    -orig-id: MINIDUMP_MEMORY_INFO_LIST
    seq:
      - id: size_of_header
        -orig-id: SizeOfHeader
        type: u4
      - id: size_of_entry
        -orig-id: SizeOfEntry
        type: u4
      - id: number_of_entries
        -orig-id: NumberOfEntries
        type: u8
    instances:
      entries:
        -orig-id: Entries
        pos: size_of_header
        type: minidump_memory_info
        size: size_of_entry
        repeat: expr
        repeat-expr: number_of_entries
  minidump_memory_info:
    -orig-id: MINIDUMP_MEMORY_INFO
    seq:
      - id: base_address
        -orig-id: BaseAddress
        type: u8
      - id: allocation_base
        -orig-id: AllocationBase
        type: u8
      - id: allocation_protect
        -orig-id: AllocationProtect
        type: minidump_memory_info_protection
      - id: alignment
        -orig-id: __alignment
        type: u4
      - id: region_size
        -orig-id: RegionSize
        type: u8
      - id: state
        -orig-id: State
        type: u4
        enum: minidump_memory_info_state
      - id: protect
        -orig-id: Protect
        type: minidump_memory_info_protection
      - id: type
        -orig-id: Type
        type: u4
        enum: minidump_memory_info_type
      - id: alignment2
        -orig-id: __alignment2
        type: u4

  minidump_memory_info_protection:
    seq:
      - id: page_noaccess
        -orig-id: PAGE_NOACCESS  #0x01
        type: b1
      - id: page_readonly
        -orig-id: PAGE_READONLY  #0x02
        type: b1
      - id: page_readwrite
        -orig-id: PAGE_READWRITE  #0x04
        type: b1
      - id: page_writecopy
        -orig-id: PAGE_WRITECOPY  #0x08
        type: b1
      - id: page_execute
        -orig-id: PAGE_EXECUTE  #0x10
        type: b1
      - id: page_execute_read
        -orig-id: PAGE_EXECUTE_READ  #0x20
        type: b1
      - id: page_execute_readwrite
        -orig-id: PAGE_EXECUTE_READWRITE  #0x40
        type: b1
      - id: page_execute_writecopy
        -orig-id: PAGE_EXECUTE_WRITECOPY  #0x80
        type: b1
      - id: page_guard
        -orig-id: PAGE_GUARD  #0x100
        type: b1
      - id: page_nocache
        -orig-id: PAGE_NOCACHE  #0x200
        type: b1
      - id: page_writecombine
        -orig-id: PAGE_WRITECOMBINE  #0x400
        type: b1
      - id: reserved11_to_29
        type: b19
      - id: page_targets_invalid_or_no_update
        -orig-id: PAGE_TARGETS_INVALID  #0x40000000
        -orig-id: PAGE_TARGETS_NO_UPDATE  #0x40000000
        type: b1
      - id: reserved31
        type: b1

# ThreadNamesStream 24 -------------------------------------------------------24
  minidump_thread_names_list:
    -orig-id: MINIDUMP_THREAD_NAMES_LIST
    seq:
      - id: number_of_thread_names
        -orig-id: NumberOfThreadNames
        type: u4
      - id: names
        -orig-id: Names
        type: minidump_thread_name
        repeat: expr
        repeat-expr: number_of_thread_names

  minidump_thread_name:
    seq:
      - id: thread_id
        -orig-id: ThreadId
        type: u4
      - id: thread_name_rva
        -orig-id: ThreadNameRva
        type: u8
    instances:
      thread_name:
        io: _root._io
        pos: thread_name_rva
        type: minidump_string
        if: thread_name_rva > 0

# CrashpadInfoStream 0x43500001---------------------------------------0x43500001
  minidump_crashpad_info_stream:
    -orig-id: CrashpadInfo
    seq:
      - id: version
        -orig-id: Version
        type: s4
      - id: report_id
        -orig-id: ReportId
        type: minidump_guid
      - id: client_id
        -orig-id: ReportId
        type: minidump_guid
      - id: simple_annotations
        -orig-id: SimpleAnnotations
        type: minidump_location_descriptor('minidump_crashpad_simple_string_dictionary')
      - id: module_list
        -orig-id: ModuleList
        type: minidump_location_descriptor('minidump_crashpad_module_info_list')
      # Older versions of Crashpad did not write the following fields.
      - id: reserved
        -orig-id: Reserved
        type: u4
        if: _parent.data_size >= 2*4 + 2*8 + 2*16
      - id: address_mask
        -orig-id: AddressMask
        type: u8
        if: _parent.data_size >= 2*4 + 3*8 + 2*16

  minidump_crashpad_simple_string_dictionary:
    -orig-id: SimpleStringDictionary
    seq:
      - id: entry_count
        -orig-id: EntryCount
        type: u4
      - id: entries
        -orig-id: Entries
        type: minidump_crashpad_simple_string_dictionary_entry
        repeat: expr
        repeat-expr: entry_count

  minidump_crashpad_simple_string_dictionary_entry:
    seq:
      - id: key_rva
        -orig-id: Key
        type: u4
      - id: value_rva
        -orig-id: Value
        type: u4
    instances:
      key:
        io: _root._io
        pos: key_rva
        type: minidump_utf8_string
        if: key_rva > 0
      value:
        io: _root._io
        pos: value_rva
        type: minidump_utf8_string
        if: value_rva > 0

  minidump_crashpad_module_info_list:
    seq:
      - id: module_info_count
        -orig-id: ModuleInfoCount
        type: u4
      - id: module_infos
        -orig-id: ModuleInfos
        type: minidump_crashpad_module_info_link
        repeat: expr
        repeat-expr: module_info_count

  minidump_crashpad_module_info_link:
    seq:
      - id: module_list_index
        -orig-id: ModuleListIndex
        type: u4
      - id: module_info
        -orig-id: ModuleInfo
        type: minidump_location_descriptor('minidump_crashpad_module_info')

  minidump_crashpad_module_info:
    seq:
      - id: version
        -orig-id: Version
        type: u4
      - id: list_annotations
        -orig-id: ListAnnotations
        type: minidump_location_descriptor('minidump_crashpad_string_list')
      - id: simple_annotations
        -orig-id: SimpleAnnotations
        type: minidump_location_descriptor('minidump_crashpad_simple_string_dictionary')
      - id: annotation_objects
        -orig-id: AnnotationObjects
        type: minidump_location_descriptor('minidump_crashpad_annotation_list')

  minidump_crashpad_string_list:
    seq:
      - id: string_count
        -orig-id: StringCount
        type: u4
      - id: strings
        -orig-id: Strings
        type: u4
        repeat: expr
        repeat-expr: string_count
    instances:
      string:
        io: _root._io
        pos: strings[_index]
        repeat: expr
        repeat-expr: string_count
        type: minidump_string
        if: strings[_index] > 0

  minidump_crashpad_annotation_list:
    seq:
      - id: annotation_count
        -orig-id: AnnotationCount
        type: u4
      - id: annotations
        -orig-id: Annotations
        type: minidump_crashpad_annotation
        repeat: expr
        repeat-expr: annotation_count

  minidump_crashpad_annotation:
    seq:
      - id: name_rva
        -orig-id: Name
        type: u4
      - id: type
        -orig-id: Type
        type: u2
      - id: reserved
        -orig-id: Reserved
        type: u2
      - id: value_rva
        -orig-id: Value
        type: u4
    instances:
      name:
        io: _root._io
        pos: name_rva
        type: minidump_utf8_string
        if: name_rva > 0
      value:
        io: _root._io
        pos: value_rva
        type: minidump_utf8_string
        if: value_rva > 0

# Shared Types  ----------------------------------------------------------------
  minidump_string:
    seq:
      - id: length
        -orig-id: Length
        type: u4
      - id: buffer
        -orig-id: Buffer
        size: length
        type: str
        encoding: UTF-16

  minidump_utf8_string:
    seq:
    - id: length
      -orig-id: Length
      type: u4
    - id: buffer
      -orig-id: Buffer
      size: length
      type: str
      encoding: UTF-8

  string_utf16:
    seq:
      - id: string
        type: strz
        encoding: UTF-16

  string_utf8:
    seq:
      - id: string
        type: strz
        encoding: UTF-8

  minidump_guid:
    seq:
      - id: data1
        type: u4
      - id: data2
        type: u2
      - id: data3
        type: u2
      - id: data4
        type: u1
        repeat: expr
        repeat-expr: 8

  minidump_u16:
    seq:
      - id: data
        type: u4
        repeat: expr
        repeat-expr: 4

  minidump_location_descriptor:
    -orig-id: MINIDUMP_LOCATION_DESCRIPTOR
    params:
      - id: data_type
        type: str
    seq:
      - id: data_size
        -orig-id: DataSize
        type: u4
      - id: rva
        -orig-id: Rva
        type: u4
    instances:
      data:
        io: _root._io
        pos: rva
        size: data_size
        type:
          # Choosing the thread context type isn't simple. Guess based on size.
          switch-on: 'data_type == "minidump_thread_context"
                      ? (data_size ==  716 ? "minidump_thread_context_x86"
                       : data_size == 1232 ? "minidump_thread_context_amd64"
                       : data_size ==  368 ? "minidump_thread_context_arm"
                       : data_size ==  912 ? "minidump_thread_context_arm64"
                       : "minidump_thread_context_unknown")
                      : data_type'
          cases:
            #'"minidump_memory"': minidump_memory # treat as raw
            '"minidump_cv_info"': minidump_cv_info
            '"minidump_thread_context_x86"': minidumo_thread_context_x86
            '"minidump_thread_context_amd64"': minidump_thread_context_amd64
            '"minidump_thread_context_arm"': minidump_thread_context_arm
            '"minidump_thread_context_arm64"': minidump_thread_context_arm64
            '"minidump_crashpad_module_info_list"': minidump_crashpad_module_info_list
            '"minidump_crashpad_module_info"': minidump_crashpad_module_info
            '"minidump_crashpad_string_list"': minidump_crashpad_string_list
            '"minidump_crashpad_simple_string_dictionary"': minidump_crashpad_simple_string_dictionary
            '"minidump_crashpad_annotation_list"': minidump_crashpad_annotation_list
        if: rva > 0

  minidump_memory_descriptor:
    -orig-id: MINIDUMP_MEMORY_DESCRIPTOR
    seq:
      - id: start_of_memory_range
        -orig-id: StartOfMemoryRange
        type: u8
      - id: memory
        -orig-id: Memory
        type: minidump_location_descriptor('minidump_memory')

# Thread Context X86  -------------------------------------------------------X86
  minidumo_thread_context_x86:
    -orig-id: MINIDUMP_THREAD_CONTEXT_X86
    seq:
      - id: context_flags
        type: minidumo_thread_context_x86_context_flags
      - id: d0
        type: u4
      - id: d1
        type: u4
      - id: d2
        type: u4
      - id: d3
        type: u4
      - id: d6
        type: u4
      - id: d7
        type: u4
      - id: float_save
        type: minidump_thread_context_x86_floating_save_area
      - id: gs
        type: u4
      - id: fs
        type: u4
      - id: es
        type: u4
      - id: ds
        type: u4
      - id: edi
        type: u4
      - id: esi
        type: u4
      - id: ebx
        type: u4
      - id: edx
        type: u4
      - id: ecx
        type: u4
      - id: eax
        type: u4
      - id: ebp
        type: u4
      - id: eip
        type: u4
      - id: cs
        type: u4
      - id: eflags
        type: minidump_thread_context_x86_eflags
      - id: esp
        type: u4
      - id: ss
        type: u4
      - id: extended_registers
        type: minidump_thread_context_x86_fxsave

  minidumo_thread_context_x86_context_flags:
    seq:
      - id: control
        -orig-id: CONTROL  # 0x00000001
        type: b1
      - id: integer
        -orig-id: INTEGER  # 0x00000002
        type: b1
      - id: segments
        -orig-id: SEGMENTS  # 0x00000004
        type: b1
      - id: floating_point
        -orig-id: FLOATING_POINT  # 0x00000008
        type: b1
      - id: debug_registers
        -orig-id: DEBUG_REGISTERS  # 0x00000010
        type: b1
      - id: extended_registers
        -orig-id: EXTENDED_REGISTERS  # 0x00000020
        type: b1
      - id: xstate
        -orig-id: XSTATE  # 0x00000040
        type: b1
      - id: reserved7_to_15
        type: b9
      - id: x86
        -orig-id: X86  # 0x00010000
        type: b1
      - id: reserved17_to_31
        type: b15

  minidump_thread_context_x86_floating_save_area:
    -orig-id: FLOATING_SAVE_AREA
    seq:
      - id: control_word
        type: u4
      - id: status_word
        type: u4
      - id: tag_word
        type: u4
      - id: error_offset
        type: u4
      - id: error_selector
        type: u4
      - id: data_offset
        type: u4
      - id: data_selector
        type: u4
      - id: register_area
        type: minidump_thread_context_x87_long_double
        repeat: expr
        repeat-expr: 8
      - id: cr0_npx_state
        type: u4

  minidump_thread_context_x87_long_double:
    seq:
      - id: data
        size: 10

  minidump_thread_context_x86_eflags:
    seq:
      - id: cf
        -orig-id: CF  #0x00000001
        type: b1
        doc: Carry Flag: Carry to or borrow from a dest.
      - id: r1
        -orig-id: R1  #0x00000002
        type: b1
        doc: Reserved, always 1.
      - id: pf
        -orig-id: PF  #0x00000004
        type: b1
        doc: Parity flag: The dest LSB has an even number of 1's.
      - id: r2
        -orig-id: R2  #0x00000008
        type: b1
        doc: Reserved.
      - id: af
        -orig-id: AF  #0x00000010
        type: b1
        doc: Auxiliary Carry Flag: Used for BCD arithmetic.
      - id: r3
        -orig-id: R3  #0x00000020
        type: b1
        doc: Reserved.
      - id: zf
        -orig-id: ZF  #0x00000040
        type: b1
        doc: Zero Flag: The result an operation is binary zero.
      - id: sf
        -orig-id: SF  #0x00000080
        type: b1
        doc: Sign Flag: The most significant bit of the result.
      - id: tf
        -orig-id: TF  #0x00000100
        type: b1
        doc: Trap Flag: Fault after the next instruction.
      - id: if
        -orig-id: IF  #0x00000200
        type: b1
        doc: Interrupt Enable Flag: Enable interrupts.
      - id: df
        -orig-id: DF  #0x00000400
        type: b1
        doc: Direction Flag: String operation direction (0 is up).
      - id: of
        -orig-id: OF  #0x00000800
        type: b1
        doc: Overflow Flag: The result did not fit in the dest.
      - id: iopl
        -orig-id: IOPL  #0x00003000
        type: b2
        doc: I/O Privilege Level: Protected mode ring level.
      - id: nt
        -orig-id: NT  #0x00004000
        type: b1
        doc: Nested Task Flag: A system task used CALL (not JMP).
      - id: md
        -orig-id: MD  #0x00008000
        type: b1
        doc: Mode Flag: Always 1 (80186/8080 mode).
      - id: rf
        -orig-id: RF  #0x00010000
        type: b1
        doc: Resume Flag: See DR6, DR7. Disables some exceptions.
      - id: vm
        -orig-id: VM  #0x00020000
        type: b1
        doc: Virtual 8086 Mode flag: Makes 80386+ run like 8086.
      - id: ac
        -orig-id: AC  #0x00040000
        type: b1
        doc: Alignment Check / SMAP Access Check
      - id: vif
        -orig-id: VIF  #0x00080000
        type: b1
        doc: Virtual Interrupt Flag
      - id: vip
        -orig-id: VIP  #0x00100000
        type: b1
        doc: Virtual Interrupt Pending
      - id: id
        -orig-id: ID  #0x00200000
        type: b1
        doc: Able to use CPUID instruction
      - id: reserved22_to31
        type: b10

  minidump_thread_context_x86_fxsave:
    seq:
      - id: fcw
        -orig-id: FCW
        type: u2
      - id: fsw
        -orig-id: FSW
        type: u2
      - id: abridged_ftw
        -orig-id: AbridgedFTW
        type: u1
      - id: reserved1
        -orig-id: Reserved1
        type: u1
      - id: fop
        -orig-id: FOP
        type: u2
      - id: fip
        -orig-id: FIP
        type: u4
      - id: fcs
        -orig-id: FCS
        type: u2
      - id: reserved2
        -orig-id: Reserved2
        type: u2
      - id: fdp
        -orig-id: FDP
        type: u4
      - id: fds
        -orig-id: FDS
        type: u4
      - id: mxcsr
        -orig-id: MXCSR
        type: u4
      - id: mxcsr_mask
        -orig-id: MXCSR_MASK
        type: u4
      - id: sto_mm0
        -orig-id: ST0_MM0
        type: minidump_thread_context_x87_long_double
      - id: reserved_r0
        -orig-id: ReservedR0
        size: 6
      - id: sto_mm1
        -orig-id: ST0_MM1
        type: minidump_thread_context_x87_long_double
      - id: reserved_r1
        -orig-id: ReservedR1
        size: 6
      - id: sto_mm2
        -orig-id: ST0_MM2
        type: minidump_thread_context_x87_long_double
      - id: reserved_r2
        -orig-id: ReservedR2
        size: 6
      - id: sto_mm3
        -orig-id: ST0_MM3
        type: minidump_thread_context_x87_long_double
      - id: reserved_r3
        -orig-id: ReservedR3
        size: 6
      - id: sto_mm4
        -orig-id: ST0_MM4
        type: minidump_thread_context_x87_long_double
      - id: reserved_r4
        -orig-id: ReservedR4
        size: 6
      - id: sto_mm5
        -orig-id: ST0_MM5
        type: minidump_thread_context_x87_long_double
      - id: reserved_r5
        -orig-id: ReservedR5
        size: 6
      - id: sto_mm6
        -orig-id: ST0_MM6
        type: minidump_thread_context_x87_long_double
      - id: reserved_r6
        -orig-id: ReservedR6
        size: 6
      - id: sto_mm7
        -orig-id: ST0_MM7
        type: minidump_thread_context_x87_long_double
      - id: reserved_r7
        -orig-id: ReservedR7
        size: 6
      - id: xmm0
        -orig-id: XMM0
        type: minidump_u16
      - id: xmm1
        -orig-id: XMM1
        type: minidump_u16
      - id: xmm2
        -orig-id: XMM2
        type: minidump_u16
      - id: xmm3
        -orig-id: XMM3
        type: minidump_u16
      - id: xmm4
        -orig-id: XMM4
        type: minidump_u16
      - id: xmm5
        -orig-id: XMM5
        type: minidump_u16
      - id: xmm6
        -orig-id: XMM6
        type: minidump_u16
      - id: xmm7
        -orig-id: XMM7
        type: minidump_u16
      - id: reserved3
        -orig-id: Reserved3
        size: 16
      - id: reserved4
        -orig-id: Reserved4
        size: 160
      - id: available
        -orig-id: Available
        size: 48

# Thread Context AMD64  ---------------------------------------------------AMD64
  minidump_thread_context_amd64:
    -orig-id: MINIDUMP_THREAD_CONTEXT_AMD64
    seq:
      - id: p1_home
        type: u8
      - id: p2_home
        type: u8
      - id: p3_home
        type: u8
      - id: p4_home
        type: u8
      - id: p5_home
        type: u8
      - id: p6_home
        type: u8
      - id: context_flags
        type: minidump_thread_context_amd64_context_flags
      - id: mx_csr
        type: minidump_thread_context_amd64_sse_control_status
      - id: cs
        type: u2
      - id: ds
        type: u2
      - id: es
        type: u2
      - id: fs
        type: u2
      - id: gs
        type: u2
      - id: ss
        type: u2
      - id: eflags
        type: minidump_thread_context_x86_eflags
      - id: dr0
        type: u8
      - id: dr1
        type: u8
      - id: dr2
        type: u8
      - id: dr3
        type: u8
      - id: dr6
        type: u8
      - id: dr7
        type: u8
      - id: rax
        type: u8
      - id: rcx
        type: u8
      - id: rdx
        type: u8
      - id: rbx
        type: u8
      - id: rsp
        type: u8
      - id: rbp
        type: u8
      - id: rsi
        type: u8
      - id: rdi
        type: u8
      - id: r8
        type: u8
      - id: r9
        type: u8
      - id: r10
        type: u8
      - id: r11
        type: u8
      - id: r12
        type: u8
      - id: r13
        type: u8
      - id: r14
        type: u8
      - id: r15
        type: u8
      - id: rip
        type: u8
      - id: floating_point
        type: minidump_thread_context_amd64_floating_point
      - id: vector_register
        type: minidump_u16
        repeat: expr
        repeat-expr: 26
      - id: vector_control
        type: u8
      - id: debug_control
        type: u8
      - id: last_branch_to_rip
        type: u8
      - id: last_branch_from_rip
        type: u8
      - id: last_exception_to_rip
        type: u8
      - id: last_exception_from_rip
        type: u8

  minidump_thread_context_amd64_context_flags:
    seq:
      - id: control
        -orig-id: CONTROL  # 0x00000001
        type: b1
      - id: integer
        -orig-id: INTEGER  # 0x00000002
        type: b1
      - id: segments
        -orig-id: SEGMENTS  # 0x00000004
        type: b1
      - id: floating_point
        -orig-id: FLOATING_POINT  # 0x00000008
        type: b1
      - id: debug_registers
        -orig-id: DEBUG_REGISTERS  # 0x00000010
        type: b1
      - id: reserved5
        type: b1
      - id: xstate
        -orig-id: XSTATE  # 0x00000040
        type: b1
      - id: reserved7_to_19
        type: b13
      - id: amd64
        -orig-id: AMD64  # 0x00100000
        type: b1
      - id: reserved21_to_31
        type: b11

  minidump_thread_context_amd64_sse_control_status:
    seq:
      - id: ie
        -orig-id: IE  #0x0001
        type: b1
        doc: Invalid Operation Flag
      - id: de
        -orig-id: DE  #0x0002
        type: b1
        doc: Denormal Flag
      - id: ze
        -orig-id: ZE  #0x0004
        type: b1
        doc: Divide-by-Zero Flag
      - id: oe
        -orig-id: OE  #0x0008
        type: b1
        doc: Overflow Flag
      - id: ue
        -orig-id: UE  #0x0010
        type: b1
        doc: Underflow Flag
      - id: pe
        -orig-id: PE  #0x0020
        type: b1
        doc: Precision Flag
      - id: daz
        -orig-id: DAZ  #0x0040
        type: b1
        doc: Denormals Are Zeros
      - id: im
        -orig-id: IM  #0x0080
        type: b1
        doc: Invalid Operation Mask
      - id: dm
        -orig-id: DM  #0x0100
        type: b1
        doc: Denormal Operation Mask
      - id: zm
        -orig-id: ZM  #0x0200
        type: b1
        doc: Divide-by-Zero Mask
      - id: om
        -orig-id: OM  #0x0400
        type: b1
        doc: Overflow Mask
      - id: um
        -orig-id: UM  #0x0800
        type: b1
        doc: Underflow Mask
      - id: pm
        -orig-id: PM  #0x1000
        type: b1
        doc: Precision Mask
      - id: rc
        -orig-id: RC  #0x6000 (0x2000 + 0x4000)
        type: b2
        enum: minidump_thread_context_amd64_sse_control_status_rounding_control
        doc: Ronding Control
      - id: fz
        -orig-id: FZ  #0x8000
        type: b1
        doc: Flush to Zero
      - id: reserved16_to_31
        type: b16

  minidump_thread_context_amd64_floating_point:
    seq:
      - id: control_word
        type: u2
      - id: status_word
        type: u2
      - id: tag_word
        type: u1
      - id: reserved1
        type: u1
      - id: error_opcode
        type: u2
      - id: error_offset
        type: u4
      - id: error_selector
        type: u2
      - id: reserved2
        type: u2
      - id: data_offset
        type: u4
      - id: data_selector
        type: u2
      - id: reserved3
        type: u2
      - id: mx_csr
        type: u4
      - id: mx_csr_mask
        type: u4
      - id: float_registers
        type: minidump_u16
        repeat: expr
        repeat-expr: 8
      - id: xmm_registers
        type: minidump_u16
        repeat: expr
        repeat-expr: 16
      - id: reserved4
        size: 96

# Thread Context ARM  -------------------------------------------------------ARM
  minidump_thread_context_arm:
    seq:
      - id: context_flags
        type: minidump_thread_context_arm_context_flags
      - id: regs
        type: u4
        repeat: expr
        repeat-expr: 13
      - id: sp
        type: u4
      - id: lr
        type: u4
      - id: pc
        type: u4
      - id: cpsr
        type: minidump_thread_context_arm_cpsr
      # The fpscr register is 32 bit.
      # Breakpad declares this as 64 bit to avoid padding in the struct.
      # Crashpad declares this as 32 bit and has padding.
      # This works out due to everything in practice being little endian.
      # Go with crashpad since it is writing most of these.
      - id: fpscr
        type: minidump_thread_context_arm_fpscr
      - id: reserved
        type: u4
      - id: vfp
        type: u8
        repeat: expr
        repeat-expr: 32
        doc: d0 - d31
      - id: extra
        type: u4
        repeat: expr
        repeat-expr: 8

  minidump_thread_context_arm_context_flags:
    seq:
      - id: reserved0
        type: b1
      - id: integer
        -orig-id: INTEGER
        type: b1
      - id: floating_point
        -orig-id: FLOATING_POINT
        type: b1
      - id: reserved3_to_29
        type: b27
      - id: arm
        -orig-id: ARM
        type: b1
      - id: reserved31
        type: b1

  minidump_thread_context_arm_cpsr:
    seq:
      - id: m
        -orig-id: M
        type: b4
        enum: minidump_thread_context_arm_cpsr_mode
        doc: The current mode of the processor
      - id: reserved4
        -orig-id: Reserved4  #0x00000010
        type: b1
        doc: On ARMv7 and earlier was part of M and always 1
      - id: t
        -orig-id: T  #0x00000020
        type: b1
        doc: Thumb
      - id: f
        -orig-id: F  #0x00000040
        type: b1
        doc: FIQ mask
      - id: i
        -orig-id: I  #0x00000080
        type: b1
        doc: IRQ mask
      - id: a
        -orig-id: A  #0x00000100
        type: b1
        doc: Asynchronous/SError interrupt mask
      - id: e
        -orig-id: E  #0x00000200
        type: b1
        doc: Big endian
      - id: it_2
        -orig-id: IT_2  #0x00000400
        type: b1
        doc: If Then 2 (Thumb-2)
      - id: it_3
        -orig-id: IT_3  #0x00000800
        type: b1
        doc: If Then 3 (Thumb-2)
      - id: it_4
        -orig-id: IT_4  #0x00001000
        type: b1
        doc: If Then 4 (Thumb-2)
      - id: it_5
        -orig-id: IT_5  #0x00002000
        type: b1
        doc: If Then 5 (Thumb-2)
      - id: it_6
        -orig-id: IT_6  #0x00004000
        type: b1
        doc: If Then 6 (Thumb-2)
      - id: it_7
        -orig-id: IT_7  #0x00008000
        type: b1
        doc: If Then 7 (Thumb-2)
      - id: ge_1
        -orig-id: GE_1  #0x00010000
        type: b1
        doc: Greater than or Equal 1 (SIMD)
      - id: ge_2
        -orig-id: GE_2  #0x00020000
        type: b1
        doc: Greater than or Equal 2 (SIMD)
      - id: ge_3
        -orig-id: GE_3  #0x00040000
        type: b1
        doc: Greater than or Equal 3 (SIMD)
      - id: ge_4
        -orig-id: GE_4  #0x00080000
        type: b1
        doc: Greater than or Equal 4 (SIMD)
      - id: reserved20
        -orig-id: Reserved20  #0x00100000
        type: b1
      - id: dit
        -orig-id: DIT  #0x00200000
        type: b1
        doc: Data Independent Timing
      - id: pan
        -orig-id: PAN  #0x00400000
        type: b1
        doc: Privileged Access Never
      - id: ssbs
        -orig-id: SSBS  #0x00800000
        type: b1
        doc: Speculative Store Bypass Safe
      - id: j
        -orig-id: J  #0x01000000
        type: b1
        doc: Java / Jazelle
      - id: it_0
        -orig-id: IT_0  #0x02000000
        type: b1
        doc: If Then 0 (Thumb-2)
      - id: it_1
        -orig-id: IT_1  #0x04000000
        type: b1
        doc: If Then 1 (Thumb-2)
      - id: q
        -orig-id: Q  #0x08000000
        type: b1
        doc: Cumulative saturation
      - id: v
        -orig-id: V  #0x10000000
        type: b1
        doc: Overflow condition
      - id: c
        -orig-id: C  #0x20000000
        type: b1
        doc: Carry condition
      - id: z
        -orig-id: Z  #0x40000000
        type: b1
        doc: Zero condition
      - id: n
        -orig-id: N  #0x80000000
        type: b1
        doc: Negative condition

  minidump_thread_context_arm_fpscr:
    seq:
      - id: ioc
        -orig-id: IOC  #0x00000001
        type: b1
        doc: Invalid Operation Cumulative
      - id: dzc
        -orig-id: DZC  #0x00000002
        type: b1
        doc: Divide by Zero Cumulative
      - id: ofc
        -orig-id: OFC  #0x00000004
        type: b1
        doc: OverFlow Cumulative
      - id: ufc
        -orig-id: UFC  #0x00000008
        type: b1
        doc: UnderFlow Cumulative
      - id: ixc
        -orig-id: IXC  #0x00000010
        type: b1
        doc: IneXact Cumulative
      - id: reserved5_to_6
        type: b2
      - id: idc
        -orig-id: IDC  #0x00000080
        type: b1
        doc: Input Denormal Cumulative
      - id: ioe
        -orig-id: IOE  #0x00000100
        type: b1
        doc: Invalid Operations trap Enabled
      - id: dze
        -orig-id: DZE  #0x00000200
        type: b1
        doc: Divide-by-Zero trap Enabled
      - id: ofe
        -orig-id: OFE  #0x00000400
        type: b1
        doc: OverFlow trap Enabled
      - id: ufe
        -orig-id: UFE  #0x00000800
        type: b1
        doc: UnderFlow trap Enabled
      - id: ixe
        -orig-id: IXE  #0x00001000
        type: b1
        doc: IneXact trap Enabled
      - id: reserved13_to_14
        type: b2
      - id: ide
        -orig-id: IDE  #0x00008000
        type: b1
        doc: Input Denormal trap Enabled
      - id: len
        -orig-id: LEN  #0x00000000
        type: b3
        doc: Number of registers used by each vector
      - id: reserved19
        type: b1
      - id: stride
        -orig-id: STRIDE  #0x00300000
        type: b2
        enum: minidump_thread_context_arm_fpscr_stride
        doc: Distance between successive values in a vector
      - id: r
        -orig-id: R  #0x00c00000
        type: b2
        enum: minidump_thread_context_arm_fpscr_rounding_mode
        doc: Rounding mode
      - id: fz
        -orig-id: FZ  #0x01000000
        type: b1
        doc: Flush denormalized to Zero
      - id: dn
        -orig-id: DN  #0x02000000
        type: b1
        doc: Default NaN on NaN propagation
      - id: ahp
        -orig-id: AHP  #0x04000000
        type: b1
        doc: Alternative Half-Precision
      - id: qc
        -orig-id: QC  #0x08000000
        type: b1
        doc: VFP Cumulative saturation
      - id: v
        -orig-id: V  #0x10000000
        type: b1
        doc: VFP oVerflow condition
      - id: c
        -orig-id: C  #0x20000000
        type: b1
        doc: VFP Carry condition
      - id: z
        -orig-id: Z  #0x40000000
        type: b1
        doc: VFP Zero condition

# Thread Context ARM64  ---------------------------------------------------ARM64
  minidump_thread_context_arm64:
    seq:
      - id: context_flags
        type: minidump_thread_context_arm64_context_flags
      - id: cpsr
        type: minidump_thread_context_arm_cpsr
      - id: iregs
        type: u8
        repeat: expr
        repeat-expr: 29
      - id: fp
        type: u8
      - id: lr
        type: u8
      - id: sp
        type: u8
      - id: pc
        type: u8
      - id: float_regs
        type: minidump_u16
        repeat: expr
        repeat-expr: 32
      - id: fpcr
        type: minidump_thread_context_arm64_fpcr
      - id: fpsr
        type: minidump_thread_context_arm64_fpsr
      - id: bcr
        type: u4
        repeat: expr
        repeat-expr: 8
      - id: bvr
        type: u8
        repeat: expr
        repeat-expr: 8
      - id: wcr
        type: u4
        repeat: expr
        repeat-expr: 2
      - id: wvr
        type: u8
        repeat: expr
        repeat-expr: 2

  minidump_thread_context_arm64_context_flags:
    seq:
      - id: control
        -orig-id: CONTROL  #0x00000001
        type: b1
      - id: integer
        -orig-id: INTEGER  #0x00000002
        type: b1
      - id: floating_point
        -orig-id: FLOATING_POINT  #0x00000004
        type: b1
      - id: debug
        -orig-id: DEBUG  #0x00000008
        type: b1
      - id: reserved4_to_21
        type: b18
      - id: arm64
        -orig-id: ARM64  #0x00400000
        type: b1
      - id: reserved23_to_31
        type: b9

  minidump_thread_context_arm64_fpcr:
    seq:
      - id: fiz
        -orig-id: FIZ  #0x00000001
        type: b1
        doc: Flush denormalized Inputs to Zero
      - id: ah
        -orig-id: AH  #0x00000002
        type: b1
        doc: Alternate Handling (of denormalized floating point)
      - id: nep
        -orig-id: NEP  #0x00000004
        type: b1
        doc: Numeric Extended Precision (Scalar operations affect higher elements in vector registers)
      - id: reserved3_to_7
        type: b5
      - id: ioe
        -orig-id: IOE  #0x00000100
        type: b1
        doc: Invalid Operations trap Enabled
      - id: dze
        -orig-id: DZE  #0x00000200
        type: b1
        doc: Divide-by-Zero trap Enabled
      - id: ofe
        -orig-id: OFE  #0x00000400
        type: b1
        doc: OverFlow trap Enabled
      - id: ufe
        -orig-id: UFE  #0x00000800
        type: b1
        doc: UnderFlow trap Enabled
      - id: ixe
        -orig-id: IXE  #0x00001000
        type: b1
        doc: IneXact trap Enabled
      - id: reserved13
        type: b1
      - id: ide
        -orig-id: IDE  #0x00004000
        type: b1
        doc: Input Denormal trap Enabled
      - id: reserved15
        type: b1
      - id: reserved16_to_18
        type: b3
        doc: Previously Len 16-18
      - id: fz16
        -orig-id: FZ16  #0x00080000
        type: b1
        doc: Flush denormalized to Zero with 16 bit floats
      - id: reserved20_to_21
        type: b2
        doc: Previously Stride 20-21
      - id: r
        -orig-id: R  #0x00c00000
        type: b2
        enum: minidump_thread_context_arm_fpscr_rounding_mode
        doc: Rounding mode
      - id: fz
        -orig-id: FZ  #0x01000000
        type: b1
        doc: Flush denormalized to Zero
      - id: dn
        -orig-id: DN  #0x02000000
        type: b1
        doc: Default NaN on NaN propagation
      - id: ahp
        -orig-id: AHP  #0x04000000
        type: b1
        doc: Alternative Half-Precision
      - id: reserved27_to_31
        type: b5

  minidump_thread_context_arm64_fpsr:
    seq:
      - id: ioc
        -orig-id: IOC  #0x00000001
        type: b1
        doc: Invalid Operation Cumulative
      - id: dzc
        -orig-id: DZC  #0x00000002
        type: b1
        doc: Divide by Zero Cumulative
      - id: ofc
        -orig-id: OFC  #0x00000004
        type: b1
        doc: OverFlow Cumulative
      - id: ufc
        -orig-id: UFC  #0x00000008
        type: b1
        doc: UnderFlow Cumulative
      - id: ixc
        -orig-id: IXC  #0x00000010
        type: b1
        doc: IneXact Cumulative
      - id: reserved5_to_6
        type: b2
      - id: idc
        -orig-id: IDC  #0x00000080
        type: b1
        doc: Input Denormal Cumulative
      - id: reserved8_to_26
        type: b19
      - id: qc
        -orig-id: QC  #0x08000000
        type: b1
        doc: Cumulative saturation
      - id: v
        -orig-id: V  #0x10000000
        type: b1
        doc: AArch32 oVerflow condition
      - id: c
        -orig-id: C  #0x20000000
        type: b1
        doc: AArch32 Carry condition
      - id: z
        -orig-id: Z  #0x40000000
        type: b1
        doc: AArch32 Zero condition
      - id: n
        -orig-id: N  #0x80000000
        type: b1
        doc: AArch32 Negative condition

# Enumerationss ----------------------------------------------------------------
enums:
  minidump_stream_type:
    #-orig-id: MINIDUMP_STREAM_TYPE
    0:
      id: unused_stream
      -orig-id: UnusedStream
    1:
      id: reserved_stream_0
      -orig-id: ReservedStream0
    2:
      id: reserved_stream_1
      -orig-id: ReservedStream1
    3:
      id: thread_list_stream  # Done (X86, AMD64, ARM, ARM64)
      -orig-id: ThreadListStream
    4:
      id: module_list_stream  # Done
      -orig-id: ModuleListStream
    5:
      id: memory_list_stream  # Done
      -orig-id: MemoryListStream
    6:
      id: exception_stream  # Done (X86, AMD64, ARM, ARM64)
      -orig-id: ExceptionStream
    7:
      id: system_info_stream  # Done
      -orig-id: SystemInfoStream
    8:
      id: thread_ex_list_stream
      -orig-id: ThreadExListStream
    9:
      id: memory_64_list_stream
      -orig-id: Memory64ListStream
    10:
      id: comment_stream_a
      -orig-id: CommentStreamA
    11:
      id: comment_stream_w
      -orig-id: CommentStreamW
    12:
      id: handle_data_stream  # Done
      -orig-id: HandleDataStream
    13:
      id: function_table_stream
      -orig-id: FunctionTableStream
    14:
      id: unloaded_module_list_stream  # Done
      -orig-id: UnloadedModuleListStream
    15:
      id: misc_info_stream  # Done
      -orig-id: MiscInfoStream
    16:
      id: memory_info_list_stream  # Done
      -orig-id: MemoryInfoListStream
    17:
      id: thread_info_list_stream
      -orig-id: ThreadInfoListStream
    18:
      id: handle_operation_list_stream
      -orig-id: HandleOperationListStream
    19:
      id: token_stream
      -orig-id: TokenStream
    20:
      id: java_script_data_stream
      -orig-id: JavaScriptDataStream
    21:
      id: system_memory_info_stream
      -orig-id: SystemMemoryInfoStream
    22:
      id: process_vm_counters_stream
      -orig-id: ProcessVMCountersStream
    23:
      id: ipt_trace_stream
      -orig-id: IptTraceStream
    24:
      id: thread_names_stream  # Done
      -orig-id: ThreadNamesStream
    0x8000: ce_stream_null
    0x8001: ce_stream_system_info
    0x8002: ce_stream_exception
    0x8003: ce_stream_module_list
    0x8004: ce_stream_process_list
    0x8005: ce_stream_thread_list
    0x8006: ce_stream_thread_context_list
    0x8007: ce_stream_thread_call_stack_list
    0x8008: ce_stream_memory_virtual_list
    0x8009: ce_stream_memory_physical_list
    0x800A: ce_stream_bucket_parameters
    0x800B: ce_stream_process_module_map
    0x800C: ce_stream_diagnosis_list
    0xffff: last_reserved_stream
    # Breakpad extension types.
    # Breakpad's src/google_breakpad/common/minidump_format.h
    # 0x4767 = "Gg"
    0x47670001:
      id: breakpad_info_stream
      -orig-id: MDRawBreakpadInfo
    0x47670002:
      id: breakpad_assertion_info_stream
      -orig-id: MDRawAssertionInfo
    0x47670003:
      id: breakpad_linux_cpu_info
      doc: /proc/cpuinfo
    0x47670004:
      id: breakpad_linux_proc_status
      doc: /proc/$x/status
    0x47670005:
      id: breakpad_linux_lsb_release
      doc: /etc/lsb-release
    0x47670006:
      id: breakpad_linux_cmd_line
      doc: /proc/$x/cmdline
    0x47670007:
      id: breakpad_linux_environ
      doc: /proc/$x/environ
    0x47670008:
      id: breakpad_linux_auxv
      doc: /proc/$x/auxv
    0x47670009:
      id: breakpad_linux_maps
      doc: /proc/$x/maps
    0x4767000a:
      id: breakpad_linux_dso_debug
      -orig-id: MDRawDebug
    # Crashpad extension types
    # See Crashpad's minidump/minidump_extensions.h
    #0x4350 = "CP"
    0x43500001:
      id: crashpad_info_stream  # Done
      -orig-id: MDRawCrashpadInfo
    # Crashpad allows user streams, see crashpad::UserStreamDataSource.
    # These are Chromium specific protobuf streams.
    # 0x4B6B = "Kk"
    0x4B6B0002:
      id: chromium_stability_report
      doc: components/stability_report/stability_report.proto
    0x4B6B0003:
      id: chromium_system_profile
      doc: third_party/metrics_proto/system_profile.proto
    0x4B6B0004:
      id: chromium_gwp_asan_crash
      doc: components/gwp_asan/crash_handler/crash.proto

  minidump_processor_architecture:
    0:
      id: intel_x86
      -orig-id: INTEL_X86
    1:
      id: mips
      -orig-id: MIPS
    2:
      id: alpha
      -orig-id: ALPHA
    3:
      id: ppc
      -orig-id: PPC
    4:
      id: shx
      -orig-id: SHX
    5:
      id: arm
      -orig-id: ARM
    6:
      id: ia64
      -orig-id: IA64
    7:
      id: alpha64
      -orig-id: ALPHA64
    8:
      id: msil
      -orig-id: MSIL
    9:
      id: amd64
      -orig-id: AMD64
    10:
      id: ia32_on_win64
      -orig-id: IA32_ON_WIN64
    12:
      id: arm64
      -orig-id: ARM64
    # Breakpad-defined
    0x8001:
      id: sparc
      -orig-id: SPARC
    0x8002:
      id: ppc64
      -orig-id: PPC64
    0x8003:
      id: arm64_old
      -orig-id: ARM64_OLD
    0x8004:
      id: mips64
      -orig-id: MIPS64
    0x8005:
      id: riscv
      -orig-id: RISCV
    0x8006:
      id: riscv64
      -orig-id: RISCV64
    # Unknown
    0xffff:
      id: unknown
      -orig-id: UNKNOWN

  minidump_platform_id:
    0:
      id: win32s
      -orig-id: WIN32S
      doc: Windows 3.1
    1:
      id: windows
      -orig-id: WINDOWS
      doc: Windows 95-98-Me
    2:
      id: win32_nt
      -orig-id: WIN32_NT
      doc: Windows NT, 2000+
    3:
      id: win32_ce
      -orig-id: WIN32_CE
      doc: CE, Mobile, Handheld

    # Breakpad-defined
    0x8000:
      id: unix
      -orig-id: UNIX
    0x8101:
      id: mac_os_x
      -orig-id: MAC_OS_X
    0x8102:
      id: ios
      -orig-id: IOS
    0x8201:
      id: linux
      -orig-id: LINUX
    0x8202:
      id: solaris
      -orig-id: SOLARIS
    0x8203:
      id: android
      -orig-id: ANDROID
    0x8204:
      id: ps3
      -orig-id: PS3
    0x8205:
      id: nacl
      -orig-id: NACL
    0x8206:
      id: fuchsia
      -orig-id: FUCHSIA

  minidump_thread_context_amd64_sse_control_status_rounding_control:
    0x0:
      id: n
      -orig-id: N  #0x0000
      doc: toward Nearest
    0x1:
      id: ni
      -orig-id: RC_NI  #0x2000
      doc: toward Negative Infinity
    0x2:
      id: pi
      -orig-id: RC_PI  #0x4000
      doc: toward Positive Infinity
    0x3:
      id: z
      -orig-id: RC_Z  #0x6000
      doc: toward Zero

  minidump_thread_context_arm_cpsr_mode:  # 5 bits
    0x00:
      id: usr
      -orig-id: USR
      doc: User mode
    0x01:
      id: fiq
      -orig-id: FIQ
      doc: Fast or high priority interrupt mode
    0x02:
      id: irq
      -orig-id: IRQ
      doc: Normal or low priority interrupt mode
    0x03:
      id: svc
      -orig-id: SVC
      doc: Supervisor mode (software interrupt handler)
    0x06:
      id: mon
      -orig-id: MON
      doc: Monitor mode (Secure mode / SMC)
    0x07:
      id: abt
      -orig-id: ABT
      doc: Abort mode (memory access violation handler)
    0x0a:
      id: hyp
      -orig-id: HYP
      doc: Hypervisor mode (Virtualization Extensions)
    0x0b:
      id: und
      -orig-id: UND
      doc: Undef mode (undefined instruction handler)
    0x0f:
      id: sys
      -orig-id: SYS
      doc: System mode (privileged with user registers)

  minidump_thread_context_arm_fpscr_stride:
    0x0: one
    0x3: two

  minidump_thread_context_arm_fpscr_rounding_mode:
    0x0:
      id: rn
      -orig-id: RN  #0x00000000
      doc: Round to Nearest (half to even)
    0x1:
      id: rp
      -orig-id: RP  #0x00400000
      doc: Round to Plus Infinity
    0x2:
      id: rm
      -orig-id: RM  #0x00800000
      doc: Round to Minus Infinity
    0x3:
      id: rz
      -orig-id: RZ  #0x00c00000
      doc: Round to Zero

  # These are flags, but are being used as an enumeration in this context
  minidump_memory_info_state:
    0x00001000:
      id: mem_commit
      -orig-id: MEM_COMMIT
    0x00002000:
      id: mem_reserve
      -orig-id: MEM_RESERVE
    0x00004000:
      id: mem_decommit
      -orig-id: MEM_DECOMMIT
    0x00008000:
      id: mem_release
      -orig-id: MEM_RELEASE
    0x00010000:
      id: mem_free
      -orig-id: MEM_FREE

  # These are flags, but are being used as an enumeration in this context
  minidump_memory_info_type:
    0x00020000:
      id: mem_private
      -orig-id: MEM_PRIVATE
    0x00040000:
      id: mem_mapped
      -orig-id: MEM_MAPPED
    0x01000000:
      id: mem_image
      -orig-id: MEM_IMAGE

