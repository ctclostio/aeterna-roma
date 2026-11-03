cmake_minimum_required(VERSION 3.25)

cmake_policy(SET CMP0091 NEW)

project(
  Rome2DecompPort
  VERSION 0.1.0
  DESCRIPTION "64-bit recompilation scaffold for the Rome II decompilation"
  LANGUAGES C
)

if(NOT WIN32)
  message(FATAL_ERROR "The current port scaffold targets Windows only.")
endif()

if(NOT MSVC)
  message(FATAL_ERROR "The current port scaffold requires the MSVC toolchain.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Configure with an x64 compiler environment.")
endif()

include(CTest)

set(ROME2_BOOTSTRAP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap")
set(ROME2_GUEST32_RUNTIME_DIR "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_runtime")
set(ROME2_GUEST32_PORTED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_ported")
set(ROME2_GUEST32_PROBE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe")
set(ROME2_HEADLESS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless")
set(
  ROME2_CANONICAL_ROOT
  "${CMAKE_CURRENT_SOURCE_DIR}/src_canonical_out/empire.retail.dll"
  CACHE PATH
  "Canonical exporter output for empire.retail.dll"
)
set(
  ROME2_CANONICAL_STAGE_BASE
  "${CMAKE_CURRENT_SOURCE_DIR}/generated/canonical"
  CACHE PATH
  "Parent directory containing immutable fingerprint-scoped canonical stages"
)

set(ROME2_CANONICAL_SNAPSHOT "${ROME2_CANONICAL_ROOT}/canonical_snapshot.tsv")
if(NOT EXISTS "${ROME2_CANONICAL_SNAPSHOT}")
  message(FATAL_ERROR "Canonical snapshot not found: ${ROME2_CANONICAL_SNAPSHOT}")
endif()

file(STRINGS "${ROME2_CANONICAL_SNAPSHOT}" ROME2_CANONICAL_SNAPSHOT_LINES ENCODING UTF-8)
list(LENGTH ROME2_CANONICAL_SNAPSHOT_LINES ROME2_CANONICAL_SNAPSHOT_LINE_COUNT)
if(NOT ROME2_CANONICAL_SNAPSHOT_LINE_COUNT EQUAL 2)
  message(FATAL_ERROR "Canonical snapshot must contain exactly a header and one data row.")
endif()

list(GET ROME2_CANONICAL_SNAPSHOT_LINES 0 ROME2_CANONICAL_SNAPSHOT_HEADER)
set(
  ROME2_EXPECTED_SNAPSHOT_HEADER
  "format\texecutable_sha256\tmapping_fingerprint\tfunctions\tdata_symbols"
)
if(NOT ROME2_CANONICAL_SNAPSHOT_HEADER STREQUAL ROME2_EXPECTED_SNAPSHOT_HEADER)
  message(FATAL_ERROR "Canonical snapshot has an unexpected schema.")
endif()

list(GET ROME2_CANONICAL_SNAPSHOT_LINES 1 ROME2_CANONICAL_SNAPSHOT_ROW)
string(REPLACE "\t" ";" ROME2_CANONICAL_FIELDS "${ROME2_CANONICAL_SNAPSHOT_ROW}")
list(LENGTH ROME2_CANONICAL_FIELDS ROME2_CANONICAL_FIELD_COUNT)
if(NOT ROME2_CANONICAL_FIELD_COUNT EQUAL 5)
  message(FATAL_ERROR "Canonical snapshot data row must contain exactly five fields.")
endif()
list(GET ROME2_CANONICAL_FIELDS 0 ROME2_CANONICAL_FORMAT)
list(GET ROME2_CANONICAL_FIELDS 1 ROME2_CANONICAL_EXECUTABLE_SHA256)
list(GET ROME2_CANONICAL_FIELDS 2 ROME2_CANONICAL_FINGERPRINT)
list(GET ROME2_CANONICAL_FIELDS 3 ROME2_CANONICAL_FUNCTION_COUNT)
list(GET ROME2_CANONICAL_FIELDS 4 ROME2_CANONICAL_DATA_SYMBOL_COUNT)

if(NOT ROME2_CANONICAL_FORMAT STREQUAL "canonical-address-v2")
  message(FATAL_ERROR "Unsupported canonical format: ${ROME2_CANONICAL_FORMAT}")
endif()
string(LENGTH "${ROME2_CANONICAL_EXECUTABLE_SHA256}" ROME2_EXECUTABLE_SHA256_LENGTH)
string(LENGTH "${ROME2_CANONICAL_FINGERPRINT}" ROME2_FINGERPRINT_LENGTH)
if(NOT ROME2_EXECUTABLE_SHA256_LENGTH EQUAL 64 OR
   NOT ROME2_CANONICAL_EXECUTABLE_SHA256 MATCHES "^[0-9a-f]+$")
  message(FATAL_ERROR "Canonical executable SHA-256 is malformed.")
endif()
if(NOT ROME2_FINGERPRINT_LENGTH EQUAL 64 OR
   NOT ROME2_CANONICAL_FINGERPRINT MATCHES "^[0-9a-f]+$")
  message(FATAL_ERROR "Canonical mapping fingerprint is malformed.")
endif()
if(NOT ROME2_CANONICAL_FUNCTION_COUNT MATCHES "^[0-9]+$" OR
   NOT ROME2_CANONICAL_DATA_SYMBOL_COUNT MATCHES "^[0-9]+$")
  message(FATAL_ERROR "Canonical snapshot counts are malformed.")
endif()

set(
  ROME2_CANONICAL_STAGE
  "${ROME2_CANONICAL_STAGE_BASE}/${ROME2_CANONICAL_FINGERPRINT}"
)
set(ROME2_CANONICAL_SUMMARY "${ROME2_CANONICAL_STAGE}/validation_summary.json")
set(ROME2_STAGED_SNAPSHOT "${ROME2_CANONICAL_STAGE}/metadata/canonical_snapshot.tsv")
if(NOT EXISTS "${ROME2_CANONICAL_SUMMARY}" OR NOT EXISTS "${ROME2_STAGED_SNAPSHOT}")
  message(FATAL_ERROR
    "Completed canonical stage not found for ${ROME2_CANONICAL_FINGERPRINT}. "
    "Run scripts/gen_canonical_skeleton.py before configuring the port."
  )
endif()

file(READ "${ROME2_CANONICAL_SUMMARY}" ROME2_CANONICAL_SUMMARY_JSON)
string(JSON ROME2_SUMMARY_COMPLETE GET "${ROME2_CANONICAL_SUMMARY_JSON}" complete)
string(JSON ROME2_SUMMARY_EXECUTABLE_VERIFIED GET
  "${ROME2_CANONICAL_SUMMARY_JSON}" executable_verified)
string(JSON ROME2_SUMMARY_FINGERPRINT GET
  "${ROME2_CANONICAL_SUMMARY_JSON}" mapping_fingerprint)
string(JSON ROME2_SUMMARY_EXECUTABLE_SHA256 GET
  "${ROME2_CANONICAL_SUMMARY_JSON}" executable_sha256)
string(JSON ROME2_SUMMARY_FUNCTION_COUNT GET
  "${ROME2_CANONICAL_SUMMARY_JSON}" expected_functions)
string(JSON ROME2_SUMMARY_DATA_SYMBOL_COUNT GET
  "${ROME2_CANONICAL_SUMMARY_JSON}" indexed_data_symbols)
string(JSON ROME2_SUMMARY_SOURCE_SUCCESS GET
  "${ROME2_CANONICAL_SUMMARY_JSON}" source_success)
string(JSON ROME2_SUMMARY_SNAPSHOT_SHA256 GET
  "${ROME2_CANONICAL_SUMMARY_JSON}" metadata_sha256 "canonical_snapshot.tsv")

if(NOT ROME2_SUMMARY_COMPLETE OR NOT ROME2_SUMMARY_EXECUTABLE_VERIFIED)
  message(FATAL_ERROR "Canonical stage is not complete and executable-verified.")
endif()
if(NOT ROME2_SUMMARY_FINGERPRINT STREQUAL ROME2_CANONICAL_FINGERPRINT OR
   NOT ROME2_SUMMARY_EXECUTABLE_SHA256 STREQUAL ROME2_CANONICAL_EXECUTABLE_SHA256 OR
   NOT ROME2_SUMMARY_FUNCTION_COUNT STREQUAL ROME2_CANONICAL_FUNCTION_COUNT OR
   NOT ROME2_SUMMARY_DATA_SYMBOL_COUNT STREQUAL ROME2_CANONICAL_DATA_SYMBOL_COUNT OR
   NOT ROME2_SUMMARY_SOURCE_SUCCESS STREQUAL ROME2_CANONICAL_FUNCTION_COUNT)
  message(FATAL_ERROR "Canonical stage summary does not match the exporter snapshot.")
endif()

file(SHA256 "${ROME2_CANONICAL_SNAPSHOT}" ROME2_CANONICAL_SNAPSHOT_SHA256)
file(SHA256 "${ROME2_STAGED_SNAPSHOT}" ROME2_STAGED_SNAPSHOT_SHA256)
if(NOT ROME2_CANONICAL_SNAPSHOT_SHA256 STREQUAL ROME2_SUMMARY_SNAPSHOT_SHA256 OR
   NOT ROME2_STAGED_SNAPSHOT_SHA256 STREQUAL ROME2_SUMMARY_SNAPSHOT_SHA256)
  message(FATAL_ERROR "Canonical snapshot hash does not match the immutable stage summary.")
endif()

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(
  "${ROME2_BOOTSTRAP_DIR}/canonical_identity.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/generated/canonical_identity.h"
  @ONLY
)
message(STATUS "Canonical stage accepted: ${ROME2_CANONICAL_FINGERPRINT}")

set(ROME2_HARDENED_COMPILE_OPTIONS
  # Remove wall-clock COFF timestamps so release artifacts can be authenticated
  # after a clean rebuild instead of only within one build directory.
  /Brepro
  /W4
  /WX
  /sdl
  /GS
  /guard:cf
)
set(ROME2_HARDENED_LINK_OPTIONS
  /Brepro
  /INCREMENTAL:NO
  /DYNAMICBASE
  /HIGHENTROPYVA
  /NXCOMPAT
  /CETCOMPAT
  /guard:cf
  /WX
)

function(rome2_configure_x64_target target)
  target_compile_features(${target} PRIVATE c_std_17)
  target_compile_definitions(
    ${target}
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(${target} PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS})
  target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
  target_link_options(${target} PRIVATE ${ROME2_HARDENED_LINK_OPTIONS})
  set_property(
    TARGET ${target}
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )
endfunction()

add_library(
  empire_retail_bootstrap
  SHARED
  "${ROME2_BOOTSTRAP_DIR}/bootstrap_contract.h"
  "${ROME2_BOOTSTRAP_DIR}/empire_bootstrap.c"
  "${ROME2_BOOTSTRAP_DIR}/empire_bootstrap.def"
)
rome2_configure_x64_target(empire_retail_bootstrap)
target_link_options(
  empire_retail_bootstrap
  PRIVATE
    /MACHINE:X64
    /SUBSYSTEM:CONSOLE,6.00
    /BASE:0x180000000
    /OPT:NOICF
)
set_target_properties(
  empire_retail_bootstrap
  PROPERTIES
    OUTPUT_NAME "empire.retail64"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

add_executable(
  empire_bootstrap_smoke
  "${ROME2_BOOTSTRAP_DIR}/bootstrap_contract.h"
  "${ROME2_BOOTSTRAP_DIR}/smoke_loader.c"
)
rome2_configure_x64_target(empire_bootstrap_smoke)
target_link_options(
  empire_bootstrap_smoke
  PRIVATE
    /MACHINE:X64
    /SUBSYSTEM:CONSOLE,6.00
)
set_target_properties(
  empire_bootstrap_smoke
  PROPERTIES
    OUTPUT_NAME "rome2_host64"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

add_library(
  rome2_guest32_runtime
  STATIC
  EXCLUDE_FROM_ALL
  "${ROME2_GUEST32_RUNTIME_DIR}/guest32.h"
  "${ROME2_GUEST32_RUNTIME_DIR}/guest32.c"
  "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_policy.h"
  "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_policy.c"
  "${ROME2_GUEST32_PORTED_DIR}/ported_1093c450.h"
  "${ROME2_GUEST32_PORTED_DIR}/ported_1093c450.c"
)
target_compile_features(rome2_guest32_runtime PUBLIC c_std_17)
target_compile_definitions(
  rome2_guest32_runtime
  PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    WINVER=0x0602
    _WIN32_WINNT=0x0602
)
target_compile_options(
  rome2_guest32_runtime
  PRIVATE
    ${ROME2_HARDENED_COMPILE_OPTIONS}
)
target_include_directories(
  rome2_guest32_runtime
  PUBLIC
    "${ROME2_GUEST32_RUNTIME_DIR}"
    "${ROME2_GUEST32_PORTED_DIR}"
)
set_property(
  TARGET rome2_guest32_runtime
  PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

# This milestone is intentionally test-only.  Any direct link dependency on
# the bootstrap DLL is a configure-time containment failure, even if the linker
# would later discard every unused object from the archive.
get_target_property(
  ROME2_BOOTSTRAP_DIRECT_LINKS
  empire_retail_bootstrap
  LINK_LIBRARIES
)
if(ROME2_BOOTSTRAP_DIRECT_LINKS)
  message(FATAL_ERROR
    "empire_retail_bootstrap must have no direct target_link_libraries dependencies; "
    "guest32 and entry-policy code remain test-only"
  )
endif()

if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)

  # This recovered writable leaf remains separate from the shared read-only
  # guest32 archive and from every DLL.  It exists only to support its isolated
  # test executable while BUILD_TESTING is enabled.
  add_library(
    rome2_startup_100f1c10_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1c10_triplet.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1c10_triplet.c"
  )
  target_compile_features(rome2_startup_100f1c10_runtime PUBLIC c_std_17)
  target_compile_definitions(
    rome2_startup_100f1c10_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100f1c10_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100f1c10_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  set_property(
    TARGET rome2_startup_100f1c10_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  # Phase 4.2: battle unit card descriptor (0x10145c70) and battle entity
  # dispatcher (0x10cbe350), both reconstructed from the retail x86 body and
  # called by the settlement battle benchmark harness at 0x100e39c0.  The two
  # share the recovered twelve-byte std::string ABI, so they ship in one
  # test-only archive; neither links against any DLL.
  add_library(
    rome2_battle_entity_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_10145c70_unitcard.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_10145c70_unitcard.c"
    "${ROME2_GUEST32_PORTED_DIR}/ported_10cbe350_entity.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_10cbe350_entity.c"
  )
  target_compile_features(rome2_battle_entity_runtime PUBLIC c_std_17)
  target_compile_definitions(
    rome2_battle_entity_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_battle_entity_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_battle_entity_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  set_property(
    TARGET rome2_battle_entity_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_battle_unitcard_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_battle_unitcard_10145c70.c"
  )
  rome2_configure_x64_target(rome2_battle_unitcard_tests)
  target_link_libraries(
    rome2_battle_unitcard_tests
    PRIVATE rome2_battle_entity_runtime
  )
  target_link_options(
    rome2_battle_unitcard_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_battle_unitcard_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  add_executable(
    rome2_battle_entity_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_battle_entity_10cbe350.c"
  )
  rome2_configure_x64_target(rome2_battle_entity_tests)
  target_link_libraries(
    rome2_battle_entity_tests
    PRIVATE rome2_battle_entity_runtime
  )
  target_link_options(
    rome2_battle_entity_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_battle_entity_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  add_executable(
    rome2_startup_100f1c10_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f1c10.c"
  )
  rome2_configure_x64_target(rome2_startup_100f1c10_tests)
  target_link_libraries(
    rome2_startup_100f1c10_tests
    PRIVATE rome2_startup_100f1c10_runtime
  )
  target_link_options(
    rome2_startup_100f1c10_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100f1c10_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # This is only the zero-count route through original
  # 0x100f1aa0 -> 0x100ef330.  Its final triplet write is delegated to the
  # already accepted test-only 0x100f1c10 implementation.  The allocating
  # branch and both recovered functions remain otherwise unlinked.
  add_library(
    rome2_startup_100f1aa0_empty_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1aa0_empty.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1aa0_empty.c"
  )
  target_compile_features(rome2_startup_100f1aa0_empty_runtime PUBLIC c_std_17)
  target_compile_definitions(
    rome2_startup_100f1aa0_empty_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100f1aa0_empty_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100f1aa0_empty_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100f1aa0_empty_runtime
    PRIVATE rome2_startup_100f1c10_runtime
  )
  set_property(
    TARGET rome2_startup_100f1aa0_empty_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  # Two read/no-op seams from the next startup closure: only the bounded
  # 0x100f1bb0 UTF-16 length loop and the null/sentinel branches of 0x100f1cc0.
  # The allocator, release helper, mutable callback, and parent stay unlinked.
  add_library(
    rome2_startup_safe_seams_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_bounded.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_bounded.c"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1cc0_nonowning.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1cc0_nonowning.c"
  )
  target_compile_features(rome2_startup_safe_seams_runtime PUBLIC c_std_17)
  target_compile_definitions(
    rome2_startup_safe_seams_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_safe_seams_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_safe_seams_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_safe_seams_runtime
    PRIVATE rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_safe_seams_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_safe_seams_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_safe_seams.c"
  )
  rome2_configure_x64_target(rome2_startup_safe_seams_tests)
  target_link_libraries(
    rome2_startup_safe_seams_tests
    PRIVATE rome2_startup_safe_seams_runtime
  )
  target_link_options(
    rome2_startup_safe_seams_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_safe_seams_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Deterministic post-platform field projection from original
  # 0x100df343-0x100df46c.  The Win32 prefix, global publication,
  # initializer calls, allocation paths, and indirect dispatch stay unlinked.
  add_library(
    rome2_startup_100df270_headless_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_headless.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_headless.c"
  )
  target_compile_features(
    rome2_startup_100df270_headless_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100df270_headless_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100df270_headless_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100df270_headless_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100df270_headless_runtime
    PRIVATE rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_100df270_headless_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100df270_headless_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100df270_headless.c"
  )
  rome2_configure_x64_target(rome2_startup_100df270_headless_tests)
  target_link_libraries(
    rome2_startup_100df270_headless_tests
    PRIVATE rome2_startup_100df270_headless_runtime
  )
  target_link_options(
    rome2_startup_100df270_headless_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100df270_headless_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Short, forward, disjoint nonallocating branch from original 0x100f2750.
  # The allocation/release route, overlap route, and >=32-byte helper paths
  # remain rejected and unlinked.
  add_library(
    rome2_startup_100f2750_nonalloc_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_nonalloc.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_nonalloc.c"
  )
  target_compile_features(
    rome2_startup_100f2750_nonalloc_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100f2750_nonalloc_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100f2750_nonalloc_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100f2750_nonalloc_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100f2750_nonalloc_runtime
    PRIVATE rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_100f2750_nonalloc_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100f2750_nonalloc_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f2750_nonalloc.c"
  )
  rome2_configure_x64_target(rome2_startup_100f2750_nonalloc_tests)
  target_link_libraries(
    rome2_startup_100f2750_nonalloc_tests
    PRIVATE rome2_startup_100f2750_nonalloc_runtime
  )
  target_link_options(
    rome2_startup_100f2750_nonalloc_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100f2750_nonalloc_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Bounded no-crash fast path of original 0x100e8240.  Only the read-only
  # branch that returns the crash-record identity 0x119f3a38 is ported; the
  # crash-handler/crash-file window 0x100e8268-0x100e8376 stays rejected and
  # unlinked.  The adjacent suffix 0x100ea4d0 is evidence-only (every path
  # allocates or mutates) and has no executable port.
  add_library(
    rome2_startup_100e8240_fastpath_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e8240_fastpath.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e8240_fastpath.c"
  )
  target_compile_features(
    rome2_startup_100e8240_fastpath_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e8240_fastpath_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e8240_fastpath_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e8240_fastpath_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100e8240_fastpath_runtime
    PRIVATE rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_100e8240_fastpath_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e8240_fastpath_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8240_fastpath.c"
  )
  rome2_configure_x64_target(rome2_startup_100e8240_fastpath_tests)
  target_link_libraries(
    rome2_startup_100e8240_fastpath_tests
    PRIVATE rome2_startup_100e8240_fastpath_runtime
  )
  target_link_options(
    rome2_startup_100e8240_fastpath_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e8240_fastpath_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Allocation-free append prefix of original 0x100e2460.  This helper commits
  # only backing[count] and count+1 when count < capacity; the admitted branch
  # successors below add injected effects without changing this helper's
  # narrow contract.
  add_library(
    rome2_startup_100e2460_append_prefix_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_append_prefix.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_append_prefix.c"
  )
  target_compile_features(
    rome2_startup_100e2460_append_prefix_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e2460_append_prefix_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e2460_append_prefix_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e2460_append_prefix_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100e2460_append_prefix_runtime
    PRIVATE rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_100e2460_append_prefix_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e2460_append_prefix_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_append_prefix.c"
  )
  rome2_configure_x64_target(rome2_startup_100e2460_append_prefix_tests)
  target_link_libraries(
    rome2_startup_100e2460_append_prefix_tests
    PRIVATE rome2_startup_100e2460_append_prefix_runtime
  )
  target_link_options(
    rome2_startup_100e2460_append_prefix_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e2460_append_prefix_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Complete the authenticated count < capacity branch of original
  # 0x100e2460 with total injected dispatch/message effects and an explicit
  # finite drain bound.  The allocator/growth routes, native USER32 calls,
  # and guest-to-native indirect calls remain excluded.
  add_library(
    rome2_startup_100e2460_preallocated_branch_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_preallocated_branch.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_preallocated_branch.c"
  )
  target_compile_features(
    rome2_startup_100e2460_preallocated_branch_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e2460_preallocated_branch_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e2460_preallocated_branch_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e2460_preallocated_branch_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100e2460_preallocated_branch_runtime
    PRIVATE rome2_startup_100e2460_append_prefix_runtime
  )
  set_property(
    TARGET rome2_startup_100e2460_preallocated_branch_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e2460_preallocated_branch_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_preallocated_branch.c"
  )
  rome2_configure_x64_target(rome2_startup_100e2460_preallocated_branch_tests)
  target_link_libraries(
    rome2_startup_100e2460_preallocated_branch_tests
    PRIVATE rome2_startup_100e2460_preallocated_branch_runtime
  )
  target_link_options(
    rome2_startup_100e2460_preallocated_branch_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e2460_preallocated_branch_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Complete the authenticated capacity == 0, count == 0 branch of original
  # 0x100e2460 with a total injected four-byte guest allocator and the
  # already-bounded preallocated dispatch/message tail.  Native allocation,
  # native USER32 calls, and the growth/copy/free route remain excluded.
  add_library(
    rome2_startup_100e2460_capacity_zero_branch_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_capacity_zero_branch.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_capacity_zero_branch.c"
  )
  target_compile_features(
    rome2_startup_100e2460_capacity_zero_branch_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e2460_capacity_zero_branch_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e2460_capacity_zero_branch_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e2460_capacity_zero_branch_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100e2460_capacity_zero_branch_runtime
    PRIVATE rome2_startup_100e2460_preallocated_branch_runtime
  )
  set_property(
    TARGET rome2_startup_100e2460_capacity_zero_branch_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e2460_capacity_zero_branch_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_capacity_zero_branch.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e2460_capacity_zero_branch_tests
  )
  target_link_libraries(
    rome2_startup_100e2460_capacity_zero_branch_tests
    PRIVATE rome2_startup_100e2460_capacity_zero_branch_runtime
  )
  target_link_options(
    rome2_startup_100e2460_capacity_zero_branch_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e2460_capacity_zero_branch_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Complete the authenticated capacity > 0, count == capacity growth route
  # of original 0x100e2460 with total injected allocation/release adapters and
  # the bounded dispatch/message tail.  Native allocation, release, USER32,
  # and guest-to-host indirect calls remain excluded.
  add_library(
    rome2_startup_100e2460_growth_branch_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_growth_branch.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_growth_branch.c"
  )
  target_compile_features(
    rome2_startup_100e2460_growth_branch_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e2460_growth_branch_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e2460_growth_branch_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e2460_growth_branch_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  set_property(
    TARGET rome2_startup_100e2460_growth_branch_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e2460_growth_branch_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_growth_branch.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e2460_growth_branch_tests
  )
  target_link_libraries(
    rome2_startup_100e2460_growth_branch_tests
    PRIVATE rome2_startup_100e2460_growth_branch_runtime
  )
  target_link_options(
    rome2_startup_100e2460_growth_branch_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e2460_growth_branch_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Route one complete bounded append through the exact unsigned selector of
  # original 0x100e2460.  The router snapshots the full injected-effects
  # superset and delegates to the already-authenticated preallocated,
  # capacity-zero, or nonzero-growth implementation; it adds no native
  # allocation, release, platform, or guest-dispatch edge.
  add_library(
    rome2_startup_100e2460_router_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_router.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_router.c"
  )
  target_compile_features(
    rome2_startup_100e2460_router_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e2460_router_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e2460_router_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e2460_router_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100e2460_router_runtime
    PRIVATE
      rome2_startup_100e2460_preallocated_branch_runtime
      rome2_startup_100e2460_capacity_zero_branch_runtime
      rome2_startup_100e2460_growth_branch_runtime
  )
  set_property(
    TARGET rome2_startup_100e2460_router_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e2460_router_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_router.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e2460_router_tests
  )
  target_link_libraries(
    rome2_startup_100e2460_router_tests
    PRIVATE rome2_startup_100e2460_router_runtime
  )
  target_link_options(
    rome2_startup_100e2460_router_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e2460_router_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  add_executable(
    rome2_startup_100e2460_router_six_append_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_router_six_append.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e2460_router_six_append_tests
  )
  target_link_libraries(
    rome2_startup_100e2460_router_six_append_tests
    PRIVATE rome2_startup_100e2460_router_runtime
  )
  target_link_options(
    rome2_startup_100e2460_router_six_append_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e2460_router_six_append_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # First concrete handler in the six-registration order.  The original
  # performs six platform/global calls; the port emits their authenticated
  # typed transcript through one total injected callback and publishes AL=1
  # only after the final effect.
  add_library(
    rome2_startup_100e8d00_handler_transcript_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e8d00_handler_transcript.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e8d00_handler_transcript.c"
  )
  target_compile_features(
    rome2_startup_100e8d00_handler_transcript_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e8d00_handler_transcript_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e8d00_handler_transcript_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e8d00_handler_transcript_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  set_property(
    TARGET rome2_startup_100e8d00_handler_transcript_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e8d00_handler_transcript_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8d00_handler_transcript.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e8d00_handler_transcript_tests
  )
  target_link_libraries(
    rome2_startup_100e8d00_handler_transcript_tests
    PRIVATE rome2_startup_100e8d00_handler_transcript_runtime
  )
  target_link_options(
    rome2_startup_100e8d00_handler_transcript_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e8d00_handler_transcript_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Second concrete handler in original order.  Its only callee is an
  # authenticated one-byte RET, so this adapter has no injected or native
  # effect and publishes only the original normal-path AL=1.
  add_library(
    rome2_startup_100e85d0_normal_adapter_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e85d0_normal_adapter.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e85d0_normal_adapter.c"
  )
  target_compile_features(
    rome2_startup_100e85d0_normal_adapter_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e85d0_normal_adapter_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e85d0_normal_adapter_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e85d0_normal_adapter_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  set_property(
    TARGET rome2_startup_100e85d0_normal_adapter_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e85d0_normal_adapter_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e85d0_normal_adapter.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e85d0_normal_adapter_tests
  )
  target_link_libraries(
    rome2_startup_100e85d0_normal_adapter_tests
    PRIVATE rome2_startup_100e85d0_normal_adapter_runtime
  )
  target_link_options(
    rome2_startup_100e85d0_normal_adapter_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e85d0_normal_adapter_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Third concrete handler in original order.  Its nine-call transcript
  # carries an injected 0x100e8240 guest result through checked +0x68
  # arithmetic before the two suffix effects and final AL publication.
  add_library(
    rome2_startup_100e8580_handler_transcript_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e8580_handler_transcript.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e8580_handler_transcript.c"
  )
  target_compile_features(
    rome2_startup_100e8580_handler_transcript_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e8580_handler_transcript_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e8580_handler_transcript_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e8580_handler_transcript_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100e8580_handler_transcript_runtime
    PRIVATE rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_100e8580_handler_transcript_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e8580_handler_transcript_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8580_handler_transcript.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e8580_handler_transcript_tests
  )
  target_link_libraries(
    rome2_startup_100e8580_handler_transcript_tests
    PRIVATE rome2_startup_100e8580_handler_transcript_runtime
  )
  target_link_options(
    rome2_startup_100e8580_handler_transcript_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e8580_handler_transcript_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Bounded executable composition of original 0x100ea4d0.  Six injected
  # four-byte handler allocations receive the authenticated vtable identities
  # and are appended through the unified 0x100e2460 router; no native
  # allocation, platform call, or guest-derived function pointer is admitted.
  add_library(
    rome2_startup_100ea4d0_injected_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ea4d0_injected.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ea4d0_injected.c"
  )
  target_compile_features(
    rome2_startup_100ea4d0_injected_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100ea4d0_injected_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100ea4d0_injected_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100ea4d0_injected_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100ea4d0_injected_runtime
    PRIVATE rome2_startup_100e2460_router_runtime
  )
  set_property(
    TARGET rome2_startup_100ea4d0_injected_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100ea4d0_injected_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ea4d0_injected.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100ea4d0_injected_tests
  )
  target_link_libraries(
    rome2_startup_100ea4d0_injected_tests
    PRIVATE rome2_startup_100ea4d0_injected_runtime
  )
  target_link_options(
    rome2_startup_100ea4d0_injected_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100ea4d0_injected_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Fourth concrete handler in original registration order.  Its four-step
  # adapter injects two virtual lookup results and the singleton/helper
  # suffix while preserving the authenticated receiver-low-byte rewrite.
  add_library(
    rome2_startup_100e9340_handler_transcript_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e9340_handler_transcript.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e9340_handler_transcript.c"
  )
  target_compile_features(
    rome2_startup_100e9340_handler_transcript_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e9340_handler_transcript_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e9340_handler_transcript_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e9340_handler_transcript_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  set_property(
    TARGET rome2_startup_100e9340_handler_transcript_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e9340_handler_transcript_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e9340_handler_transcript.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e9340_handler_transcript_tests
  )
  target_link_libraries(
    rome2_startup_100e9340_handler_transcript_tests
    PRIVATE rome2_startup_100e9340_handler_transcript_runtime
  )
  target_link_options(
    rome2_startup_100e9340_handler_transcript_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e9340_handler_transcript_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Fifth concrete handler.  The bounded transcript preserves both predicate
  # routes, the two dependent two-word Steam getter results, and the final
  # four-word startup call without invoking Steam or native global state.
  add_library(
    rome2_startup_100e92c0_handler_transcript_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e92c0_handler_transcript.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e92c0_handler_transcript.c"
  )
  target_compile_features(
    rome2_startup_100e92c0_handler_transcript_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e92c0_handler_transcript_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e92c0_handler_transcript_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e92c0_handler_transcript_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  set_property(
    TARGET rome2_startup_100e92c0_handler_transcript_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e92c0_handler_transcript_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e92c0_handler_transcript.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e92c0_handler_transcript_tests
  )
  target_link_libraries(
    rome2_startup_100e92c0_handler_transcript_tests
    PRIVATE rome2_startup_100e92c0_handler_transcript_runtime
  )
  target_link_options(
    rome2_startup_100e92c0_handler_transcript_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e92c0_handler_transcript_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Sixth concrete handler.  A caller-provided guest span and injected
  # effects model listener allocation, optional vtable publication, global
  # publication, and FaceFX startup with explicit prefix-commit failures.
  add_library(
    rome2_startup_100e87a0_handler_transcript_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e87a0_handler_transcript.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100e87a0_handler_transcript.c"
  )
  target_compile_features(
    rome2_startup_100e87a0_handler_transcript_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100e87a0_handler_transcript_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100e87a0_handler_transcript_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100e87a0_handler_transcript_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  set_property(
    TARGET rome2_startup_100e87a0_handler_transcript_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100e87a0_handler_transcript_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e87a0_handler_transcript.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100e87a0_handler_transcript_tests
  )
  target_link_libraries(
    rome2_startup_100e87a0_handler_transcript_tests
    PRIVATE rome2_startup_100e87a0_handler_transcript_runtime
  )
  target_link_options(
    rome2_startup_100e87a0_handler_transcript_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100e87a0_handler_transcript_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Complete deterministic suffix of original 0x100df270.  Guest identities,
  # direct calls, virtual selector queries, the conditional four-call route,
  # and the final marker publication remain bounded injected effects.
  add_library(
    rome2_startup_100df270_suffix_transcript_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_suffix_transcript.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_suffix_transcript.c"
  )
  target_compile_features(
    rome2_startup_100df270_suffix_transcript_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100df270_suffix_transcript_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100df270_suffix_transcript_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100df270_suffix_transcript_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100df270_suffix_transcript_runtime
    PUBLIC rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_100df270_suffix_transcript_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100df270_suffix_transcript_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100df270_suffix_transcript.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100df270_suffix_transcript_tests
  )
  target_link_libraries(
    rome2_startup_100df270_suffix_transcript_tests
    PRIVATE rome2_startup_100df270_suffix_transcript_runtime
  )
  target_link_options(
    rome2_startup_100df270_suffix_transcript_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100df270_suffix_transcript_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Platform-bound prefix of original 0x100df270.  Native resource, mutex,
  # UI, system-setting, and termination effects remain typed injected call
  # shapes; only three authenticated receiver cells are written directly.
  add_library(
    rome2_startup_100df270_platform_prefix_transcript_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_platform_prefix_transcript.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_platform_prefix_transcript.c"
  )
  target_compile_features(
    rome2_startup_100df270_platform_prefix_transcript_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100df270_platform_prefix_transcript_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100df270_platform_prefix_transcript_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100df270_platform_prefix_transcript_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100df270_platform_prefix_transcript_runtime
    PUBLIC rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_100df270_platform_prefix_transcript_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100df270_platform_prefix_transcript_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100df270_platform_prefix_transcript.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100df270_platform_prefix_transcript_tests
  )
  target_link_libraries(
    rome2_startup_100df270_platform_prefix_transcript_tests
    PRIVATE rome2_startup_100df270_platform_prefix_transcript_runtime
  )
  target_link_options(
    rome2_startup_100df270_platform_prefix_transcript_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100df270_platform_prefix_transcript_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Straight-line empty-input prefix of launcher-facing original 0x100ed3c0.
  # The two global stores and all platform-bound child effects remain typed
  # injected transcripts.  The allocator-capable nonempty route and the loop
  # beginning at 0x100ed471 remain outside this test-only target.
  add_library(
    rome2_startup_100ed3c0_empty_preloop_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_empty_preloop.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_empty_preloop.c"
  )
  target_compile_features(
    rome2_startup_100ed3c0_empty_preloop_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100ed3c0_empty_preloop_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100ed3c0_empty_preloop_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100ed3c0_empty_preloop_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100ed3c0_empty_preloop_runtime
    PUBLIC rome2_guest32_runtime
    PRIVATE
      rome2_startup_100f1c10_runtime
      rome2_startup_100f1aa0_empty_runtime
      rome2_startup_safe_seams_runtime
      rome2_startup_100df270_headless_runtime
      rome2_startup_100df270_suffix_transcript_runtime
      rome2_startup_100df270_platform_prefix_transcript_runtime
  )
  set_property(
    TARGET rome2_startup_100ed3c0_empty_preloop_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100ed3c0_empty_preloop_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_empty_preloop.c"
  )
  rome2_configure_x64_target(rome2_startup_100ed3c0_empty_preloop_tests)
  target_link_libraries(
    rome2_startup_100ed3c0_empty_preloop_tests
    PRIVATE rome2_startup_100ed3c0_empty_preloop_runtime
  )
  target_link_options(
    rome2_startup_100ed3c0_empty_preloop_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100ed3c0_empty_preloop_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Finite ordinary-domain lifecycle tail [0x100ed471,0x100ed550).  Poll
  # results are a prevalidated injected 0* -> 2 transcript; all original
  # direct and indirect calls remain typed by-value observations.
  add_library(
    rome2_startup_100ed471_ordinary_lifecycle_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ed471_ordinary_lifecycle.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ed471_ordinary_lifecycle.c"
  )
  target_compile_features(
    rome2_startup_100ed471_ordinary_lifecycle_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100ed471_ordinary_lifecycle_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100ed471_ordinary_lifecycle_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100ed471_ordinary_lifecycle_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100ed471_ordinary_lifecycle_runtime
    PUBLIC rome2_guest32_runtime
    PRIVATE rome2_startup_safe_seams_runtime
  )
  set_property(
    TARGET rome2_startup_100ed471_ordinary_lifecycle_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100ed471_ordinary_lifecycle_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed471_ordinary_lifecycle.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100ed471_ordinary_lifecycle_tests
  )
  target_link_libraries(
    rome2_startup_100ed471_ordinary_lifecycle_tests
    PRIVATE rome2_startup_100ed471_ordinary_lifecycle_runtime
  )
  target_link_options(
    rome2_startup_100ed471_ordinary_lifecycle_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100ed471_ordinary_lifecycle_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Bounded nonempty UTF-16 descriptor construction and the paired owning
  # cleanup from original 0x100f1bb0 -> 0x100ef330 and 0x100f1cc0.  Allocation
  # and release remain one-shot injected grants over a caller-provided guest32
  # heap arena; no native/original allocator is linked into this test target.
  add_library(
    rome2_startup_100f1bb0_owned_utf16_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_owned_utf16.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_owned_utf16.c"
  )
  target_compile_features(
    rome2_startup_100f1bb0_owned_utf16_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100f1bb0_owned_utf16_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100f1bb0_owned_utf16_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100f1bb0_owned_utf16_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100f1bb0_owned_utf16_runtime
    PUBLIC rome2_guest32_runtime
  )
  set_property(
    TARGET rome2_startup_100f1bb0_owned_utf16_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100f1bb0_owned_utf16_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f1bb0_owned_utf16.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100f1bb0_owned_utf16_tests
  )
  target_link_libraries(
    rome2_startup_100f1bb0_owned_utf16_tests
    PRIVATE rome2_startup_100f1bb0_owned_utf16_runtime
  )
  target_link_options(
    rome2_startup_100f1bb0_owned_utf16_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100f1bb0_owned_utf16_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # First-use replacement of the persistent crash descriptor at guest identity
  # 0x119f3aa0.  Registration, allocation, release, and the optional release
  # hook are typed test-only effects; no original CRT callback or address is
  # linked, and the source and persistent owners remain distinct.
  add_library(
    rome2_startup_100f2750_sentinel_owned_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_first_use_owned.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_first_use_owned.c"
  )
  target_compile_features(
    rome2_startup_100f2750_sentinel_owned_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100f2750_sentinel_owned_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100f2750_sentinel_owned_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100f2750_sentinel_owned_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100f2750_sentinel_owned_runtime
    PUBLIC rome2_startup_100f1bb0_owned_utf16_runtime
  )
  set_property(
    TARGET rome2_startup_100f2750_sentinel_owned_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100f2750_sentinel_owned_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f2750_sentinel_owned.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100f2750_sentinel_owned_tests
  )
  target_link_libraries(
    rome2_startup_100f2750_sentinel_owned_tests
    PRIVATE rome2_startup_100f2750_sentinel_owned_runtime
  )
  target_link_options(
    rome2_startup_100f2750_sentinel_owned_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100f2750_sentinel_owned_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Bounded nonempty composition of the straight-line parent interval
  # [0x100ed3c0,0x100ed471).  Both allocations, the delegated first-use copy,
  # and temporary cleanup remain injected typed effects.  This independently
  # tested leaf has no headless, export, probe, or production consumer.
  add_library(
    rome2_startup_100ed3c0_nonempty_preloop_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_preloop.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_preloop.c"
  )
  target_compile_features(
    rome2_startup_100ed3c0_nonempty_preloop_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100ed3c0_nonempty_preloop_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100ed3c0_nonempty_preloop_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100ed3c0_nonempty_preloop_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100ed3c0_nonempty_preloop_runtime
    PUBLIC rome2_guest32_runtime
    PRIVATE
      rome2_startup_100f1c10_runtime
      rome2_startup_100f1aa0_empty_runtime
      rome2_startup_safe_seams_runtime
      rome2_startup_100df270_headless_runtime
      rome2_startup_100df270_platform_prefix_transcript_runtime
      rome2_startup_100df270_suffix_transcript_runtime
      rome2_startup_100f1bb0_owned_utf16_runtime
      rome2_startup_100f2750_sentinel_owned_runtime
  )
  set_property(
    TARGET rome2_startup_100ed3c0_nonempty_preloop_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100ed3c0_nonempty_preloop_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_nonempty_preloop.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100ed3c0_nonempty_preloop_tests
  )
  target_link_libraries(
    rome2_startup_100ed3c0_nonempty_preloop_tests
    PRIVATE rome2_startup_100ed3c0_nonempty_preloop_runtime
  )
  target_link_options(
    rome2_startup_100ed3c0_nonempty_preloop_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100ed3c0_nonempty_preloop_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Whole bounded nonempty parent composition [0x100ed3c0,0x100ed550).
  # A private ordinary-lifecycle preview settles deterministic successor
  # validation before the first nonempty effect.  The admitted leaves then run
  # once each on one frame.  This target has no headless or production consumer.
  add_library(
    rome2_startup_100ed3c0_nonempty_lifecycle_runtime
    STATIC
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_lifecycle.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_lifecycle.c"
  )
  target_compile_features(
    rome2_startup_100ed3c0_nonempty_lifecycle_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100ed3c0_nonempty_lifecycle_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100ed3c0_nonempty_lifecycle_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100ed3c0_nonempty_lifecycle_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100ed3c0_nonempty_lifecycle_runtime
    PUBLIC rome2_guest32_runtime
    PRIVATE
      rome2_startup_100ed3c0_nonempty_preloop_runtime
      rome2_startup_100ed471_ordinary_lifecycle_runtime
  )
  set_property(
    TARGET rome2_startup_100ed3c0_nonempty_lifecycle_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100ed3c0_nonempty_lifecycle_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_nonempty_lifecycle.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100ed3c0_nonempty_lifecycle_tests
  )
  target_link_libraries(
    rome2_startup_100ed3c0_nonempty_lifecycle_tests
    PRIVATE rome2_startup_100ed3c0_nonempty_lifecycle_runtime
  )
  target_link_options(
    rome2_startup_100ed3c0_nonempty_lifecycle_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100ed3c0_nonempty_lifecycle_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Exact caller closure for the two authenticated 0x100edd70 windows around
  # the admitted whole nonempty parent.  Keeper stores remain typed observer
  # data; handler registration and both branch epilogues remain excluded.
  add_library(
    rome2_startup_100edd70_caller_closure_runtime
    STATIC EXCLUDE_FROM_ALL
    "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_caller_closure.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_caller_closure.c"
  )
  target_compile_features(
    rome2_startup_100edd70_caller_closure_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100edd70_caller_closure_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100edd70_caller_closure_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100edd70_caller_closure_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100edd70_caller_closure_runtime
    PUBLIC rome2_guest32_runtime
    PRIVATE rome2_startup_100ed3c0_nonempty_lifecycle_runtime
  )
  set_property(
    TARGET rome2_startup_100edd70_caller_closure_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100edd70_caller_closure_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100edd70_caller_closure.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100edd70_caller_closure_tests
  )
  target_link_libraries(
    rome2_startup_100edd70_caller_closure_tests
    PRIVATE rome2_startup_100edd70_caller_closure_runtime
  )
  target_link_options(
    rome2_startup_100edd70_caller_closure_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100edd70_caller_closure_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Exact entry decision: one pure selector call, four inert registration
  # records on the install route, then the admitted caller closure.  The CRT
  # callee and handler leaf remain identities and are never executed.
  add_library(
    rome2_startup_100edd70_entry_decision_runtime
    STATIC EXCLUDE_FROM_ALL
    "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_entry_decision.h"
    "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_entry_decision.c"
  )
  target_compile_features(
    rome2_startup_100edd70_entry_decision_runtime PUBLIC c_std_17
  )
  target_compile_definitions(
    rome2_startup_100edd70_entry_decision_runtime
    PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      WINVER=0x0602
      _WIN32_WINNT=0x0602
  )
  target_compile_options(
    rome2_startup_100edd70_entry_decision_runtime
    PRIVATE ${ROME2_HARDENED_COMPILE_OPTIONS}
  )
  target_include_directories(
    rome2_startup_100edd70_entry_decision_runtime
    PUBLIC
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_startup_100edd70_entry_decision_runtime
    PUBLIC rome2_guest32_runtime
    PRIVATE rome2_startup_100edd70_caller_closure_runtime
  )
  set_property(
    TARGET rome2_startup_100edd70_entry_decision_runtime
    PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  )

  add_executable(
    rome2_startup_100edd70_entry_decision_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100edd70_entry_decision.c"
  )
  rome2_configure_x64_target(
    rome2_startup_100edd70_entry_decision_tests
  )
  target_link_libraries(
    rome2_startup_100edd70_entry_decision_tests
    PRIVATE rome2_startup_100edd70_entry_decision_runtime
  )
  target_link_options(
    rome2_startup_100edd70_entry_decision_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100edd70_entry_decision_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  # Native composition harness for the admitted bounded slices.  It executes
  # all complete admitted 0x100e2460 branches with total test-only allocation,
  # release, dispatch, and message adapters, but invokes no native platform
  # callback or gameplay code.
  add_executable(
    rome2_headless64
    "${ROME2_HEADLESS_DIR}/headless_main.c"
  )
  rome2_configure_x64_target(rome2_headless64)
  target_include_directories(
    rome2_headless64
    PRIVATE
      "${ROME2_GUEST32_RUNTIME_DIR}"
      "${ROME2_GUEST32_PORTED_DIR}"
  )
  target_link_libraries(
    rome2_headless64
    PRIVATE
      rome2_guest32_runtime
      rome2_startup_100f1aa0_empty_runtime
      rome2_startup_safe_seams_runtime
      rome2_startup_100df270_headless_runtime
      rome2_startup_100f2750_nonalloc_runtime
      rome2_startup_100e8240_fastpath_runtime
      rome2_startup_100e2460_append_prefix_runtime
      rome2_startup_100e2460_preallocated_branch_runtime
      rome2_startup_100e2460_capacity_zero_branch_runtime
      rome2_startup_100e2460_growth_branch_runtime
      rome2_startup_100e2460_router_runtime
      rome2_startup_100e8d00_handler_transcript_runtime
      rome2_startup_100e85d0_normal_adapter_runtime
      rome2_startup_100e8580_handler_transcript_runtime
      rome2_startup_100ea4d0_injected_runtime
      rome2_startup_100e9340_handler_transcript_runtime
      rome2_startup_100e92c0_handler_transcript_runtime
      rome2_startup_100e87a0_handler_transcript_runtime
      rome2_startup_100df270_suffix_transcript_runtime
      rome2_startup_100df270_platform_prefix_transcript_runtime
      rome2_startup_100ed3c0_empty_preloop_runtime
      rome2_startup_100ed471_ordinary_lifecycle_runtime
  )
  target_link_options(
    rome2_headless64
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_headless64
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  add_executable(
    rome2_startup_100f1aa0_empty_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f1aa0_empty.c"
  )
  rome2_configure_x64_target(rome2_startup_100f1aa0_empty_tests)
  target_link_libraries(
    rome2_startup_100f1aa0_empty_tests
    PRIVATE rome2_startup_100f1aa0_empty_runtime
  )
  target_link_options(
    rome2_startup_100f1aa0_empty_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_startup_100f1aa0_empty_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  add_executable(
    rome2_guest32_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_guest32.c"
  )
  rome2_configure_x64_target(rome2_guest32_tests)
  target_link_libraries(rome2_guest32_tests PRIVATE rome2_guest32_runtime)
  target_link_options(
    rome2_guest32_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_guest32_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  add_executable(
    rome2_entry_policy_tests
    "${ROME2_GUEST32_RUNTIME_DIR}/test_entry_policy.c"
  )
  rome2_configure_x64_target(rome2_entry_policy_tests)
  target_link_libraries(rome2_entry_policy_tests PRIVATE rome2_guest32_runtime)
  target_link_options(
    rome2_entry_policy_tests
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.00
  )
  set_target_properties(
    rome2_entry_policy_tests
    PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  set(
    ROME2_GUEST32_PROBE_MAP
    "${CMAKE_BINARY_DIR}/rome2_guest32_probe64.map"
  )
  add_library(
    rome2_guest32_probe
    SHARED
    "${ROME2_GUEST32_PROBE_DIR}/probe_contract.h"
    "${ROME2_GUEST32_PROBE_DIR}/probe_dll.c"
    "${ROME2_GUEST32_PROBE_DIR}/probe_exports.def"
  )
  rome2_configure_x64_target(rome2_guest32_probe)
  target_include_directories(
    rome2_guest32_probe
    PRIVATE "${ROME2_GUEST32_PROBE_DIR}"
  )
  target_link_libraries(
    rome2_guest32_probe
    PRIVATE rome2_guest32_runtime
  )
  target_link_options(
    rome2_guest32_probe
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.02
      "/MAP:${ROME2_GUEST32_PROBE_MAP}"
      /MAPINFO:EXPORTS
  )
  set_target_properties(
    rome2_guest32_probe
    PROPERTIES
      OUTPUT_NAME "rome2_guest32_probe64"
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  add_executable(
    rome2_guest32_probe_host
    "${ROME2_GUEST32_PROBE_DIR}/probe_contract.h"
    "${ROME2_GUEST32_PROBE_DIR}/probe_host.c"
  )
  rome2_configure_x64_target(rome2_guest32_probe_host)
  target_include_directories(
    rome2_guest32_probe_host
    PRIVATE "${ROME2_GUEST32_PROBE_DIR}"
  )
  target_link_options(
    rome2_guest32_probe_host
    PRIVATE
      /MACHINE:X64
      /SUBSYSTEM:CONSOLE,6.02
  )
  set_target_properties(
    rome2_guest32_probe_host
    PROPERTIES
      OUTPUT_NAME "rome2_guest32_probe_host64"
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
      COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
  )

  add_test(
    NAME x64_bootstrap_load
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME x64_bootstrap_load_relative
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE_NAME:empire_retail_bootstrap>"
  )
  set_tests_properties(
    x64_bootstrap_load_relative
    PROPERTIES WORKING_DIRECTORY "$<TARGET_FILE_DIR:empire_retail_bootstrap>"
  )
  add_test(
    NAME guest32_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_guest32_provenance.py"
  )
  add_test(
    NAME entry_policy_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_entry_policy_provenance.py"
  )
  add_test(
    NAME entry_policy_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_static_gate.py"
      --guest-h "${ROME2_GUEST32_RUNTIME_DIR}/guest32.h"
      --guest-c "${ROME2_GUEST32_RUNTIME_DIR}/guest32.c"
      --policy-h "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_policy.h"
      --policy-c "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_policy.c"
  )
  add_test(
    NAME entry_policy_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_entry_policy_static_gate.py"
  )
  add_test(
    NAME entry_policy_probe_pe_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --self-test
  )
  add_test(
    NAME x64_reproducible_build_v2
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_reproducible_build_v2.py"
      --manifest
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_reproducible_build_v2_manifest.json"
      --dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --host "$<TARGET_FILE:empire_bootstrap_smoke>"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
  )
  add_test(
    NAME entry_policy_probe_containment_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_entry_policy_probe_containment.py"
      --self-test
  )
  add_test(
    NAME entry_policy_probe_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME entry_policy_probe_link_containment
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_entry_policy_probe_containment.py"
      --map "${ROME2_GUEST32_PROBE_MAP}"
  )
  add_test(
    NAME entry_policy_probe_runtime
    COMMAND
      "$<TARGET_FILE:rome2_guest32_probe_host>"
      "$<TARGET_FILE:rome2_guest32_probe>"
  )
  add_test(
    NAME entry_policy_probe_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_probe
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(NAME guest32_runtime COMMAND "$<TARGET_FILE:rome2_guest32_tests>")
  add_test(
    NAME entry_policy_runtime
    COMMAND "$<TARGET_FILE:rome2_entry_policy_tests>"
  )
  add_test(
    NAME startup_100f1c10_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f1c10_provenance.py"
  )
  add_test(
    NAME startup_100ed3c0_abi_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_abi_provenance.py"
  )
  add_test(
    NAME startup_100ec5c0_return_domain
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ec5c0_return_domain.py"
  )
  add_test(
    NAME pi_startup_abi_evidence_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_pi_startup_abi_evidence_gate.py"
  )
  add_test(
    NAME pi_startup_abi_evidence_gate_v2_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_pi_startup_abi_evidence_gate_v2.py"
  )
  add_test(
    NAME pi_wave3_abi_evidence_v2_schema
    COMMAND
      pwsh
      -NoProfile
      -NonInteractive
      -File
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_pi_wave3_abi_evidence_v2_schema.ps1"
      -RepositoryRoot
      "${CMAKE_CURRENT_SOURCE_DIR}"
  )
  add_test(
    NAME pi_startup_abi_oracle_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_pi_startup_abi_oracle_gate.py"
  )
  add_test(
    NAME pi_startup_abi_oracle_gate_v2_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_pi_startup_abi_oracle_gate_v2.py"
  )
  add_test(
    NAME pi_wave3_v5_wiring
    COMMAND
      pwsh
      -NoProfile
      -NonInteractive
      -File
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_pi_wave3_v5_wiring.ps1"
      -RepositoryRoot
      "${CMAKE_CURRENT_SOURCE_DIR}"
  )
  add_test(
    NAME pi_wave3_oracle_v2_schema
    COMMAND
      pwsh
      -NoProfile
      -NonInteractive
      -File
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_pi_wave3_oracle_v2_schema.ps1"
      -RepositoryRoot
      "${CMAKE_CURRENT_SOURCE_DIR}"
  )
  add_test(
    NAME startup_100f1c10_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f1c10_static_gate.py"
  )
  add_test(
    NAME startup_100f1c10_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100f1c10_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100f1c10_triplet.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100f1c10_triplet.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
  )
  add_test(
    NAME startup_100f1c10_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100f1c10_tests>"
  )
  add_test(
    NAME battle_unitcard_10145c70_runtime
    COMMAND "$<TARGET_FILE:rome2_battle_unitcard_tests>"
  )
  add_test(
    NAME battle_entity_10cbe350_runtime
    COMMAND "$<TARGET_FILE:rome2_battle_entity_tests>"
  )
  add_test(
    NAME startup_100f1c10_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100f1c10
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100f1aa0_empty_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f1aa0_empty_provenance.py"
  )
  add_test(
    NAME startup_100f1aa0_empty_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f1aa0_empty_static_gate.py"
  )
  add_test(
    NAME startup_100f1aa0_empty_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100f1aa0_empty_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100f1aa0_empty.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100f1aa0_empty.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f1aa0_empty.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100f1aa0_empty_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100f1aa0_empty_tests>"
  )
  add_test(
    NAME startup_100f1aa0_empty_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100f1aa0_empty
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_safe_seams_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_safe_seams_provenance.py"
  )
  add_test(
    NAME startup_safe_seams_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_safe_seams_static_gate.py"
  )
  add_test(
    NAME startup_safe_seams_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_safe_seams_static_gate.py"
      --measure-header "${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_bounded.h"
      --measure-source "${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_bounded.c"
      --noop-header "${ROME2_GUEST32_PORTED_DIR}/ported_100f1cc0_nonowning.h"
      --noop-source "${ROME2_GUEST32_PORTED_DIR}/ported_100f1cc0_nonowning.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_safe_seams.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_safe_seams_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_safe_seams_tests>"
  )
  add_test(
    NAME startup_safe_seams_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_safe_seams
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100df270_headless_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100df270_headless_provenance.py"
  )
  add_test(
    NAME startup_100df270_headless_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100df270_headless_static_gate.py"
  )
  add_test(
    NAME startup_100df270_headless_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100df270_headless_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_headless.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_headless.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100df270_headless.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100df270_headless_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100df270_headless_tests>"
  )
  add_test(
    NAME startup_100df270_headless_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100df270_headless
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100f2750_nonalloc_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f2750_nonalloc_provenance.py"
  )
  add_test(
    NAME startup_100f2750_nonalloc_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f2750_nonalloc_static_gate.py"
  )
  add_test(
    NAME startup_100f2750_nonalloc_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100f2750_nonalloc_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_nonalloc.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_nonalloc.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f2750_nonalloc.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100f2750_nonalloc_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100f2750_nonalloc_tests>"
  )
  add_test(
    NAME startup_100e8240_fastpath_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e8240_fastpath_provenance.py"
  )
  add_test(
    NAME startup_100ea4d0_evidence_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ea4d0_evidence_provenance.py"
  )
  add_test(
    NAME startup_100e8240_fastpath_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e8240_fastpath_static_gate.py"
  )
  add_test(
    NAME startup_100e8240_fastpath_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e8240_fastpath_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e8240_fastpath.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e8240_fastpath.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8240_fastpath.c"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e8240_fastpath_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e8240_fastpath_tests>"
  )
  add_test(
    NAME startup_100e2460_append_prefix_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_append_prefix_provenance.py"
  )
  add_test(
    NAME startup_100e2460_append_prefix_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_append_prefix_static_gate.py"
  )
  add_test(
    NAME startup_100e2460_append_prefix_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e2460_append_prefix_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_append_prefix.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_append_prefix.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_append_prefix.c"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e2460_append_prefix_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e2460_append_prefix_tests>"
  )
  add_test(
    NAME startup_100e2460_preallocated_branch_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_preallocated_branch_provenance.py"
  )
  add_test(
    NAME startup_100e2460_preallocated_branch_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_preallocated_branch_static_gate.py"
  )
  add_test(
    NAME startup_100e2460_preallocated_branch_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e2460_preallocated_branch_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_preallocated_branch.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_preallocated_branch.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_preallocated_branch.c"
      --append-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_append_prefix_provenance.py"
      --branch-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_preallocated_branch_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e2460_preallocated_branch_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e2460_preallocated_branch_tests>"
  )
  add_test(
    NAME startup_100e2460_capacity_zero_branch_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_capacity_zero_branch_provenance.py"
  )
  add_test(
    NAME startup_100e2460_capacity_zero_branch_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_capacity_zero_branch_static_gate.py"
  )
  add_test(
    NAME startup_100e2460_capacity_zero_branch_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e2460_capacity_zero_branch_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_capacity_zero_branch.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_capacity_zero_branch.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_capacity_zero_branch.c"
      --preallocated-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_preallocated_branch_provenance.py"
      --capacity-zero-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_capacity_zero_branch_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e2460_capacity_zero_branch_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e2460_capacity_zero_branch_tests>"
  )
  add_test(
    NAME startup_100e2460_growth_branch_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_growth_branch_provenance.py"
  )
  add_test(
    NAME startup_100e2460_growth_branch_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_growth_branch_static_gate.py"
  )
  add_test(
    NAME startup_100e2460_growth_branch_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e2460_growth_branch_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_growth_branch.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_growth_branch.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_growth_branch.c"
      --growth-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_growth_branch_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e2460_growth_branch_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e2460_growth_branch_tests>"
  )
  add_test(
    NAME startup_100e2460_router_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_router_provenance.py"
  )
  add_test(
    NAME startup_100e2460_router_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_router_static_gate.py"
  )
  add_test(
    NAME startup_100e2460_router_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e2460_router_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_router.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e2460_router.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_router.c"
      --six-append-test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e2460_router_six_append.c"
      --router-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e2460_router_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e2460_router_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e2460_router_tests>"
  )
  add_test(
    NAME startup_100e2460_router_six_append_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e2460_router_six_append_tests>"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e8d00_handler_transcript_provenance.py"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e8d00_handler_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e8d00_handler_transcript_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e8d00_handler_transcript.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e8d00_handler_transcript.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8d00_handler_transcript.c"
      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e8d00_handler_transcript_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e8d00_handler_transcript_tests>"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e85d0_normal_adapter_provenance.py"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e85d0_normal_adapter_static_gate.py"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e85d0_normal_adapter_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e85d0_normal_adapter.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e85d0_normal_adapter.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e85d0_normal_adapter.c"
      --adapter-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e85d0_normal_adapter_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e85d0_normal_adapter_tests>"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e8580_handler_transcript_provenance.py"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e8580_handler_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e8580_handler_transcript_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e8580_handler_transcript.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e8580_handler_transcript.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e8580_handler_transcript.c"
      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e8580_handler_transcript_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e8580_handler_transcript_tests>"
  )
  add_test(
    NAME startup_100ea4d0_executable_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ea4d0_executable_provenance.py"
  )
  add_test(
    NAME startup_100ea4d0_injected_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ea4d0_injected_static_gate.py"
  )
  add_test(
    NAME startup_100ea4d0_injected_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100ea4d0_injected_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100ea4d0_injected.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100ea4d0_injected.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ea4d0_injected.c"
      --executable-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ea4d0_executable_provenance.py"
      --evidence-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ea4d0_evidence_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100ea4d0_injected_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100ea4d0_injected_tests>"
  )
  add_test(
    NAME startup_100e9340_handler_transcript_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e9340_handler_transcript_provenance.py"
  )
  add_test(
    NAME startup_100e9340_handler_transcript_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e9340_handler_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100e9340_handler_transcript_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e9340_handler_transcript_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e9340_handler_transcript.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e9340_handler_transcript.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e9340_handler_transcript.c"
      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e9340_handler_transcript_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e9340_handler_transcript_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e9340_handler_transcript_tests>"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e92c0_handler_transcript_provenance.py"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e92c0_handler_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e92c0_handler_transcript_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e92c0_handler_transcript.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e92c0_handler_transcript.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e92c0_handler_transcript.c"
      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e92c0_handler_transcript_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e92c0_handler_transcript_tests>"
  )
  add_test(
    NAME startup_100e87a0_handler_transcript_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e87a0_handler_transcript_provenance.py"
  )
  add_test(
    NAME startup_100e87a0_handler_transcript_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e87a0_handler_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100e87a0_handler_transcript_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100e87a0_handler_transcript_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100e87a0_handler_transcript.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100e87a0_handler_transcript.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100e87a0_handler_transcript.c"
      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100e87a0_handler_transcript_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100e87a0_handler_transcript_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100e87a0_handler_transcript_tests>"
  )
  add_test(
    NAME startup_100df270_suffix_transcript_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100df270_suffix_transcript_provenance.py"
  )
  add_test(
    NAME startup_100df270_suffix_transcript_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100df270_suffix_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100df270_suffix_transcript_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100df270_suffix_transcript_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_suffix_transcript.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_suffix_transcript.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100df270_suffix_transcript.c"
      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100df270_suffix_transcript_provenance.py"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100df270_suffix_transcript_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100df270_suffix_transcript_tests>"
  )
  add_test(
    NAME startup_100df270_platform_prefix_transcript_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100df270_platform_prefix_transcript_provenance.py"
  )
  add_test(
    NAME startup_100df270_platform_prefix_transcript_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100df270_platform_prefix_transcript_static_gate.py"
  )
  add_test(
    NAME startup_100df270_platform_prefix_transcript_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100df270_platform_prefix_transcript_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_platform_prefix_transcript.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100df270_platform_prefix_transcript.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100df270_platform_prefix_transcript.c"
      --transcript-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100df270_platform_prefix_transcript_provenance.py"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --export-contract "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --bootstrap-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/empire_bootstrap.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100df270_platform_prefix_transcript_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100df270_platform_prefix_transcript_tests>"
  )
  add_test(
    NAME startup_100ed3c0_empty_preloop_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_preloop_transcript_provenance.py"
  )
  add_test(
    NAME startup_100ed3c0_empty_preloop_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_empty_preloop_static_gate.py"
  )
  add_test(
    NAME startup_100ed3c0_empty_preloop_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100ed3c0_empty_preloop_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_empty_preloop.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_empty_preloop.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_empty_preloop.c"
      --preloop-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_preloop_transcript_provenance.py"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --export-contract "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --bootstrap-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/empire_bootstrap.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
      --repro-manifest "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_reproducible_build_v2_manifest.json"
      --repro-verifier "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_reproducible_build_v2.py"
  )
  add_test(
    NAME startup_100ed3c0_empty_preloop_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100ed3c0_empty_preloop_tests>"
  )
  add_test(
    NAME startup_100ed471_ordinary_lifecycle_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed471_ordinary_lifecycle_provenance.py"
  )
  add_test(
    NAME startup_100ed471_ordinary_lifecycle_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed471_ordinary_lifecycle_static_gate.py"
  )
  add_test(
    NAME startup_100ed471_ordinary_lifecycle_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100ed471_ordinary_lifecycle_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100ed471_ordinary_lifecycle.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100ed471_ordinary_lifecycle.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed471_ordinary_lifecycle.c"
      --lifecycle-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed471_ordinary_lifecycle_provenance.py"
      --doc "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_startup_100ed471_ordinary_lifecycle.md"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --export-contract "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --bootstrap-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/empire_bootstrap.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
      --repro-manifest "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_reproducible_build_v2_manifest.json"
      --repro-verifier "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_reproducible_build_v2.py"
  )
  add_test(
    NAME startup_100ed471_ordinary_lifecycle_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100ed471_ordinary_lifecycle_tests>"
  )
  add_test(
    NAME startup_100f1bb0_owned_utf16_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f1bb0_owned_utf16_provenance.py"
  )
  add_test(
    NAME startup_100f1bb0_owned_utf16_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f1bb0_owned_utf16_static_gate.py"
  )
  add_test(
    NAME startup_100f1bb0_owned_utf16_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100f1bb0_owned_utf16_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_owned_utf16.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100f1bb0_owned_utf16.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f1bb0_owned_utf16.c"
      --owned-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f1bb0_owned_utf16_provenance.py"
      --doc "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_startup_100f1bb0_owned_utf16.md"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
  )
  add_test(
    NAME startup_100f1bb0_owned_utf16_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100f1bb0_owned_utf16_tests>"
  )
  add_test(
    NAME startup_100f2750_sentinel_owned_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f2750_sentinel_owned_provenance.py"
  )
  add_test(
    NAME startup_100f2750_sentinel_owned_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f2750_sentinel_owned_static_gate.py"
  )
  add_test(
    NAME startup_100f2750_sentinel_owned_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100f2750_sentinel_owned_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_first_use_owned.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100f2750_first_use_owned.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100f2750_sentinel_owned.c"
      --sentinel-provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100f2750_sentinel_owned_provenance.py"
      --doc "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_startup_100f2750_sentinel_owned.md"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
  )
  add_test(
    NAME startup_100f2750_sentinel_owned_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100f2750_sentinel_owned_tests>"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_preloop_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_nonempty_preloop_provenance.py"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_preloop_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_nonempty_preloop_static_gate.py"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_preloop_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100ed3c0_nonempty_preloop_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_preloop.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_preloop.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_nonempty_preloop.c"
      --provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_nonempty_preloop_provenance.py"
      --doc "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_startup_100ed3c0_nonempty_preloop.md"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --export-contract "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --bootstrap-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/empire_bootstrap.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_preloop_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100ed3c0_nonempty_preloop_tests>"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_lifecycle_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_nonempty_lifecycle_provenance.py"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_lifecycle_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_nonempty_lifecycle_static_gate.py"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_lifecycle_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100ed3c0_nonempty_lifecycle_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_lifecycle.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100ed3c0_nonempty_lifecycle.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100ed3c0_nonempty_lifecycle.c"
      --provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100ed3c0_nonempty_lifecycle_provenance.py"
      --doc "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_startup_100ed3c0_nonempty_lifecycle.md"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --export-contract "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --bootstrap-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/empire_bootstrap.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_lifecycle_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100ed3c0_nonempty_lifecycle_tests>"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_lifecycle_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100ed3c0_nonempty_lifecycle
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100edd70_caller_closure_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100edd70_caller_closure_provenance.py"
  )
  add_test(
    NAME startup_100edd70_caller_closure_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100edd70_caller_closure_static_gate.py"
  )
  add_test(
    NAME startup_100edd70_caller_closure_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100edd70_caller_closure_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_caller_closure.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_caller_closure.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100edd70_caller_closure.c"
      --provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100edd70_caller_closure_provenance.py"
      --doc "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_startup_100edd70_caller_closure.md"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --export-contract "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --bootstrap-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/empire_bootstrap.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100edd70_caller_closure_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100edd70_caller_closure_tests>"
  )
  add_test(
    NAME startup_100edd70_caller_closure_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100edd70_caller_closure
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100edd70_entry_decision_provenance
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100edd70_entry_decision_provenance.py"
  )
  add_test(
    NAME startup_100edd70_entry_decision_static_gate_unit
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100edd70_entry_decision_static_gate.py"
  )
  add_test(
    NAME startup_100edd70_entry_decision_static_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_startup_100edd70_entry_decision_static_gate.py"
      --header "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_entry_decision.h"
      --source "${ROME2_GUEST32_PORTED_DIR}/ported_100edd70_entry_decision.c"
      --test "${ROME2_GUEST32_RUNTIME_DIR}/test_startup_100edd70_entry_decision.c"
      --provenance "${CMAKE_CURRENT_SOURCE_DIR}/scripts/test_x64_startup_100edd70_entry_decision_provenance.py"
      --doc "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_startup_100edd70_entry_decision.md"
      --cmake "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
      --headless "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_headless/headless_main.c"
      --export-manifest "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/export_manifest.tsv"
      --export-contract "${CMAKE_CURRENT_SOURCE_DIR}/docs/x64_export_contract.md"
      --legacy-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_exports/empire.retail.exports.def"
      --bootstrap-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_bootstrap/empire_bootstrap.def"
      --probe-def "${CMAKE_CURRENT_SOURCE_DIR}/port/x64_probe/probe_exports.def"
  )
  add_test(
    NAME startup_100edd70_entry_decision_runtime
    COMMAND "$<TARGET_FILE:rome2_startup_100edd70_entry_decision_tests>"
  )
  add_test(
    NAME startup_100edd70_entry_decision_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100edd70_entry_decision
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100f2750_nonalloc_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100f2750_nonalloc
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e8240_fastpath_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e8240_fastpath
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e2460_append_prefix_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e2460_append_prefix
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e2460_preallocated_branch_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e2460_preallocated_branch
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e2460_capacity_zero_branch_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e2460_capacity_zero_branch
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e2460_growth_branch_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e2460_growth_branch
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e2460_router_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e2460_router
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e8d00_handler_transcript_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e8d00_handler_transcript
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e85d0_normal_adapter_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e85d0_normal_adapter
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e8580_handler_transcript_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e8580_handler_transcript
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100ea4d0_injected_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100ea4d0_injected
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e9340_handler_transcript_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e9340_handler_transcript
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e92c0_handler_transcript_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e92c0_handler_transcript
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100e87a0_handler_transcript_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100e87a0_handler_transcript
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100df270_suffix_transcript_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100df270_suffix_transcript
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100df270_platform_prefix_transcript_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100df270_platform_prefix_transcript
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100ed3c0_empty_preloop_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100ed3c0_empty_preloop
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100ed3c0_nonempty_preloop_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100ed3c0_nonempty_preloop
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME startup_100ed471_ordinary_lifecycle_post_pe_gate
    COMMAND
      Python3::Interpreter
      -B
      "${CMAKE_CURRENT_SOURCE_DIR}/scripts/x64_entry_policy_probe_pe_gate_v2.py"
      --dll "$<TARGET_FILE:rome2_guest32_probe>"
      --host "$<TARGET_FILE:rome2_guest32_probe_host>"
      --bootstrap-dll "$<TARGET_FILE:empire_retail_bootstrap>"
      --bootstrap-host "$<TARGET_FILE:empire_bootstrap_smoke>"
  )
  add_test(
    NAME x64_bootstrap_load_after_startup_100ed471_ordinary_lifecycle
    COMMAND
      "$<TARGET_FILE:empire_bootstrap_smoke>"
      "$<TARGET_FILE:empire_retail_bootstrap>"
  )
  add_test(
    NAME headless_bounded_lifecycle
    COMMAND "$<TARGET_FILE:rome2_headless64>"
  )
  set_tests_properties(
    guest32_provenance
    PROPERTIES FIXTURES_SETUP guest32_provenance_verified
  )
  set_tests_properties(
    guest32_runtime
    PROPERTIES FIXTURES_REQUIRED guest32_provenance_verified
  )
  set_tests_properties(
    entry_policy_provenance
    PROPERTIES FIXTURES_SETUP entry_policy_provenance_verified
  )
  set_tests_properties(
    entry_policy_static_gate
    PROPERTIES FIXTURES_SETUP entry_policy_static_verified
  )
  set_tests_properties(
    entry_policy_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "guest32_provenance_verified;entry_policy_provenance_verified;entry_policy_static_verified"
  )
  set_tests_properties(
    x64_bootstrap_load
    PROPERTIES FIXTURES_SETUP x64_bootstrap_pre_verified
  )
  set_tests_properties(
    entry_policy_probe_pe_gate_unit
    PROPERTIES FIXTURES_SETUP entry_policy_probe_pe_tool_verified
  )
  set_tests_properties(
    x64_reproducible_build_v2
    PROPERTIES FIXTURES_SETUP x64_reproducible_build_v2_verified
  )
  set_tests_properties(
    entry_policy_probe_containment_gate_unit
    PROPERTIES FIXTURES_SETUP entry_policy_probe_containment_tool_verified
  )
  set_tests_properties(
    entry_policy_probe_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;x64_reproducible_build_v2_verified;guest32_provenance_verified;entry_policy_provenance_verified;entry_policy_static_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP entry_policy_probe_pe_verified
  )
  set_tests_properties(
    entry_policy_probe_link_containment
    PROPERTIES
      FIXTURES_REQUIRED
        "guest32_provenance_verified;entry_policy_provenance_verified;entry_policy_static_verified;entry_policy_probe_containment_tool_verified"
      FIXTURES_SETUP entry_policy_probe_containment_verified
  )
  set_tests_properties(
    entry_policy_probe_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;guest32_provenance_verified;entry_policy_provenance_verified;entry_policy_static_verified;entry_policy_probe_pe_verified;entry_policy_probe_containment_verified"
      FIXTURES_SETUP entry_policy_probe_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    entry_policy_probe_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "entry_policy_probe_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP entry_policy_probe_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_probe
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;entry_policy_probe_post_verified"
  )
  set_tests_properties(
    startup_100f1c10_provenance
    PROPERTIES FIXTURES_SETUP startup_100f1c10_provenance_verified
  )
  set_tests_properties(
    startup_100f1c10_static_gate_unit
    PROPERTIES FIXTURES_SETUP startup_100f1c10_static_tool_verified
  )
  set_tests_properties(
    startup_100f1c10_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100f1c10_static_tool_verified
      FIXTURES_SETUP startup_100f1c10_static_verified
  )
  set_tests_properties(
    startup_100f1c10_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "entry_policy_probe_post_verified;guest32_provenance_verified;startup_100f1c10_provenance_verified;startup_100f1c10_static_verified"
      FIXTURES_SETUP startup_100f1c10_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100f1c10_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100f1c10_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100f1c10_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100f1c10
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100f1c10_post_verified"
  )
  set_tests_properties(
    startup_100f1aa0_empty_provenance
    PROPERTIES FIXTURES_SETUP startup_100f1aa0_empty_provenance_verified
  )
  set_tests_properties(
    startup_100f1aa0_empty_static_gate_unit
    PROPERTIES FIXTURES_SETUP startup_100f1aa0_empty_static_tool_verified
  )
  set_tests_properties(
    startup_100f1aa0_empty_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100f1aa0_empty_static_tool_verified
      FIXTURES_SETUP startup_100f1aa0_empty_static_verified
  )
  set_tests_properties(
    startup_100f1aa0_empty_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100f1c10_post_verified;startup_100f1aa0_empty_provenance_verified;startup_100f1aa0_empty_static_verified"
      FIXTURES_SETUP startup_100f1aa0_empty_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100f1aa0_empty_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100f1aa0_empty_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100f1aa0_empty_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100f1aa0_empty
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100f1aa0_empty_post_verified"
  )
  set_tests_properties(
    startup_safe_seams_provenance
    PROPERTIES FIXTURES_SETUP startup_safe_seams_provenance_verified
  )
  set_tests_properties(
    startup_safe_seams_static_gate_unit
    PROPERTIES FIXTURES_SETUP startup_safe_seams_static_tool_verified
  )
  set_tests_properties(
    startup_safe_seams_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_safe_seams_static_tool_verified
      FIXTURES_SETUP startup_safe_seams_static_verified
  )
  set_tests_properties(
    startup_safe_seams_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100f1aa0_empty_post_verified;startup_safe_seams_provenance_verified;startup_safe_seams_static_verified"
      FIXTURES_SETUP startup_safe_seams_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_safe_seams_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_safe_seams_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_safe_seams_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_safe_seams
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_safe_seams_post_verified"
  )
  set_tests_properties(
    startup_100df270_headless_provenance
    PROPERTIES FIXTURES_SETUP startup_100df270_headless_provenance_verified
  )
  set_tests_properties(
    startup_100df270_headless_static_gate_unit
    PROPERTIES FIXTURES_SETUP startup_100df270_headless_static_tool_verified
  )
  set_tests_properties(
    startup_100df270_headless_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100df270_headless_static_tool_verified
      FIXTURES_SETUP startup_100df270_headless_static_verified
  )
  set_tests_properties(
    startup_100df270_headless_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_safe_seams_post_verified;startup_100df270_headless_provenance_verified;startup_100df270_headless_static_verified"
      FIXTURES_SETUP startup_100df270_headless_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100df270_headless_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100df270_headless_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100df270_headless_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100df270_headless
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100df270_headless_post_verified"
  )
  set_tests_properties(
    startup_100f2750_nonalloc_provenance
    PROPERTIES FIXTURES_SETUP startup_100f2750_nonalloc_provenance_verified
  )
  set_tests_properties(
    startup_100f2750_nonalloc_static_gate_unit
    PROPERTIES FIXTURES_SETUP startup_100f2750_nonalloc_static_tool_verified
  )
  set_tests_properties(
    startup_100f2750_nonalloc_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100f2750_nonalloc_static_tool_verified
      FIXTURES_SETUP startup_100f2750_nonalloc_static_verified
  )
  set_tests_properties(
    startup_100f2750_nonalloc_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100df270_headless_post_verified;startup_100f2750_nonalloc_provenance_verified;startup_100f2750_nonalloc_static_verified"
      FIXTURES_SETUP startup_100f2750_nonalloc_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100f2750_nonalloc_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100f2750_nonalloc_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100f2750_nonalloc_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100f2750_nonalloc
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100f2750_nonalloc_post_verified"
  )
  set_tests_properties(
    startup_100e8240_fastpath_provenance
    PROPERTIES FIXTURES_SETUP startup_100e8240_fastpath_provenance_verified
  )
  set_tests_properties(
    startup_100ea4d0_evidence_provenance
    PROPERTIES FIXTURES_SETUP startup_100ea4d0_evidence_verified
  )
  set_tests_properties(
    startup_100e8240_fastpath_static_gate_unit
    PROPERTIES FIXTURES_SETUP startup_100e8240_fastpath_static_tool_verified
  )
  set_tests_properties(
    startup_100e8240_fastpath_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e8240_fastpath_static_tool_verified
      FIXTURES_SETUP startup_100e8240_fastpath_static_verified
  )
  set_tests_properties(
    startup_100e8240_fastpath_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100f2750_nonalloc_post_verified;startup_100e8240_fastpath_provenance_verified;startup_100ea4d0_evidence_verified;startup_100e8240_fastpath_static_verified"
      FIXTURES_SETUP startup_100e8240_fastpath_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e8240_fastpath_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8240_fastpath_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e8240_fastpath_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e8240_fastpath
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e8240_fastpath_post_verified"
      FIXTURES_SETUP startup_100e8240_fastpath_reload_verified
  )
  set_tests_properties(
    startup_100e2460_append_prefix_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_append_prefix_provenance_verified
  )
  set_tests_properties(
    startup_100e2460_append_prefix_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_append_prefix_static_tool_verified
  )
  set_tests_properties(
    startup_100e2460_append_prefix_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e2460_append_prefix_static_tool_verified
      FIXTURES_SETUP startup_100e2460_append_prefix_static_verified
  )
  set_tests_properties(
    startup_100e2460_append_prefix_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8240_fastpath_reload_verified;startup_100e2460_append_prefix_provenance_verified;startup_100e2460_append_prefix_static_verified"
      FIXTURES_SETUP startup_100e2460_append_prefix_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e2460_append_prefix_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_append_prefix_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e2460_append_prefix_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e2460_append_prefix
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e2460_append_prefix_post_verified"
      FIXTURES_SETUP startup_100e2460_append_prefix_reload_verified
  )
  set_tests_properties(
    startup_100e2460_preallocated_branch_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_preallocated_branch_provenance_verified
  )
  set_tests_properties(
    startup_100e2460_preallocated_branch_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_preallocated_branch_static_tool_verified
  )
  set_tests_properties(
    startup_100e2460_preallocated_branch_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e2460_preallocated_branch_static_tool_verified
      FIXTURES_SETUP startup_100e2460_preallocated_branch_static_verified
  )
  set_tests_properties(
    startup_100e2460_preallocated_branch_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_append_prefix_reload_verified;startup_100e2460_preallocated_branch_provenance_verified;startup_100e2460_preallocated_branch_static_verified"
      FIXTURES_SETUP startup_100e2460_preallocated_branch_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e2460_preallocated_branch_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_preallocated_branch_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e2460_preallocated_branch_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e2460_preallocated_branch
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e2460_preallocated_branch_post_verified"
      FIXTURES_SETUP startup_100e2460_preallocated_branch_reload_verified
  )
  set_tests_properties(
    startup_100e2460_capacity_zero_branch_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_capacity_zero_branch_provenance_verified
  )
  set_tests_properties(
    startup_100e2460_capacity_zero_branch_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_capacity_zero_branch_static_tool_verified
  )
  set_tests_properties(
    startup_100e2460_capacity_zero_branch_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e2460_capacity_zero_branch_static_tool_verified
      FIXTURES_SETUP startup_100e2460_capacity_zero_branch_static_verified
  )
  set_tests_properties(
    startup_100e2460_capacity_zero_branch_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_preallocated_branch_reload_verified;startup_100e2460_capacity_zero_branch_provenance_verified;startup_100e2460_capacity_zero_branch_static_verified"
      FIXTURES_SETUP startup_100e2460_capacity_zero_branch_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e2460_capacity_zero_branch_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_capacity_zero_branch_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e2460_capacity_zero_branch_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e2460_capacity_zero_branch
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e2460_capacity_zero_branch_post_verified"
      FIXTURES_SETUP startup_100e2460_capacity_zero_branch_reload_verified
  )
  set_tests_properties(
    startup_100e2460_growth_branch_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_growth_branch_provenance_verified
  )
  set_tests_properties(
    startup_100e2460_growth_branch_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_growth_branch_static_tool_verified
  )
  set_tests_properties(
    startup_100e2460_growth_branch_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e2460_growth_branch_static_tool_verified
      FIXTURES_SETUP startup_100e2460_growth_branch_static_verified
  )
  set_tests_properties(
    startup_100e2460_growth_branch_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_capacity_zero_branch_reload_verified;startup_100e2460_growth_branch_provenance_verified;startup_100e2460_growth_branch_static_verified"
      FIXTURES_SETUP startup_100e2460_growth_branch_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e2460_growth_branch_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_growth_branch_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e2460_growth_branch_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e2460_growth_branch
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e2460_growth_branch_post_verified"
      FIXTURES_SETUP startup_100e2460_growth_branch_reload_verified
  )
  set_tests_properties(
    startup_100e2460_router_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_router_provenance_verified
  )
  set_tests_properties(
    startup_100e2460_router_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e2460_router_static_tool_verified
  )
  set_tests_properties(
    startup_100e2460_router_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e2460_router_static_tool_verified
      FIXTURES_SETUP startup_100e2460_router_static_verified
  )
  set_tests_properties(
    startup_100e2460_router_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_growth_branch_reload_verified;startup_100e2460_router_provenance_verified;startup_100e2460_router_static_verified"
      FIXTURES_SETUP startup_100e2460_router_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e2460_router_six_append_runtime
    PROPERTIES
      FIXTURES_REQUIRED startup_100e2460_router_runtime_verified
      FIXTURES_SETUP startup_100e2460_router_six_append_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e2460_router_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_router_six_append_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e2460_router_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e2460_router
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e2460_router_post_verified"
      FIXTURES_SETUP startup_100e2460_router_reload_verified
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e8d00_handler_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e8d00_handler_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e8d00_handler_transcript_static_tool_verified
      FIXTURES_SETUP startup_100e8d00_handler_transcript_static_verified
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e2460_router_reload_verified;startup_100e8d00_handler_transcript_provenance_verified;startup_100e8d00_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e8d00_handler_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e8d00_handler_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8d00_handler_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e8d00_handler_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e8d00_handler_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e8d00_handler_transcript_post_verified"
      FIXTURES_SETUP startup_100e8d00_handler_transcript_reload_verified
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e85d0_normal_adapter_provenance_verified
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e85d0_normal_adapter_static_tool_verified
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e85d0_normal_adapter_static_tool_verified
      FIXTURES_SETUP startup_100e85d0_normal_adapter_static_verified
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8d00_handler_transcript_reload_verified;startup_100e85d0_normal_adapter_provenance_verified;startup_100e85d0_normal_adapter_static_verified"
      FIXTURES_SETUP startup_100e85d0_normal_adapter_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e85d0_normal_adapter_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e85d0_normal_adapter_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e85d0_normal_adapter_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e85d0_normal_adapter
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e85d0_normal_adapter_post_verified"
      FIXTURES_SETUP startup_100e85d0_normal_adapter_reload_verified
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e8580_handler_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e8580_handler_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e8580_handler_transcript_static_tool_verified
      FIXTURES_SETUP startup_100e8580_handler_transcript_static_verified
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e85d0_normal_adapter_reload_verified;startup_100e8580_handler_transcript_provenance_verified;startup_100e8580_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e8580_handler_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e8580_handler_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8580_handler_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e8580_handler_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e8580_handler_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e8580_handler_transcript_post_verified"
      FIXTURES_SETUP startup_100e8580_handler_transcript_reload_verified
  )
  set_tests_properties(
    startup_100ea4d0_executable_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100ea4d0_executable_provenance_verified
  )
  set_tests_properties(
    startup_100ea4d0_injected_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100ea4d0_injected_static_tool_verified
  )
  set_tests_properties(
    startup_100ea4d0_injected_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100ea4d0_injected_static_tool_verified
      FIXTURES_SETUP startup_100ea4d0_injected_static_verified
  )
  set_tests_properties(
    startup_100ea4d0_injected_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e8580_handler_transcript_reload_verified;startup_100ea4d0_executable_provenance_verified;startup_100ea4d0_injected_static_verified"
      FIXTURES_SETUP startup_100ea4d0_injected_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100ea4d0_injected_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ea4d0_injected_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100ea4d0_injected_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100ea4d0_injected
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100ea4d0_injected_post_verified"
      FIXTURES_SETUP startup_100ea4d0_injected_reload_verified
  )
  set_tests_properties(
    startup_100e9340_handler_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e9340_handler_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100e9340_handler_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e9340_handler_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100e9340_handler_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e9340_handler_transcript_static_tool_verified
      FIXTURES_SETUP startup_100e9340_handler_transcript_static_verified
  )
  set_tests_properties(
    startup_100e9340_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ea4d0_injected_reload_verified;startup_100e9340_handler_transcript_provenance_verified;startup_100e9340_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e9340_handler_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e9340_handler_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e9340_handler_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e9340_handler_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e9340_handler_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e9340_handler_transcript_post_verified"
      FIXTURES_SETUP startup_100e9340_handler_transcript_reload_verified
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e92c0_handler_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e92c0_handler_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e92c0_handler_transcript_static_tool_verified
      FIXTURES_SETUP startup_100e92c0_handler_transcript_static_verified
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e9340_handler_transcript_reload_verified;startup_100e92c0_handler_transcript_provenance_verified;startup_100e92c0_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e92c0_handler_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e92c0_handler_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e92c0_handler_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e92c0_handler_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e92c0_handler_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e92c0_handler_transcript_post_verified"
      FIXTURES_SETUP startup_100e92c0_handler_transcript_reload_verified
  )
  set_tests_properties(
    startup_100e87a0_handler_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100e87a0_handler_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100e87a0_handler_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100e87a0_handler_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100e87a0_handler_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100e87a0_handler_transcript_static_tool_verified
      FIXTURES_SETUP startup_100e87a0_handler_transcript_static_verified
  )
  set_tests_properties(
    startup_100e87a0_handler_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e92c0_handler_transcript_reload_verified;startup_100e87a0_handler_transcript_provenance_verified;startup_100e87a0_handler_transcript_static_verified"
      FIXTURES_SETUP startup_100e87a0_handler_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100e87a0_handler_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e87a0_handler_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100e87a0_handler_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100e87a0_handler_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100e87a0_handler_transcript_post_verified"
      FIXTURES_SETUP startup_100e87a0_handler_transcript_reload_verified
  )
  set_tests_properties(
    startup_100df270_suffix_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100df270_suffix_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100df270_suffix_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100df270_suffix_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100df270_suffix_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100df270_suffix_transcript_static_tool_verified
      FIXTURES_SETUP startup_100df270_suffix_transcript_static_verified
  )
  set_tests_properties(
    startup_100df270_suffix_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100e87a0_handler_transcript_reload_verified;startup_100df270_suffix_transcript_provenance_verified;startup_100df270_suffix_transcript_static_verified"
      FIXTURES_SETUP startup_100df270_suffix_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100df270_suffix_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100df270_suffix_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100df270_suffix_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100df270_suffix_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100df270_suffix_transcript_post_verified"
      FIXTURES_SETUP startup_100df270_suffix_transcript_reload_verified
  )
  set_tests_properties(
    startup_100df270_platform_prefix_transcript_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100df270_platform_prefix_transcript_provenance_verified
  )
  set_tests_properties(
    startup_100df270_platform_prefix_transcript_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100df270_platform_prefix_transcript_static_tool_verified
  )
  set_tests_properties(
    startup_100df270_platform_prefix_transcript_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100df270_platform_prefix_transcript_static_tool_verified
      FIXTURES_SETUP startup_100df270_platform_prefix_transcript_static_verified
  )
  set_tests_properties(
    startup_100df270_platform_prefix_transcript_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100df270_suffix_transcript_reload_verified;startup_100df270_platform_prefix_transcript_provenance_verified;startup_100df270_platform_prefix_transcript_static_verified"
      FIXTURES_SETUP startup_100df270_platform_prefix_transcript_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100df270_platform_prefix_transcript_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100df270_platform_prefix_transcript_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100df270_platform_prefix_transcript_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100df270_platform_prefix_transcript
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100df270_platform_prefix_transcript_post_verified"
      FIXTURES_SETUP startup_100df270_platform_prefix_transcript_reload_verified
  )
  set_tests_properties(
    startup_100ed3c0_empty_preloop_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100ed3c0_empty_preloop_provenance_verified
  )
  set_tests_properties(
    startup_100ed3c0_empty_preloop_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100ed3c0_empty_preloop_static_tool_verified
  )
  set_tests_properties(
    startup_100ed3c0_empty_preloop_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100ed3c0_empty_preloop_static_tool_verified
      FIXTURES_SETUP startup_100ed3c0_empty_preloop_static_verified
  )
  set_tests_properties(
    startup_100ed3c0_empty_preloop_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100df270_platform_prefix_transcript_reload_verified;startup_100ed3c0_empty_preloop_provenance_verified;startup_100ed3c0_empty_preloop_static_verified"
      FIXTURES_SETUP startup_100ed3c0_empty_preloop_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100ed3c0_empty_preloop_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ed3c0_empty_preloop_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100ed3c0_empty_preloop_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100ed3c0_empty_preloop
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100ed3c0_empty_preloop_post_verified"
      FIXTURES_SETUP startup_100ed3c0_empty_preloop_reload_verified
  )
  set_tests_properties(
    startup_100ed471_ordinary_lifecycle_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100ed471_ordinary_lifecycle_provenance_verified
  )
  set_tests_properties(
    startup_100ed471_ordinary_lifecycle_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100ed471_ordinary_lifecycle_static_tool_verified
  )
  set_tests_properties(
    startup_100ed471_ordinary_lifecycle_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100ed471_ordinary_lifecycle_static_tool_verified
      FIXTURES_SETUP startup_100ed471_ordinary_lifecycle_static_verified
  )
  set_tests_properties(
    startup_100ed471_ordinary_lifecycle_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ed3c0_empty_preloop_reload_verified;startup_100ed471_ordinary_lifecycle_provenance_verified;startup_100ed471_ordinary_lifecycle_static_verified"
      FIXTURES_SETUP startup_100ed471_ordinary_lifecycle_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100ed471_ordinary_lifecycle_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ed471_ordinary_lifecycle_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100ed471_ordinary_lifecycle_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100ed471_ordinary_lifecycle
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100ed471_ordinary_lifecycle_post_verified"
      FIXTURES_SETUP startup_100ed471_ordinary_lifecycle_reload_verified
  )
  set_tests_properties(
    startup_100f1bb0_owned_utf16_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100f1bb0_owned_utf16_provenance_verified
  )
  set_tests_properties(
    startup_100f1bb0_owned_utf16_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100f1bb0_owned_utf16_static_tool_verified
  )
  set_tests_properties(
    startup_100f1bb0_owned_utf16_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100f1bb0_owned_utf16_static_tool_verified
      FIXTURES_SETUP startup_100f1bb0_owned_utf16_static_verified
  )
  set_tests_properties(
    startup_100f1bb0_owned_utf16_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ed471_ordinary_lifecycle_reload_verified;startup_100f1bb0_owned_utf16_provenance_verified;startup_100f1bb0_owned_utf16_static_verified"
      FIXTURES_SETUP startup_100f1bb0_owned_utf16_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100f2750_sentinel_owned_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100f2750_sentinel_owned_provenance_verified
  )
  set_tests_properties(
    startup_100f2750_sentinel_owned_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100f2750_sentinel_owned_static_tool_verified
  )
  set_tests_properties(
    startup_100f2750_sentinel_owned_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100f2750_sentinel_owned_static_tool_verified
      FIXTURES_SETUP startup_100f2750_sentinel_owned_static_verified
  )
  set_tests_properties(
    startup_100f2750_sentinel_owned_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100f1bb0_owned_utf16_runtime_verified;startup_100f2750_sentinel_owned_provenance_verified;startup_100f2750_sentinel_owned_static_verified"
      FIXTURES_SETUP startup_100f2750_sentinel_owned_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_preloop_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100ed3c0_nonempty_preloop_provenance_verified
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_preloop_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100ed3c0_nonempty_preloop_static_tool_verified
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_preloop_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100ed3c0_nonempty_preloop_static_tool_verified
      FIXTURES_SETUP startup_100ed3c0_nonempty_preloop_static_verified
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_preloop_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100df270_suffix_transcript_reload_verified;startup_100f1bb0_owned_utf16_runtime_verified;startup_100f2750_sentinel_owned_runtime_verified;startup_100ed3c0_nonempty_preloop_provenance_verified;startup_100ed3c0_nonempty_preloop_static_verified"
      FIXTURES_SETUP startup_100ed3c0_nonempty_preloop_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_preloop_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ed3c0_nonempty_preloop_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100ed3c0_nonempty_preloop_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100ed3c0_nonempty_preloop
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100ed3c0_nonempty_preloop_post_verified"
      FIXTURES_SETUP startup_100ed3c0_nonempty_preloop_reload_verified
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_lifecycle_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100ed3c0_nonempty_lifecycle_provenance_verified
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_lifecycle_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100ed3c0_nonempty_lifecycle_static_tool_verified
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_lifecycle_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100ed3c0_nonempty_lifecycle_static_tool_verified
      FIXTURES_SETUP startup_100ed3c0_nonempty_lifecycle_static_verified
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_lifecycle_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ed3c0_nonempty_preloop_reload_verified;startup_100ed471_ordinary_lifecycle_reload_verified;startup_100ed3c0_nonempty_lifecycle_provenance_verified;startup_100ed3c0_nonempty_lifecycle_static_verified"
      FIXTURES_SETUP startup_100ed3c0_nonempty_lifecycle_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100ed3c0_nonempty_lifecycle_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100ed3c0_nonempty_lifecycle_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100ed3c0_nonempty_lifecycle_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100ed3c0_nonempty_lifecycle
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100ed3c0_nonempty_lifecycle_post_verified"
      FIXTURES_SETUP startup_100ed3c0_nonempty_lifecycle_reload_verified
  )
  set_tests_properties(
    startup_100edd70_caller_closure_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100edd70_caller_closure_provenance_verified
  )
  set_tests_properties(
    startup_100edd70_caller_closure_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100edd70_caller_closure_static_tool_verified
  )
  set_tests_properties(
    startup_100edd70_caller_closure_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100edd70_caller_closure_static_tool_verified
      FIXTURES_SETUP startup_100edd70_caller_closure_static_verified
  )
  set_tests_properties(
    startup_100edd70_caller_closure_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "entry_policy_provenance_verified;entry_policy_static_verified;startup_100ed3c0_nonempty_lifecycle_reload_verified;startup_100edd70_caller_closure_provenance_verified;startup_100edd70_caller_closure_static_verified"
      FIXTURES_SETUP startup_100edd70_caller_closure_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100edd70_caller_closure_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100edd70_caller_closure_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100edd70_caller_closure_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100edd70_caller_closure
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100edd70_caller_closure_post_verified"
      FIXTURES_SETUP startup_100edd70_caller_closure_reload_verified
  )
  set_tests_properties(
    startup_100edd70_entry_decision_provenance
    PROPERTIES
      FIXTURES_SETUP startup_100edd70_entry_decision_provenance_verified
  )
  set_tests_properties(
    startup_100edd70_entry_decision_static_gate_unit
    PROPERTIES
      FIXTURES_SETUP startup_100edd70_entry_decision_static_tool_verified
  )
  set_tests_properties(
    startup_100edd70_entry_decision_static_gate
    PROPERTIES
      FIXTURES_REQUIRED startup_100edd70_entry_decision_static_tool_verified
      FIXTURES_SETUP startup_100edd70_entry_decision_static_verified
  )
  set_tests_properties(
    startup_100edd70_entry_decision_runtime
    PROPERTIES
      FIXTURES_REQUIRED
        "entry_policy_provenance_verified;entry_policy_static_verified;startup_100edd70_caller_closure_reload_verified;startup_100edd70_entry_decision_provenance_verified;startup_100edd70_entry_decision_static_verified"
      FIXTURES_SETUP startup_100edd70_entry_decision_runtime_verified
      TIMEOUT 90
  )
  set_tests_properties(
    startup_100edd70_entry_decision_post_pe_gate
    PROPERTIES
      FIXTURES_REQUIRED
        "startup_100edd70_entry_decision_runtime_verified;entry_policy_probe_pe_tool_verified"
      FIXTURES_SETUP startup_100edd70_entry_decision_post_verified
  )
  set_tests_properties(
    x64_bootstrap_load_after_startup_100edd70_entry_decision
    PROPERTIES
      FIXTURES_REQUIRED
        "x64_bootstrap_pre_verified;startup_100edd70_entry_decision_post_verified"
      FIXTURES_SETUP startup_100edd70_entry_decision_reload_verified
  )
  set_tests_properties(
    headless_bounded_lifecycle
    PROPERTIES
      FIXTURES_REQUIRED
        "entry_policy_provenance_verified;entry_policy_static_verified;startup_100ed471_ordinary_lifecycle_reload_verified"
      TIMEOUT 90
  )
endif()
