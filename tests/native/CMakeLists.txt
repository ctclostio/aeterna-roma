cmake_minimum_required(VERSION 3.25)
cmake_policy(SET CMP0091 NEW)
project(Rome2PublicTests VERSION 0.1.0 LANGUAGES C)

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Public native tests require Windows x64 MSVC.")
endif()

include(CTest)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
# Runtime tests use assert(); keep those checks active in optimized builds.
string(REPLACE "/DNDEBUG" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
option(ROME2_TYPES_ASAN "Run public native tests with AddressSanitizer" OFF)
get_filename_component(ROME2_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

# This is a standalone test graph. It does not admit draft entry compositions
# into the production bootstrap or substitute for original-byte provenance.
add_subdirectory("${ROME2_ROOT}/port/recovered_types" recovered-types)

function(configure_public_target target)
  target_compile_features(${target} PRIVATE c_std_17)
  target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX WINVER=0x0602 _WIN32_WINNT=0x0602)
  target_compile_options(${target} PRIVATE /W4 /WX /sdl /GS /guard:cf)
  if(ROME2_TYPES_ASAN)
    target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
    target_link_options(${target} PRIVATE /DEBUG /INCREMENTAL:NO)
  endif()
endfunction()

add_library(rome2_public_ported STATIC
  "${ROME2_ROOT}/port/x64_ported/ported_100df270_headless.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100df270_platform_prefix_transcript.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100df270_suffix_transcript.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e2460_append_prefix.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e2460_capacity_zero_branch.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e2460_growth_branch.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e2460_preallocated_branch.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e2460_router.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e3360_vfs.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e39c0_battle.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e6310_render.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e8240_fastpath.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e8240_singleton.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e8580_handler_transcript.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e85d0_normal_adapter.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e87a0_handler_transcript.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e8d00_handler_transcript.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e8e80_audio.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e92c0_handler_transcript.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100e9340_handler_transcript.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100ea060_injected.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100ea4d0_injected.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100ed3c0_empty_preloop.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100ed3c0_nonempty_lifecycle.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100ed3c0_nonempty_preloop.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100ed471_ordinary_lifecycle.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100edd70_caller_closure.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100edd70_entry_decision.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100edd70_full_entry.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100edd70_policy.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100edd70_terminal_transcript.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100edd70_unified_entry.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100f1aa0_empty.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100f1bb0_bounded.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100f1bb0_owned_utf16.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100f1c10_triplet.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100f1cc0_nonowning.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100f2750_first_use_owned.c"
  "${ROME2_ROOT}/port/x64_ported/ported_100f2750_nonalloc.c"
  "${ROME2_ROOT}/port/x64_ported/ported_106ba2e0_campaign.c"
  "${ROME2_ROOT}/port/x64_ported/ported_1075da00_model.c"
  "${ROME2_ROOT}/port/x64_ported/ported_1093c450.c"
 )
target_include_directories(rome2_public_ported PUBLIC
  "${ROME2_ROOT}/port/x64_ported"
  "${ROME2_ROOT}/port/x64_runtime"
)
target_link_libraries(rome2_public_ported PUBLIC rome2_recovered_types ole32)
configure_public_target(rome2_public_ported)

set(ROME2_PUBLIC_TEST_SOURCES
  test_audio_100e8e80.c
  test_battle_100e39c0.c
  test_campaign_106ba2e0.c
  test_entry_policy.c
  test_guest32.c
  test_model_1075da00.c
  test_render_100e6310.c
  test_singleton_100e8240.c
  test_startup_100df270_headless.c
  test_startup_100df270_platform_prefix_transcript.c
  test_startup_100df270_suffix_transcript.c
  test_startup_100e2460_append_prefix.c
  test_startup_100e2460_capacity_zero_branch.c
  test_startup_100e2460_growth_branch.c
  test_startup_100e2460_preallocated_branch.c
  test_startup_100e2460_router.c
  test_startup_100e2460_router_six_append.c
  test_startup_100e8240_fastpath.c
  test_startup_100e8580_handler_transcript.c
  test_startup_100e85d0_normal_adapter.c
  test_startup_100e87a0_handler_transcript.c
  test_startup_100e8d00_handler_transcript.c
  test_startup_100e92c0_handler_transcript.c
  test_startup_100e9340_handler_transcript.c
  test_startup_100ea060_injected.c
  test_startup_100ea4d0_injected.c
  test_startup_100ed3c0_empty_preloop.c
  test_startup_100ed3c0_nonempty_lifecycle.c
  test_startup_100ed3c0_nonempty_preloop.c
  test_startup_100ed471_ordinary_lifecycle.c
  test_startup_100edd70_caller_closure.c
  test_startup_100edd70_entry_decision.c
  test_startup_100edd70_full_entry.c
  test_startup_100edd70_terminal_transcript.c
  test_startup_100edd70_unified_entry.c
  test_startup_100f1aa0_empty.c
  test_startup_100f1bb0_owned_utf16.c
  test_startup_100f1c10.c
  test_startup_100f2750_nonalloc.c
  test_startup_100f2750_sentinel_owned.c
  test_startup_safe_seams.c
  test_vfs_100e3360.c
 )
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
foreach(source IN LISTS ROME2_PUBLIC_TEST_SOURCES)
  get_filename_component(stem "${source}" NAME_WE)
  add_executable(rome2_public_${stem} "${ROME2_ROOT}/port/x64_runtime/${source}")
  target_link_libraries(rome2_public_${stem} PRIVATE rome2_public_ported)
  configure_public_target(rome2_public_${stem})
  if(stem STREQUAL "test_campaign_106ba2e0")
    add_test(NAME public_${stem} COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/campaign_fixture.py"
      "$<TARGET_FILE:rome2_public_${stem}>")
  else()
    add_test(NAME public_${stem} COMMAND rome2_public_${stem})
  endif()
endforeach()

add_executable(rome2_terminal_runner
  "${ROME2_ROOT}/tests/terminal_runtime/main.c")
target_link_libraries(rome2_terminal_runner PRIVATE rome2_public_ported)
configure_public_target(rome2_terminal_runner)
add_test(NAME public_terminal_scenarios COMMAND "${Python3_EXECUTABLE}"
  "${ROME2_ROOT}/tests/terminal_runtime/test_runner.py"
  "$<TARGET_FILE:rome2_terminal_runner>")
