cmake_minimum_required(VERSION 3.25)
project(Rome2RecoveredTypes VERSION 0.1.0 LANGUAGES C)

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Recovered native types require Windows x64 MSVC.")
endif()

include(CTest)
option(ROME2_TYPES_ASAN "Instrument recovered type tests with AddressSanitizer" OFF)
if(ROME2_TYPES_ASAN AND NOT CMAKE_BUILD_TYPE STREQUAL "Release")
  message(FATAL_ERROR "The standalone ASan profile requires CMAKE_BUILD_TYPE=Release.")
endif()

function(configure_type_target target)
  target_compile_features(${target} PRIVATE c_std_17)
  target_compile_options(${target} PRIVATE /W4 /WX /sdl /GS /guard:cf)
  target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  set_property(TARGET ${target} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
  if(ROME2_TYPES_ASAN)
    target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
    target_link_options(${target} PRIVATE /DEBUG /INCREMENTAL:NO)
  else()
    target_compile_options(${target} PRIVATE /analyze)
  endif()
endfunction()

# Separate project: no dependency is added to the inert production bootstrap,
# and the immutable canonical sources and shared Ghidra DB are not touched.
add_library(rome2_recovered_types STATIC
  owned_string.c owned_string.h
  layout_bridge.c layout_bridge.h guest32_layouts.h
  owned_entity.c owned_entity.h
  free_list_pool.c free_list_pool.h image_defaults.h
  tag_types.h owned_tag.c owned_tag.h
  scalar_vectors.c scalar_vectors.h
  owned_fauna.c owned_fauna.h
  owned_unit_card.c owned_unit_card.h
  pack_resource.c pack_resource.h
  native_xml.c native_xml.h
  fauna_config.c fauna_config.h
  unit_card_resource.c unit_card_resource.h
  xml_loader_policy.c xml_loader_policy.h
  vfs_dispatch.c vfs_dispatch.h
  vfs_name.c vfs_name.h
  vfs_name_assign.c vfs_name_assign.h
  vfs_archive_tree.c vfs_archive_tree.h
  vfs_dependency_graph.c vfs_dependency_graph.h
  vfs_archive_register.c vfs_archive_register.h
  vfs_archive_mount_step.c vfs_archive_mount_step.h
  vfs_pack_entry.c vfs_pack_entry.h
  vfs_pack_stream.c vfs_pack_stream.h
  vfs_pool_slab.c vfs_pool_slab.h
  vfs_quota_map.c vfs_quota_map.h
  vfs_scan_mount.c vfs_scan_mount.h
  vfs_dep_rehash.c vfs_dep_rehash.h
  vfs_rb_bucket_ops.c vfs_rb_bucket_ops.h
  vfs_stream_wrap_ops.c vfs_stream_wrap_ops.h
  vfs_adj_open_ops.c vfs_adj_open_ops.h
  vfs_view_map_ops.c vfs_view_map_ops.h
  vfs_state_telemetry_ops.c vfs_state_telemetry_ops.h
  vfs_stream_completion_ops.c vfs_stream_completion_ops.h
  vfs_handle_lifecycle_ops.c vfs_handle_lifecycle_ops.h
  vfs_substream_loose_ops.c vfs_substream_loose_ops.h
  vfs_stream_mux_async_ops.c vfs_stream_mux_async_ops.h
  vfs_fs_secondary_ops.c vfs_fs_secondary_ops.h
  vfs_fs_primary_ops.c vfs_fs_primary_ops.h
  vfs_fs_mount_ops.c vfs_fs_mount_ops.h
  vfs_fs_index_atexit_ops.c vfs_fs_index_atexit_ops.h
  vfs_fs_init_xml_pack_ops.c vfs_fs_init_xml_pack_ops.h
  vfs_fs_folder_tree_ops.c vfs_fs_folder_tree_ops.h
  vfs_fs_leaf_codec_ops.c vfs_fs_leaf_codec_ops.h
  vfs_fs_codec_vec_ops.c vfs_fs_codec_vec_ops.h
  vfs_fs_dlmalloc_stream_ops.c vfs_fs_dlmalloc_stream_ops.h
  vfs_fs_engine_channel_ops.c vfs_fs_engine_channel_ops.h
  vfs_fs_engine_codec_ops.c vfs_fs_engine_codec_ops.h
  vfs_fs_engine_net_sys_ops.c vfs_fs_engine_net_sys_ops.h
  vfs_fs_engine_crt_ops.c vfs_fs_engine_crt_ops.h
  vfs_fs_engine_crt_fmt_ops.c vfs_fs_engine_crt_fmt_ops.h
  vfs_fs_engine_crt_io_ops.c vfs_fs_engine_crt_io_ops.h
  vfs_fs_engine_crt_sec_ops.c vfs_fs_engine_crt_sec_ops.h
  vfs_fs_engine_crt_flt_ops.c vfs_fs_engine_crt_flt_ops.h
  vfs_fs_engine_crt_env_ops.c vfs_fs_engine_crt_env_ops.h
  vfs_fs_engine_crt_fenv_ops.c vfs_fs_engine_crt_fenv_ops.h
  vfs_fs_engine_crt_strtox_ops.c vfs_fs_engine_crt_strtox_ops.h
  vfs_fs_engine_crt_printf_ops.c vfs_fs_engine_crt_printf_ops.h
  vfs_fs_engine_crt_lconv_ops.c vfs_fs_engine_crt_lconv_ops.h
  vfs_fs_engine_crt_wio_ops.c vfs_fs_engine_crt_wio_ops.h
  vfs_fs_engine_crt_fpfmt_ops.c vfs_fs_engine_crt_fpfmt_ops.h
  vfs_fs_engine_crt_utf8_ops.c vfs_fs_engine_crt_utf8_ops.h
  vfs_fs_engine_crt_fls_ops.c vfs_fs_engine_crt_fls_ops.h
  vfs_fs_engine_crt_scanf_ops.c vfs_fs_engine_crt_scanf_ops.h
  vfs_fs_engine_crt_envinit_ops.c vfs_fs_engine_crt_envinit_ops.h
  vfs_fs_engine_crt_mbcp_ops.c vfs_fs_engine_crt_mbcp_ops.h
  vfs_fs_engine_tail_thunk_ops.c vfs_fs_engine_tail_thunk_ops.h
  vfs_fs_engine_crt_exit_ops.c vfs_fs_engine_crt_exit_ops.h
  startup_export_bootstrap_ops.c startup_export_bootstrap_ops.h
  ../x64_runtime/guest32.c
  ../x64_ported/ported_10cbe350_entity.c
  ../x64_ported/ported_10145c70_unitcard.c
)
target_include_directories(rome2_recovered_types PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../x64_ported"
)
target_compile_features(rome2_recovered_types PUBLIC c_std_17)
set_source_files_properties(scalar_vectors.c fauna_config.c PROPERTIES COMPILE_OPTIONS /fp:strict)
target_link_libraries(rome2_recovered_types PUBLIC xmllite shlwapi uuid)
configure_type_target(rome2_recovered_types)

if(BUILD_TESTING)
  foreach(test IN ITEMS layout_bridge owned_string owned_entity free_list_pool owned_tag owned_attachment scalar_vectors owned_fauna unit_card_observer owned_unit_card pack_resource native_xml fauna_config unit_card_resource unit_card_xml_node xml_loader_policy vfs_dispatch vfs_name vfs_name_assign vfs_archive_tree vfs_dependency_graph vfs_archive_register vfs_archive_mount_step vfs_pack_entry vfs_pack_stream vfs_pool_slab vfs_quota_map vfs_scan_mount vfs_dep_rehash vfs_rb_bucket_ops vfs_stream_wrap_ops vfs_adj_open_ops vfs_view_map_ops vfs_state_telemetry_ops vfs_stream_completion_ops vfs_handle_lifecycle_ops vfs_substream_loose_ops vfs_stream_mux_async_ops vfs_fs_secondary_ops vfs_fs_primary_ops vfs_fs_mount_ops vfs_fs_index_atexit_ops vfs_fs_init_xml_pack_ops vfs_fs_folder_tree_ops vfs_fs_leaf_codec_ops vfs_fs_codec_vec_ops vfs_fs_dlmalloc_stream_ops vfs_fs_engine_channel_ops vfs_fs_engine_codec_ops vfs_fs_engine_net_sys_ops vfs_fs_engine_crt_ops vfs_fs_engine_crt_fmt_ops vfs_fs_engine_crt_io_ops vfs_fs_engine_crt_sec_ops vfs_fs_engine_crt_flt_ops vfs_fs_engine_crt_env_ops vfs_fs_engine_crt_fenv_ops vfs_fs_engine_crt_strtox_ops vfs_fs_engine_crt_printf_ops vfs_fs_engine_crt_lconv_ops vfs_fs_engine_crt_wio_ops vfs_fs_engine_crt_fpfmt_ops vfs_fs_engine_crt_utf8_ops vfs_fs_engine_crt_fls_ops vfs_fs_engine_crt_scanf_ops vfs_fs_engine_crt_envinit_ops vfs_fs_engine_crt_mbcp_ops vfs_fs_engine_tail_thunk_ops vfs_fs_engine_crt_exit_ops startup_export_bootstrap_ops)
    add_executable(rome2_${test}_tests test_${test}.c)
    target_link_libraries(rome2_${test}_tests PRIVATE rome2_recovered_types)
    configure_type_target(rome2_${test}_tests)
    if(test STREQUAL "pack_resource")
      add_test(NAME recovered_${test} COMMAND rome2_${test}_tests "${CMAKE_CURRENT_BINARY_DIR}")
    elseif(test STREQUAL "unit_card_resource")
      add_test(NAME recovered_${test} COMMAND rome2_${test}_tests "${CMAKE_CURRENT_BINARY_DIR}/unit-card-fixture.pack")
    else()
      add_test(NAME recovered_${test} COMMAND rome2_${test}_tests)
    endif()
  endforeach()
  foreach(slice IN ITEMS battle_unitcard_10145c70 battle_entity_10cbe350)
    add_executable(rome2_legacy_${slice}_tests ../x64_runtime/test_${slice}.c)
    target_link_libraries(rome2_legacy_${slice}_tests PRIVATE rome2_recovered_types)
    configure_type_target(rome2_legacy_${slice}_tests)
    add_test(NAME legacy_${slice} COMMAND rome2_legacy_${slice}_tests)
  endforeach()
  add_executable(rome2_fauna_asset_probe fauna_asset_probe.c)
  target_link_libraries(rome2_fauna_asset_probe PRIVATE rome2_recovered_types)
  configure_type_target(rome2_fauna_asset_probe)
  find_package(Python3 3.10 QUIET COMPONENTS Interpreter)
  set(ROME2_ASSET_DATA "${CMAKE_CURRENT_SOURCE_DIR}/../../Total War Rome II/data")
  if(Python3_Interpreter_FOUND AND EXISTS "${ROME2_ASSET_DATA}/data.pack" AND EXISTS "${ROME2_ASSET_DATA}/data_rome2.pack")
    add_test(NAME recovered_fauna_installed_assets COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/verify_fauna_resources.py"
      --probe "$<TARGET_FILE:rome2_fauna_asset_probe>" --data-root "${ROME2_ASSET_DATA}")
  else()
    message(STATUS "Installed fauna asset oracle not registered (requires Python3 and both local game archives).")
  endif()
endif()
