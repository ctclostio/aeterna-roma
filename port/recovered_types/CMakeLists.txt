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
  foreach(test IN ITEMS layout_bridge owned_string owned_entity free_list_pool owned_tag owned_attachment scalar_vectors owned_fauna unit_card_observer owned_unit_card pack_resource native_xml fauna_config unit_card_resource unit_card_xml_node xml_loader_policy)
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
