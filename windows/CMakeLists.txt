cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "certificate_pinning_httpclient")
project(${PROJECT_NAME} LANGUAGES CXX)

cmake_policy(VERSION 3.14...3.25)

set(PLUGIN_NAME "${PROJECT_NAME}_plugin")

list(APPEND PLUGIN_SOURCES
  "certificate_pinning_httpclient_plugin.cpp"
  "certificate_pinning_httpclient_plugin.h"
)

add_library(${PLUGIN_NAME} SHARED
  "include/certificate_pinning_httpclient/certificate_pinning_http_client_plugin_c_api.h"
  "certificate_pinning_httpclient_plugin_c_api.cpp"
  ${PLUGIN_SOURCES}
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE
  flutter
  flutter_wrapper_plugin
  crypt32
  winhttp
)

set(certificate_pinning_httpclient_bundled_libraries
  ""
  PARENT_SCOPE
)
