
# Copyright (c) <2024-2027> <Asterfusion Network>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

add_vpp_plugin(geosite
  SOURCES
  geosite.c
  node.c
  geosite_periodic.c
  geosite.h
  domain_trie.c
  domain_trie.h
  geoip_trie.c
  geoip_trie.h

  MULTIARCH_SOURCES
  node.c

  API_FILES
  geosite.api

  API_TEST_SOURCES
  geosite_test.c
)


find_package(PkgConfig REQUIRED)
pkg_check_modules(PROTOBUF_C REQUIRED libprotobuf-c)

set(PROTO_SRCS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

set(PROTO_FILES
    ${PROTO_SRCS_DIR}/common.proto
)

set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GENERATED_DIR})

set(GENERATED_SRCS "")
set(GENERATED_HDRS "")

foreach(protofile IN LISTS PROTO_FILES)
    get_filename_component(proto_name ${protofile} NAME_WE)
    set(src_file ${GENERATED_DIR}/${proto_name}.pb-c.c)
    set(hdr_file ${GENERATED_DIR}/${proto_name}.pb-c.h)
    list(APPEND GENERATED_SRCS ${src_file})
    list(APPEND GENERATED_HDRS ${hdr_file})

    add_custom_command(
        OUTPUT ${src_file} ${hdr_file}
        COMMAND protoc-c --proto_path=${PROTO_SRCS_DIR} --c_out=${GENERATED_DIR} ${protofile}
        DEPENDS ${protofile}
        COMMENT "Generating C protobuf files from ${proto_name}.proto"
        VERBATIM
    )
endforeach()

add_library(geoproto_c_objs STATIC ${GENERATED_SRCS})
target_include_directories(geoproto_c_objs PUBLIC ${GENERATED_DIR} ${PROTOBUF_C_INCLUDE_DIRS})
target_compile_options(geoproto_c_objs PRIVATE -fPIC)

target_include_directories(geosite_plugin PRIVATE ${GENERATED_DIR} ${PROTOBUF_C_INCLUDE_DIRS})
target_link_libraries(geosite_plugin geoproto_c_objs ${PROTOBUF_C_LIBRARIES})
