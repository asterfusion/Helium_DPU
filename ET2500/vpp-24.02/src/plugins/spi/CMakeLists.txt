# Copyright 2024-2027 Asterfusion Network
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

add_vpp_plugin(spi
  SOURCES
  plugin.c
  spi.c
  spi_api.c
  spi_cli.c
  spi_format.c
  spi_node.c
  spi_aging.c
  spi_handoff_node.c
  

  MULTIARCH_SOURCES
  spi_node.c
  spi_aging.c
  spi_handoff_node.c

  API_FILES
  spi.api

  API_TEST_SOURCES
)
