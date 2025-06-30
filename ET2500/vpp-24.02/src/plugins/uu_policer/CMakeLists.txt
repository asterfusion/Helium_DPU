
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

add_vpp_plugin(uu_policer
  SOURCES
  plugin.c
  l2_uu_policer.c
  l2_uu_policer_node.c
  l2_uu_policer_api.c
  l2_uu_policer_cli.c
  

  MULTIARCH_SOURCES
  l2_uu_policer_node.c

  API_FILES
  l2_uu_policer.api

  API_TEST_SOURCES
)
