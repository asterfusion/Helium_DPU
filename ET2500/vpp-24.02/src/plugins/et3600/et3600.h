
/*
 * et3600.h - ET3600 port control plugin header
 *
 * Copyright 2024-2027 Asterfusion Network
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_et3600_h__
#define __included_et3600_h__

#include <vlib/log.h>

extern vlib_log_class_registration_t et3600_log;

#define et3600_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, et3600_log.class, __VA_ARGS__)
#define et3600_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, et3600_log.class, __VA_ARGS__)
#define et3600_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, et3600_log.class, __VA_ARGS__)
#define et3600_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, et3600_log.class, __VA_ARGS__)

#endif /* __included_et3600_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
