/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

def run_ci(Object s) {
	node ("buildenv-2004-le") {
		s.GROOVY_DIR = '/data/isoc_platform_devops/dev-ci/scripts_cache/dev-ci/dpdk'
		s.preinit = load s.GROOVY_DIR + "/preinit.groovy"
	}
	s.preinit.run(s)
}

return this
