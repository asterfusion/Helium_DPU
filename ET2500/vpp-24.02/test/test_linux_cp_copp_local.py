#!/usr/bin/env python3
"""CoPP host-bound (local context) tests."""

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    LOCAL_TRAPS,
    generate_trap_methods,
)


class TestLinuxCpCoppLocal(LinuxCpCoppTestCase):
    """Host-bound CoPP classification tests."""

    pass


generate_trap_methods(TestLinuxCpCoppLocal, LOCAL_TRAPS)

if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
