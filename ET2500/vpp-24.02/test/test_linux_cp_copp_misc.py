#!/usr/bin/env python3
"""Placeholder tests for traps that currently have no data-path producer."""

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    MISC_TRAPS,
    generate_trap_methods,
)


class TestLinuxCpCoppMisc(LinuxCpCoppTestCase):
    """Misc / placeholder CoPP tests."""

    pass


generate_trap_methods(TestLinuxCpCoppMisc, MISC_TRAPS)

if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
