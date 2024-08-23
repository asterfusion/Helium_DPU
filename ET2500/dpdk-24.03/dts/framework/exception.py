# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation
# Copyright(c) 2022-2023 PANTHEON.tech s.r.o.
# Copyright(c) 2022-2023 University of New Hampshire

"""DTS exceptions.

The exceptions all have different severities expressed as an integer.
The highest severity of all raised exceptions is used as the exit code of DTS.
"""

from enum import IntEnum, unique
from typing import ClassVar


@unique
class ErrorSeverity(IntEnum):
    """The severity of errors that occur during DTS execution.

    All exceptions are caught and the most severe error is used as return code.
    """

    #:
    NO_ERR = 0
    #:
    GENERIC_ERR = 1
    #:
    CONFIG_ERR = 2
    #:
    REMOTE_CMD_EXEC_ERR = 3
    #:
    SSH_ERR = 4
    #:
    DPDK_BUILD_ERR = 10
    #:
    TESTCASE_VERIFY_ERR = 20
    #:
    BLOCKING_TESTSUITE_ERR = 25


class DTSError(Exception):
    """The base exception from which all DTS exceptions are subclassed.

    Do not use this exception, only use subclassed exceptions.
    """

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.GENERIC_ERR


class SSHTimeoutError(DTSError):
    """The SSH execution of a command timed out."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.SSH_ERR
    _command: str

    def __init__(self, command: str):
        """Define the meaning of the first argument.

        Args:
            command: The executed command.
        """
        self._command = command

    def __str__(self) -> str:
        """Add some context to the string representation."""
        return f"{self._command} execution timed out."


class SSHConnectionError(DTSError):
    """An unsuccessful SSH connection."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.SSH_ERR
    _host: str
    _errors: list[str]

    def __init__(self, host: str, errors: list[str] | None = None):
        """Define the meaning of the first two arguments.

        Args:
            host: The hostname to which we're trying to connect.
            errors: Any errors that occurred during the connection attempt.
        """
        self._host = host
        self._errors = [] if errors is None else errors

    def __str__(self) -> str:
        """Include the errors in the string representation."""
        message = f"Error trying to connect with {self._host}."
        if self._errors:
            message += f" Errors encountered while retrying: {', '.join(self._errors)}"

        return message


class SSHSessionDeadError(DTSError):
    """The SSH session is no longer alive."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.SSH_ERR
    _host: str

    def __init__(self, host: str):
        """Define the meaning of the first argument.

        Args:
            host: The hostname of the disconnected node.
        """
        self._host = host

    def __str__(self) -> str:
        """Add some context to the string representation."""
        return f"SSH session with {self._host} has died."


class ConfigurationError(DTSError):
    """An invalid configuration."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.CONFIG_ERR


class RemoteCommandExecutionError(DTSError):
    """An unsuccessful execution of a remote command."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.REMOTE_CMD_EXEC_ERR
    #: The executed command.
    command: str
    _command_return_code: int

    def __init__(self, command: str, command_return_code: int):
        """Define the meaning of the first two arguments.

        Args:
            command: The executed command.
            command_return_code: The return code of the executed command.
        """
        self.command = command
        self._command_return_code = command_return_code

    def __str__(self) -> str:
        """Include both the command and return code in the string representation."""
        return f"Command {self.command} returned a non-zero exit code: {self._command_return_code}"


class InteractiveCommandExecutionError(DTSError):
    """An unsuccessful execution of a remote command in an interactive environment."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.REMOTE_CMD_EXEC_ERR


class RemoteDirectoryExistsError(DTSError):
    """A directory that exists on a remote node."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.REMOTE_CMD_EXEC_ERR


class DPDKBuildError(DTSError):
    """A DPDK build failure."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.DPDK_BUILD_ERR


class TestCaseVerifyError(DTSError):
    """A test case failure."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.TESTCASE_VERIFY_ERR


class BlockingTestSuiteError(DTSError):
    """A failure in a blocking test suite."""

    #:
    severity: ClassVar[ErrorSeverity] = ErrorSeverity.BLOCKING_TESTSUITE_ERR
    _suite_name: str

    def __init__(self, suite_name: str) -> None:
        """Define the meaning of the first argument.

        Args:
            suite_name: The blocking test suite.
        """
        self._suite_name = suite_name

    def __str__(self) -> str:
        """Add some context to the string representation."""
        return f"Blocking suite {self._suite_name} failed."
