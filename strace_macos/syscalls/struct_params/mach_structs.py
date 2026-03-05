"""Struct parameter decoders for mach trap structures."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any, ClassVar

from strace_macos.syscalls.args import PointerArg, StringArg, StructArrayArg

from strace_macos.syscalls.definitions import (
    DecodeContext,
    Param,
    ParamDirection,
    StructParamBase,
    SyscallArg,
)

class MachTimebaseInfoStruct(ctypes.Structure):
    """ctypes definition for struct mach_timebase_info.

    struct mach_timebase_info {
        uint32_t        numer;
        uint32_t        denom;
    };
    """

    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("numer", ctypes.c_uint32),  # uint32_t
        ("denom", ctypes.c_uint32),  # suint32_t
    ]


class MachTimebaseInfoParam(StructParamBase):
    """Parameter decoder for struct mach_timebase_info."""

    struct_type = MachTimebaseInfoStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self, direction : ParamDirection) -> None:
        self.direction = direction

__all__ = [
    "MachTimebaseInfoParam",
]
