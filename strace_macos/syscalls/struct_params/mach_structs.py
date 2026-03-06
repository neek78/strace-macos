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
    StructArg,
    UnsignedArg,
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
        ("denom", ctypes.c_uint32),  # uint32_t
    ]


class MachTimebaseInfoParam(StructParamBase):
    """Parameter decoder for struct mach_timebase_info."""

    struct_type = MachTimebaseInfoStruct
    excluded_fields: ClassVar[set[str]] = set()
    field_formatters: ClassVar[dict[str, str]] = {}

    def __init__(self, direction : ParamDirection) -> None:
        self.direction = direction

#   MACH_MSG2_SHIFT_ARGS(header.msgh_bits, send_size),
#   MACH_MSG2_SHIFT_ARGS(header.msgh_remote_port, header.msgh_local_port),
#   MACH_MSG2_SHIFT_ARGS(header.msgh_voucher_port, header.msgh_id),
#   MACH_MSG2_SHIFT_ARGS(descriptors, rcv_name),
#   MACH_MSG2_SHIFT_ARGS(rcv_size, priority), timeout);

@dataclass
class MachMsg2Param(Param):
    """Decode the parameters to mach_msg2()"""
    def decode(self, ctx: DecodeContext) -> SyscallArg | None:

        def split(val):
            hi = (val >> 32) & 0xffffffff
            lo = val & 0xffffffff
            return hi, lo

        header_msgh_bits, send_size = split(ctx.all_args[2])
        header_msgh_remote_port, header_msgh_local_port = split(ctx.all_args[3])
        header_msgh_voucher_port, header_msgh_id = split(ctx.all_args[4])
        descriptors, rcv_name = split(ctx.all_args[5])
        rcv_size, priority = split(ctx.all_args[6])
        timeout = ctx.all_args[7]

        header = StructArg({
            "msgh_bits": header_msgh_bits,
            #"msgh_size": 
            "msgh_remote_port":header_msgh_remote_port, 
            "msgh_local_port":header_msgh_local_port, 
            "msgh_voucher_port": header_msgh_voucher_port,
            "msgh_id":header_msgh_id  
        })

        return [
            header, 
            UnsignedArg(send_size), 
            UnsignedArg(rcv_size), 
            UnsignedArg(rcv_name), 
            UnsignedArg(timeout), 
            UnsignedArg(priority)
        ]

    def raw_params_consumed(self) -> int:
        # we consume the latter 6 (of 8) parameters
        return 6

__all__ = [
    "MachTimebaseInfoParam",
    "MachMsg2Param"
]
