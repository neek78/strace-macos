
from __future__ import annotations

from strace_macos.syscalls import numbers

from strace_macos.syscalls.definitions import (
    BufferParam,
    ConstParam,
    CustomParam,
    DirFdParam,
    FileDescriptorParam,
    FlagsParam,
    FlockOpParam,
    IntParam,
    OctalParam,
    ParamDirection,
    PointerParam,
    StringParam,
    SyscallDef,
    UidGidParam,
    UnsignedParam,
    VariantParam,
)

from strace_macos.syscalls.struct_params import (
    AttrListParam,
    FssearchblockParam,
    IntPtrParam,
    IovecParam,
    StatfsParam,
    StatParam,
    TermiosParam,
    WinsizeParam,
)

MACH_TRAPS: list[SyscallDef] = [
    SyscallDef(numbers.SYS_link, "link", params=()),  
]
