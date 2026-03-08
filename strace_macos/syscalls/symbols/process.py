"""Process-related constants and decoders for macOS/Darwin."""

from __future__ import annotations

# wait4/waitpid options
WAIT_OPTIONS: dict[int, str] = {
    0x00000001: "WNOHANG",
    0x00000002: "WUNTRACED",
    0x00000010: "WCONTINUED",
}

# waitid idtype constants
IDTYPE_CONSTANTS: dict[int, str] = {
    0: "P_ALL",
    1: "P_PID",
    2: "P_PGID",
}

# waitid options (WEXITED, WSTOPPED, etc.)
WAITID_OPTIONS: dict[int, str] = {
    0x00000004: "WEXITED",
    0x00000008: "WSTOPPED",
    0x00000010: "WCONTINUED",
    0x00000020: "WNOWAIT",
}

# getpriority/setpriority which constants
PRIO_WHICH: dict[int, str] = {
    0: "PRIO_PROCESS",  # Standard POSIX
    1: "PRIO_PGRP",  # Standard POSIX
    2: "PRIO_USER",  # Standard POSIX
    3: "PRIO_DARWIN_THREAD",
    4: "PRIO_DARWIN_PROCESS",
    0x1000: "PRIO_DARWIN_BG",
    0x1001: "PRIO_DARWIN_NONUI",
}

# getrusage who constants
RUSAGE_WHO: dict[int, str] = {
    -1: "RUSAGE_CHILDREN",
    0: "RUSAGE_SELF",
}

# Resource limit constants for getrlimit/setrlimit
RLIMIT_RESOURCES: dict[int, str] = {
    0: "RLIMIT_CPU",
    1: "RLIMIT_FSIZE",
    2: "RLIMIT_DATA",
    3: "RLIMIT_STACK",
    4: "RLIMIT_CORE",
    5: "RLIMIT_AS",  # Also RLIMIT_RSS
    6: "RLIMIT_MEMLOCK",
    7: "RLIMIT_NPROC",
    8: "RLIMIT_NOFILE",
}

# sigprocmask how constants
SIG_HOW: dict[int, str] = {
    1: "SIG_BLOCK",
    2: "SIG_UNBLOCK",
    3: "SIG_SETMASK",
}

# reboot() flags
REBOOT_FLAGS: dict[int, str] = {
    0x00: "RB_AUTOBOOT",
    0x01: "RB_ASKNAME",
    0x02: "RB_SINGLE",
    0x04: "RB_NOSYNC",
    0x08: "RB_HALT",
    0x10: "RB_INITNAME",
    0x20: "RB_DFLTROOT",
    0x40: "RB_ALTBOOT",
    0x80: "RB_UNIPROC",
    0x100: "RB_SAFEBOOT",
    0x200: "RB_UPSDELAY",
    0x400: "RB_QUICK",
    0x800: "RB_PANIC",
    0x1000: "RB_PANIC_ZPRINT",
    0x2000: "RB_PANIC_FORCERESET",
}

# __proc_info() call numbers
PROC_INFO_CALLNUM: dict[int, str] = {
    # from proc_info.h
    0x1: "PROC_INFO_CALL_LISTPIDS",
    0x2: "PROC_INFO_CALL_PIDINFO",
    0x3: "PROC_INFO_CALL_PIDFDINFO",
    0x4: "PROC_INFO_CALL_KERNMSGBUF",
    0x5: "PROC_INFO_CALL_SETCONTROL",
    0x6: "PROC_INFO_CALL_PIDFILEPORTINFO",
    0x7: "PROC_INFO_CALL_TERMINATE",
    0x8: "PROC_INFO_CALL_DIRTYCONTROL",
    0x9: "PROC_INFO_CALL_PIDRUSAGE",
    0xa: "PROC_INFO_CALL_PIDORIGINATORINFO",
    0xb: "PROC_INFO_CALL_LISTCOALITIONS",
    0xc: "PROC_INFO_CALL_CANUSEFGHW",
    0xd: "PROC_INFO_CALL_PIDDYNKQUEUEINFO",
    0xe: "PROC_INFO_CALL_UDATA_INFO",
    0xf: "PROC_INFO_CALL_SET_DYLD_IMAGES",
    0x10: "PROC_INFO_CALL_TERMINATE_RSR",
    0x11: "PROC_INFO_CALL_SIGNAL_AUDITTOKEN",
    0x12: "PROC_INFO_CALL_TERMINATE_AUDITTOKEN",
    0x13: "PROC_INFO_CALL_DELEGATE_SIGNAL",
    0x14: "PROC_INFO_CALL_DELEGATE_TERMINATE",
    # ... from proc_info_private.h
    0x17: "PROC_PIDUNIQIDENTIFIERINFO",
    0x18: "PROC_PIDT_BSDINFOWITHUNIQID",
    0x19: "PROC_PIDARCHINFO",
    0x20: "PROC_PIDCOALITIONINFO",
    0x21: "PROC_PIDNOTEEXIT",
    0x22: "PROC_PIDREGIONPATHINFO2",
    0x23: "PROC_PIDREGIONPATHINFO3",
    0x24: "PROC_PIDEXITREASONINFO",
    0x25: "PROC_PIDEXITREASONBASICINFO",
    0x26: "PROC_PIDLISTUPTRS",
    0x27: "PROC_PIDLISTDYNKQUEUES",
    0x28: "PROC_PIDLISTTHREADIDS",
    0x29: "PROC_PIDVMRTFAULTINFO",
    0x30: "PROC_PIDPLATFORMINFO",
    0x31: "PROC_PIDREGIONPATH",
    0x32: "PROC_PIDIPCTABLEINFO",
    0x33: "PROC_PIDTHREADSCHEDINFO",
}

# __proc_info(): map the callnum (see above) to the set of values for the flavor param
PROC_INFO_FLAVOR : dict[int, dict[int, str]] = {
    0x2: {
        # Flavors for proc_pidinfo() from proc_info.h
        1: "PROC_PIDLISTFDS",
        2: "PROC_PIDTASKALLINFO",
        3: "PROC_PIDTBSDINFO",
        4: "PROC_PIDTASKINFO",
        5: "PROC_PIDTHREADINFO",
        6: "PROC_PIDLISTTHREADS",
        7: "PROC_PIDREGIONINFO",
        8: "PROC_PIDREGIONPATHINFO",
        9: "PROC_PIDVNODEPATHINFO",
        10: "PROC_PIDTHREADPATHINFO",
        11: "PROC_PIDPATHINFO",
        12: "PROC_PIDWORKQUEUEINFO",
        13: "PROC_PIDT_SHORTBSDINFO",
        14: "PROC_PIDLISTFILEPORTS",
        15: "PROC_PIDTHREADID64INFO",
        16: "PROC_PID_RUSAGE",

        # ... from proc_info_private.h
        17: "PROC_PIDUNIQIDENTIFIERINFO",
        18: "PROC_PIDT_BSDINFOWITHUNIQID",
        19: "PROC_PIDARCHINFO",
        20: "PROC_PIDCOALITIONINFO",
        21: "PROC_PIDNOTEEXIT",
        22: "PROC_PIDREGIONPATHINFO2",
        23: "PROC_PIDREGIONPATHINFO3",
        24: "PROC_PIDEXITREASONINFO",
        25: "PROC_PIDEXITREASONBASICINFO",
        26: "PROC_PIDLISTUPTRS",
        27: "PROC_PIDLISTDYNKQUEUES",
        28: "PROC_PIDLISTTHREADIDS",
        29: "PROC_PIDVMRTFAULTINFO",
        30: "PROC_PIDPLATFORMINFO",
        31: "PROC_PIDREGIONPATH",
        32: "PROC_PIDIPCTABLEINFO",
        33: "PROC_PIDTHREADSCHEDINFO",
        34: "PROC_PIDTHREADCOUNTS",
    },
    0x3: {
        # Flavors for proc_pidfdinfo from proc_info.h
        1: "PROC_PIDFDVNODEINFO",
        2: "PROC_PIDFDVNODEPATHINFO",
        3: "PROC_PIDFDSOCKETINFO",
        4: "PROC_PIDFDPSEMINFO",
        5: "PROC_PIDFDPSHMINFO",
        6: "PROC_PIDFDPIPEINFO",
        7: "PROC_PIDFDKQUEUEINFO",
        8: "PROC_PIDFDATALKINFO",
        10: "PROC_PIDFDCHANNELINFO",
    },
    0x6: {
        # Flavors for proc_pidfileportinfo from proc_info.h
        2: "PROC_PIDFILEPORTVNODEPATHINFO",
        3: "PROC_PIDFILEPORTSOCKETINFO",
        5: "PROC_PIDFILEPORTPSHMINFO",
        6: "PROC_PIDFILEPORTPIPEINFO",
    },
    0x8: {
        # used for proc_dirtycontrol from proc_info.h
        1: "PROC_DIRTYCONTROL_TRACK",
        2: "PROC_DIRTYCONTROL_SET",
        3: "PROC_DIRTYCONTROL_GET",
        4: "PROC_DIRTYCONTROL_CLEAR",
    },
    0xe: {
        # Flavors for proc_udata_info
        1: "PROC_UDATA_INFO_GET",
        2: "PROC_UDATA_INFO_SET",
    }
}

# 
# 
# used for proc_setcontrol
# PROC_SELFSET_PCONTROL           1
# PROC_SELFSET_THREADNAME         2
# PROC_SELFSET_VMRSRCOWNER        3
# PROC_SELFSET_DELAYIDLESLEEP     4
# 
# /* proc_track_dirty() flags */
# PROC_DIRTY_TRACK                0x1
# PROC_DIRTY_ALLOW_IDLE_EXIT      0x2
# PROC_DIRTY_DEFER                0x4
# PROC_DIRTY_LAUNCH_IN_PROGRESS   0x8
# PROC_DIRTY_DEFER_ALWAYS         0x10
# PROC_DIRTY_SHUTDOWN_ON_CLEAN    0x20
