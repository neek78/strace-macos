from __future__ import annotations

from strace_macos.syscalls import numbers

from strace_macos.syscalls.definitions import (
    BufferParam,
    ConstParam,
    CustomParam,
#    FileDescriptorParam,
    FlagsParam,
    IntParam,
    ParamDirection,
    PointerParam,
    StringParam,
    SyscallDef,
    UnsignedParam,
    MachMsg2Param,
)

from strace_macos.syscalls.struct_params import (
    MachTimebaseInfoParam
)


from strace_macos.syscalls.symbols.mach import (
    MACH_MSG_OPTION_FLAGS,
    MACH_MSG_OPTION64_FLAGS,
)

MACH_TRAPS: list[SyscallDef] = [
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_vm_allocate_trap,
        "_kernelrpc_mach_vm_allocate",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_vm_purgable_control_trap,
        "_kernelrpc_mach_vm_purgable_control",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_vm_deallocate_trap,
        "_kernelrpc_mach_vm_deallocate",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_task_dyld_process_info_notify_get_trap,
        "task_dyld_process_info_notify_get",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_vm_protect_trap,
        "_kernelrpc_mach_vm_protect",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_vm_map_trap, "_kernelrpc_mach_vm_map", params=()
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_allocate_trap,
        "_kernelrpc_mach_port_allocate",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_deallocate_trap,
        "_kernelrpc_mach_port_deallocate",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_mod_refs_trap,
        "_kernelrpc_mach_port_mod_refs",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_move_member_trap,
        "_kernelrpc_mach_port_move_member",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_insert_right_trap,
        "_kernelrpc_mach_port_insert_right",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_insert_member_trap,
        "_kernelrpc_mach_port_insert_member",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_extract_member_trap,
        "_kernelrpc_mach_port_extract_member",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_construct_trap,
        "_kernelrpc_mach_port_construct",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_kernelrpc_mach_port_destruct_trap,
        "_kernelrpc_mach_port_destruct",
        params=[],
    ),
    SyscallDef(numbers.TRAP_mach_reply_port, "mach_reply_port", params=[]),  # no params
    SyscallDef(numbers.TRAP_thread_self_trap, "thread_self_trap", params=[]),
    SyscallDef(numbers.TRAP_task_self_trap, "task_self_trap", params=[]),  # no params
    SyscallDef(numbers.TRAP_host_self_trap, "host_self_trap", params=[]),  # no params
    SyscallDef(numbers.TRAP_mach_msg_trap, "mach_msg_trap", params=[]),
    SyscallDef(
        numbers.TRAP_mach_msg_overwrite_trap, "mach_msg_overwrite_trap", params=[]
    ),
    SyscallDef(numbers.TRAP_semaphore_signal_trap, "semaphore_signal_trap", params=[]),
    SyscallDef(
        numbers.TRAP_semaphore_signal_all_trap, "semaphore_signal_all_trap", params=[]
    ),
    SyscallDef(
        numbers.TRAP_semaphore_signal_thread_trap,
        "semaphore_signal_thread_trap",
        params=[],
    ),
    SyscallDef(numbers.TRAP_semaphore_wait_trap, "semaphore_wait_trap", params=[]),
    SyscallDef(
        numbers.TRAP_semaphore_wait_signal_trap, "semaphore_wait_signal_trap", params=[]
    ),
    SyscallDef(
        numbers.TRAP_semaphore_timedwait_trap, "semaphore_timedwait_trap", params=[]
    ),
    SyscallDef(
        numbers.TRAP_semaphore_timedwait_signal_trap,
        "semaphore_timedwait_signal_trap",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP__kernelrpc_mach_port_get_attributes_trap,
        "_kernelrpc_mach_port_get_attributes_trap",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP__kernelrpc_mach_port_guard_trap,
        "_kernelrpc_mach_port_guard_trap",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP__kernelrpc_mach_port_unguard_trap,
        "_kernelrpc_mach_port_unguard_trap",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP_mach_generate_activity_id, "mach_generate_activity_id", params=[]
    ),
    SyscallDef(numbers.TRAP_task_name_for_pid, "task_name_for_pid", params=[]),
    SyscallDef(numbers.TRAP_task_for_pid, "task_for_pid", params=[]),
    SyscallDef(numbers.TRAP_pid_for_task, "pid_for_task", params=[]),

    SyscallDef(
        numbers.TRAP_mach_msg2_trap,
        "mach_msg2_trap",
        params=[
            PointerParam(),  # void *data,
            FlagsParam(
                MACH_MSG_OPTION64_FLAGS
            ),  # mach_msg_option64_t options - osfmk/mach/message.h:1044
            MachMsg2Param()
        ],
        display_name = "mach_msg2"
    ),
    SyscallDef(numbers.TRAP_macx_swapon, "macx_swapon", params=()),
    SyscallDef(numbers.TRAP_macx_swapoff, "macx_swapoff", params=()),
    SyscallDef(
        numbers.TRAP_thread_get_special_reply_port,
        "thread_get_special_reply_port",
        params=[],  # no params
    ),
    SyscallDef(numbers.TRAP_macx_triggers, "macx_triggers", params=()),
    SyscallDef(
        numbers.TRAP_macx_backing_store_suspend, "macx_backing_store_suspend", params=[]
    ),
    SyscallDef(
        numbers.TRAP_macx_backing_store_recovery,
        "macx_backing_store_recovery",
        params=[],
    ),
    SyscallDef(numbers.TRAP_swtch_pri, "swtch_pri", params=[]),
    SyscallDef(numbers.TRAP_swtch, "swtch", params=[]),
    SyscallDef(numbers.TRAP_thread_switch, "thread_switch", params=[]),
    SyscallDef(numbers.TRAP_clock_sleep_trap, "clock_sleep_trap", params=[]),

    SyscallDef(
        numbers.TRAP_host_create_mach_voucher_trap,
        "host_create_mach_voucher",
        params=[
            UnsignedParam(),
            PointerParam(), # recipes - FIXME: what does this actually point at?
            UnsignedParam(), # recipesCnt
            PointerParam(), # voucher
        ],
    ),
    SyscallDef(
        numbers.TRAP_mach_voucher_extract_attr_recipe_trap,
        "mach_voucher_extract_attr_recipe_trap",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP__kernelrpc_mach_port_type_trap,
        "_kernelrpc_mach_port_type_trap",
        params=[],
    ),
    SyscallDef(
        numbers.TRAP__kernelrpc_mach_port_request_notification_trap,
        "_kernelrpc_mach_port_request_notification_trap",
        params=[],
    ),
    SyscallDef(numbers.TRAP__exclaves_ctl_trap, "_exclaves_ctl_trap", params=[]),
    SyscallDef(
        numbers.TRAP_mach_timebase_info_trap, "mach_timebase_info", params=[
            MachTimebaseInfoParam(ParamDirection.OUT),
        ]
    ),
    SyscallDef(numbers.TRAP_mach_wait_until_trap, "mach_wait_until", params=[]),
    SyscallDef(numbers.TRAP_mk_timer_create_trap, "mk_timer_create", params=[]),
    SyscallDef(numbers.TRAP_mk_timer_destroy_trap, "mk_timer_destroy", params=[]),
    SyscallDef(numbers.TRAP_mk_timer_arm_trap, "mk_timer_arm", params=[]),
    SyscallDef(numbers.TRAP_mk_timer_cancel_trap, "mk_timer_cancel", params=[]),
    SyscallDef(
        numbers.TRAP_mk_timer_arm_leeway_trap, "mk_timer_arm_leeway", params=[]
    ),
    SyscallDef(
        numbers.TRAP_debug_control_port_for_pid, "debug_control_port_for_pid", params=[]
    ),
]
