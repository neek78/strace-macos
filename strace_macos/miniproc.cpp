
#define Py_LIMITED_API 0x030d80000
#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

#include <libproc.h>

struct ModuleState {
    PyObject* ipaddr_mod;
    PyObject* ipv4_ctor;
    PyObject* ipv6_ctor;
    PyObject* enum_mod;
    PyObject* enum_ctor;

    void print() {
        printf("    %p:  %p %p %p %p %p\n",
        this,
        ipaddr_mod,
        ipv4_ctor,
        ipv6_ctor,
        enum_mod,
        enum_ctor);
    }

    void clear() {
        Py_XDECREF(ipaddr_mod);
        Py_XDECREF(ipv4_ctor);
        Py_XDECREF(ipv6_ctor);
        Py_XDECREF(enum_mod);
        Py_XDECREF(enum_ctor);
    }

private:
    ModuleState(ModuleState&);
};

ModuleState& get_module_state(PyObject* module)
{
    assert(module);
    void* state = PyModule_GetState(module);
    //printf("get_module_state mod=%p state=%p\n", module, state);
    assert(state != NULL);

    //ModuleState* s = (ModuleState*)state;
    //assert(s->ipv4_ctor);
    return *(ModuleState*)state;
}
#if 0
ModuleState& get_module_state_from_self(PyObject* self)
{
    printf("get_module_state_from_Self selfmod=%p \n", self);
    assert(self);
    PyTypeObject* type = Py_TYPE(self);
    assert(type);
    PyObject* module = PyType_GetModule(type);
    return get_module_state(module);
}

#endif
PyObject* extract_address(ModuleState& state, const in4in6_addr& addr, bool ipv4)
{
    //printf("extract addr\n");
    //state.print();
    assert(state.ipv4_ctor);
    assert(state.ipv6_ctor);

    PyObject* out = PyDict_New();
    if(out == NULL) {
        return NULL;
    }

    PyObject* py_addr = NULL;
    if (ipv4) {
        //py_addr = PyLong_FromLong(ntohl(addr.i46a_addr4.s_addr));
        uint32_t a = ntohl(addr.i46a_addr4.s_addr);
        //PyObject* args = Py_BuildValue("(i)", a);

        PyObject* b = PyLong_FromLong(a);
        PyObject* args = PyTuple_Pack(1, b);
        assert(args);
        py_addr = PyObject_Call(state.ipv4_ctor, args, NULL);
    } else {
    // FIXME: byte order
        printf("IP6\n");
        py_addr = PyUnicode_FromString("Nuh-Uh IP6");
    }
    //printf("addr %p\n", py_addr);
    PyDict_SetItemString(out, "address", py_addr);

    return out;
}

PyObject* handle_socket_addr(ModuleState& state, const socket_fdinfo& si)
{
    PyObject* out = PyDict_New();
    if(out == NULL) {
        return NULL;
    }

    int family = si.psi.soi_family;
    assert(family == AF_INET || family == AF_INET6);
    bool ipv4 = family == AF_INET;

    if (si.psi.soi_kind == SOCKINFO_TCP) {
        // tcp socket
        PyDict_SetItemString(out, "kind", PyUnicode_FromString("tcp"));
        PyObject* local_addr = extract_address(state,
                si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46, ipv4);

        PyObject* remote_addr = extract_address(state,
                si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46, ipv4);
    
        PyDict_SetItemString(out, "local_addr", local_addr);
        PyDict_SetItemString(out, "remote_addr", remote_addr);

        long local_port = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
        long remote_port = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

        PyDict_SetItemString(out, "local_port", PyLong_FromLong(local_port));
        PyDict_SetItemString(out, "remote_port", PyLong_FromLong(remote_port));
    } else {
        // non-tcp socket
        PyObject* local_addr = extract_address(state,
                si.psi.soi_proto.pri_in.insi_laddr.ina_46, ipv4);

        PyObject* remote_addr = extract_address(state,
                si.psi.soi_proto.pri_in.insi_faddr.ina_46, ipv4);
    
        PyDict_SetItemString(out, "local_addr", local_addr);
        PyDict_SetItemString(out, "remote_addr", remote_addr);

        long local_port = ntohs(si.psi.soi_proto.pri_in.insi_lport);
        long remote_port = ntohs(si.psi.soi_proto.pri_in.insi_fport);

        PyDict_SetItemString(out, "local_port", PyLong_FromLong(local_port));
        PyDict_SetItemString(out, "remote_port", PyLong_FromLong(remote_port));

#if 0
        /*
         * Enter information for a non-TCP socket.
         */
        lp = (int)ntohs(si.psi.soi_proto.pri_in.insi_lport);
        fa = (unsigned char *)&si.psi.soi_proto.pri_in.insi_faddr.ina_46.i46a_addr4;
#endif
    }
#if 0
    if ((fa && (*fa == INADDR_ANY)) && !fp) {
        fa = (unsigned char *)NULL;
        fp = 0;
    }
#endif
    return out;
}


static void handle_socket(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    socket_fdinfo si;
    int size = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
                "proc_pidfdinfo PROC_PIDFDSOCKETINFO failed, errno %d", errno);
        return;
    }

    PyObject* st= PyLong_FromLong(si.psi.soi_state);
    PyDict_SetItemString(out, "state", st);

    PyObject* details = NULL;
    switch ((si.psi.soi_family)) {
    case AF_INET:
    case AF_INET6:
        if ((si.psi.soi_kind != SOCKINFO_IN) && (si.psi.soi_kind != SOCKINFO_TCP)) {
            break;
        }
        details = handle_socket_addr(state, si);
    };

    if(details != NULL)
        PyDict_SetItemString(out, "yep", details);
}

static void handle_vnode(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    vnode_fdinfowithpath vi;

    size_t size = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
                "proc_pidfdinfo PROC_PIDFDVNODEPATHINFO failed, errno %d", errno);
        return;
        // if (errno == ENOENT) {
       //  } 
    } else if (size < sizeof(vi)) {
    }

    PyObject* value = PyUnicode_FromString(vi.pvip.vip_path);
    PyDict_SetItemString(out, "path", value);
}

static PyObject* get_fd_info(PyObject* self, PyObject *args)  
{
    int fd = -1;
    pid_t pid;
    if (!PyArg_ParseTuple(args, _Py_PARSE_PID _Py_PARSE_INTPTR, &pid, &fd))
        return NULL;

    // FIXME: heap alloc
    proc_fdinfo buffer[1024];

    int n = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &buffer, sizeof(buffer));
    if (n <= 0) {
        PyErr_Format(PyExc_RuntimeError, "proc_pidinfo failed, errno %d", errno);
    }
    int count = n / sizeof(struct proc_fdinfo);

    bool found = false;
    uint32_t kind = 0;

    // search for fd in returned set
    for (int i = 0; i < count; i++) {
        if (buffer[i].proc_fd == fd) {
            kind = buffer[i].proc_fdtype;
            found = true;
            break;
        }
    }

    if (!found) {
        PyErr_Format(PyExc_RuntimeError, "couldn't find fd %d", fd);
        return NULL;
    }

    auto& state = get_module_state(self);
    PyObject* out = PyDict_New();

    printf("kind %d\n", kind);
    switch(kind) {
        case PROX_FDTYPE_VNODE:
            handle_vnode(state, pid, fd, out);
            break;
        case PROX_FDTYPE_SOCKET:
            handle_socket(state, pid, fd, out);
            break;
    };
    //switch ((int)(vip->vip_vi.vi_stat.vst_mode & S_IFMT)) {

    return out;
}


static int miniproc_exec(PyObject *module) 
{
    printf("miniproc_exec mod=%p state=%p\n", module, PyModule_GetState(module));

    ModuleState& state = get_module_state(module);

    // note that even in the case of error return, miniproc_free() is still
    // called, which will clean up. We just have to leave the state
    // sane enough for it to work. Python guarantees the state to be zeroed
    // (PEP 3121) so don't have to worry about garbage getting in.
    state.ipaddr_mod = PyImport_ImportModule("ipaddress");
    if (state.ipaddr_mod == NULL) {
        return -1;
    }

    state.ipv4_ctor = PyObject_GetAttrString(state.ipaddr_mod, "IPv4Address");
    state.ipv6_ctor = PyObject_GetAttrString(state.ipaddr_mod, "IPv6Address");
    if (state.ipv4_ctor == NULL || state.ipv4_ctor == NULL) {
        return -1;
    }

    assert(state.ipv4_ctor);
    assert(state.ipv6_ctor);

    state.enum_mod = PyImport_ImportModule("enum");
    if (state.enum_mod == NULL) {
        return -1;
    }

    state.enum_ctor = PyObject_GetAttrString(state.enum_mod, "Enum");
    //printf("exec done\n");
    //state.print();

    assert(state.ipv4_ctor);
    assert(state.ipv6_ctor);

    return 0;
}

//typedef int (*inquiry)(PyObject *);
static int miniproc_clear(PyObject* module) {
    //printf("miniproc clear mod=%p\n", module);
    ModuleState& state = get_module_state(module);
    //state.print();
    state.clear();
    return 0;
}

static PyMethodDef miniproc_methods[] = {
    {"get_fd_info", (PyCFunction) get_fd_info, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL} 
};

static PyModuleDef_Slot miniproc_slots[] = {
    {Py_mod_exec, (void*)miniproc_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static PyModuleDef miniproc_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "miniproc",
    .m_doc  = "docstring FIXME",
    .m_size = sizeof(ModuleState), 
    .m_methods = miniproc_methods,
    .m_slots = miniproc_slots,
    .m_clear = miniproc_clear,
    //.m_free = miniproc_free,
};

PyMODINIT_FUNC PyInit_miniproc(void) {
    return PyModuleDef_Init(&miniproc_module);
}

