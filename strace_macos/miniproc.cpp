
#define Py_LIMITED_API 0x030d80000
#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

#include <libproc.h>

struct ModuleState {
    PyObject* ipv4_ctor;
    PyObject* ipv6_ctor;

    PyObject* fd_type_enums;

    int clear() {
        Py_XDECREF(ipv4_ctor);
        Py_XDECREF(ipv6_ctor);

        Py_XDECREF(fd_type_enums);

        return 0;
    }

    int traverse(visitproc visit, void *arg) {
        Py_VISIT(ipv4_ctor);
        Py_VISIT(ipv6_ctor);

        Py_VISIT(fd_type_enums);

        return 0;
    }

private:
    ModuleState(ModuleState&);
};

ModuleState& get_module_state(PyObject* module)
{
    assert(module);
    void* state = PyModule_GetState(module);
    assert(state != NULL);
    return *(ModuleState*)state;
}

static int add_enum_value(PyObject* attrs, const char* name, int value) {
    PyObject* py_key = PyUnicode_FromString(name);
    PyObject* py_val = PyLong_FromLong(value);

    int ret = -1;
    if (py_key != NULL && py_val != NULL) {
        ret = 0;
        PyObject_SetItem(attrs, py_key, py_val);
    }

    Py_XDECREF(py_key);
    Py_XDECREF(py_val);
    return ret;
}

static PyObject* make_reverse_enum(PyObject* this_enum_type, PyObject* values, int max_enum_value)
{
    PyObject* key = NULL;
    PyObject* value = NULL;
    Py_ssize_t pos = 0;

    PyObject* ret = PyList_New(max_enum_value + 1);
    if (ret == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to alloc enum reverse list"); 
        return NULL;
    }

    while (PyDict_Next(values, &pos, &key, &value)) {
        long idx = PyLong_AsLong(value);
        PyObject* e = PyObject_GetAttr(this_enum_type, key);
        // FIXME: check item's not already set
        // FIXME: check error return
        PyList_SetItem(ret, idx, e);
    }
    return ret;
}

static PyObject* create_enum(PyObject* module, const char* enum_name, 
        PyObject* values, int max_enum_value)
{
    PyObject* ret = NULL;
    PyObject* name = NULL, *args = NULL, *enum_mod = NULL;
    PyObject* enum_type = NULL, *this_enum_type = NULL;

    name = PyUnicode_FromString(enum_name);
    args = PyTuple_Pack(2, name, values);
    enum_mod = PyImport_ImportModule("enum");

    if (name == NULL || args == NULL || enum_mod == NULL) {
        goto out;
    }

    enum_type = PyObject_GetAttrString(enum_mod, "Enum");
    if (enum_type == NULL) {
        goto out;
    }
    
    this_enum_type = PyObject_Call(enum_type, args, NULL);
    if (this_enum_type == NULL) {
        goto out;
    }

    // Ok, enum is built.. thwack it in the module.
    if (PyObject_SetAttr(module, name, this_enum_type) < 0) {
        goto out;
    }

    // now we've created the "forward enum", create a reverse one 
    // i.e. mapping into to enum value
    ret = make_reverse_enum(this_enum_type, values, max_enum_value);
    
out:
    Py_XDECREF(name);
    Py_XDECREF(args);
    Py_XDECREF(enum_mod);
    Py_XDECREF(enum_type);
    Py_XDECREF(this_enum_type);
    return ret;
}

static PyObject* get_enum_value(PyObject* enum_list, int idx) {
    return PyList_GetItem(enum_list, idx);
}

static int build_enum_fd_type(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for enum fd_type");
        return -1;
    }

    add_enum_value(attrs, "ATALK", PROX_FDTYPE_ATALK);
    add_enum_value(attrs, "VNODE", PROX_FDTYPE_VNODE);
    add_enum_value(attrs, "SOCKET", PROX_FDTYPE_SOCKET);
    add_enum_value(attrs, "PSHM", PROX_FDTYPE_PSHM);
    add_enum_value(attrs, "PSEM", PROX_FDTYPE_PSEM);
    add_enum_value(attrs, "KQUEUE", PROX_FDTYPE_KQUEUE);
    add_enum_value(attrs, "PIPE", PROX_FDTYPE_PIPE);
    add_enum_value(attrs, "FSEVENTS", PROX_FDTYPE_FSEVENTS);
    add_enum_value(attrs, "NETPOLICY", PROX_FDTYPE_NETPOLICY);
    add_enum_value(attrs, "CHANNEL", PROX_FDTYPE_CHANNEL);
    add_enum_value(attrs, "NEXUS", PROX_FDTYPE_NEXUS);

    struct ModuleState& state = get_module_state(module);

    PyObject* reverse = create_enum(module, "FDType", attrs, PROX_FDTYPE_NEXUS);
    state.fd_type_enums = reverse;

    Py_DECREF(attrs);
    return reverse == NULL ? -1 : 0;
};

static PyObject* get_fd_type(ModuleState& state, int fd_type) {
    return get_enum_value(state.fd_type_enums, fd_type);
}

static int build_enums(PyObject* module) 
{
    if (build_enum_fd_type(module) < 0) {
        return -1;
    }
    return 0;
}

PyObject* extract_ipv4_address(ModuleState& state, const in4in6_addr& addr)
{
    assert(state.ipv4_ctor);

    uint32_t a = ntohl(addr.i46a_addr4.s_addr);

    PyObject* b = PyLong_FromLong(a);
    PyObject* args = PyTuple_Pack(1, b);
    PyObject* py_addr = PyObject_Call(state.ipv4_ctor, args, NULL);

    // FIXME: catch errors
    return py_addr;
}

PyObject* extract_ipv6_address(ModuleState& state, const in6_addr& addr)
{
    assert(state.ipv6_ctor);

    // FIXME: byte order ?
    PyObject* array = PyBytes_FromStringAndSize((const char*)addr.__u6_addr.__u6_addr8, 16);
    PyObject* args = PyTuple_Pack(1, array);

    PyObject* py_addr = PyObject_Call(state.ipv6_ctor, args, NULL);

    // FIXME: catch errors
    return py_addr;
}

int handle_tcp_socket(ModuleState& state, const socket_fdinfo& si, PyObject* out) 
{
    int family = si.psi.soi_family;
    const bool is_ipv4 = family == AF_INET;

    PyDict_SetItemString(out, "kind", PyUnicode_FromString("tcp"));
    PyObject* local_addr = is_ipv4 ? 
        extract_ipv4_address(state, si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46) :
        extract_ipv6_address(state, si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6);

    PyObject* remote_addr = is_ipv4 ? 
        extract_ipv4_address(state, si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46) :
        extract_ipv6_address(state, si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6);

    PyDict_SetItemString(out, "local_addr", local_addr);
    PyDict_SetItemString(out, "remote_addr", remote_addr);

    long local_port = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
    long remote_port = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

    PyDict_SetItemString(out, "local_port", PyLong_FromLong(local_port));
    PyDict_SetItemString(out, "remote_port", PyLong_FromLong(remote_port));

    return 0;
}

int handle_in_socket(ModuleState& state, const socket_fdinfo& si, PyObject* out) 
{
    int family = si.psi.soi_family;
    const bool is_ipv4 = family == AF_INET;
    PyObject* local_addr = is_ipv4 ?
        extract_ipv4_address(state, si.psi.soi_proto.pri_in.insi_laddr.ina_46) :
        extract_ipv6_address(state, si.psi.soi_proto.pri_in.insi_laddr.ina_6);

    PyObject* remote_addr = is_ipv4 ?
        extract_ipv4_address(state, si.psi.soi_proto.pri_in.insi_faddr.ina_46) :
        extract_ipv6_address(state, si.psi.soi_proto.pri_in.insi_faddr.ina_6);

    PyDict_SetItemString(out, "local_addr", local_addr);
    PyDict_SetItemString(out, "remote_addr", remote_addr);

    long local_port = ntohs(si.psi.soi_proto.pri_in.insi_lport);
    long remote_port = ntohs(si.psi.soi_proto.pri_in.insi_fport);

    PyDict_SetItemString(out, "local_port", PyLong_FromLong(local_port));
    PyDict_SetItemString(out, "remote_port", PyLong_FromLong(remote_port));
    return 0;
}

PyObject* handle_inet_socket(ModuleState& state, const socket_fdinfo& si)
{
    PyObject* out = PyDict_New();
    if(out == NULL) {
        return NULL;
    }

    int family = si.psi.soi_family;
    assert(family == AF_INET || family == AF_INET6);

    switch(si.psi.soi_kind) {
        case SOCKINFO_TCP: // tcp socket
            handle_tcp_socket(state, si, out);
            break;
        case SOCKINFO_IN: // inet, non-tcp socket
            handle_in_socket(state, si, out);
            break;
        default:
            PyErr_Format(PyExc_RuntimeError, 
                "handle_socket_addr: Unhandled soi_kind %d", si.psi.soi_kind);
            Py_DECREF(out);
            return NULL;
    };

    return out;
}


static int handle_socket(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    socket_fdinfo si;
    int size = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
                "proc_pidfdinfo: PROC_PIDFDSOCKETINFO failed, errno %d", errno);
        return -1;
    }

    PyObject* st = PyLong_FromLong(si.psi.soi_state);

    PyObject* details = NULL;
    switch ((si.psi.soi_family)) {
    case AF_INET:
    case AF_INET6:
        details = handle_inet_socket(state, si);
        break;
    // case AF_UNIX:
    //    break;
    default:
        PyErr_Format(PyExc_RuntimeError, 
                "proc_pidfdinfo: handle_socket unhandled family %d", si.psi.soi_family);
        return -1;
    };

    PyDict_SetItemString(details, "state", st);

    if(details != NULL) {
        PyDict_SetItemString(out, "socket", details);
        return 0;
    } else {
        return -1;
    }
}

static int handle_vnode(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    //switch ((int)(vip->vip_vi.vi_stat.vst_mode & S_IFMT)) {
    vnode_fdinfowithpath vi;

    size_t size = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
                "proc_pidfdinfo PROC_PIDFDVNODEPATHINFO failed, errno %d", errno);
        return -1;
        // if (errno == ENOENT) {
       //  } 
    } else if (size < sizeof(vi)) {
    }

    PyObject* value = PyUnicode_FromString(vi.pvip.vip_path);
    PyDict_SetItemString(out, "path", value);
    return 0;
}

static int handle_pipe(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    return -1;
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
    uint32_t fd_type = 0;

    // search for fd in returned set
    for (int i = 0; i < count; i++) {
        if (buffer[i].proc_fd == fd) {
            fd_type = buffer[i].proc_fdtype;
            found = true;
            break;
        }
    }

    if (!found) {
        PyErr_Format(PyExc_RuntimeError, "couldn't find fd %d", fd);
        return NULL;
    }

    ModuleState& state = get_module_state(self);
    PyObject* out = PyDict_New();

    PyDict_SetItemString(out, "fd", PyLong_FromLong(fd));
    PyDict_SetItemString(out, "fd_type", get_fd_type(state, fd_type));

    int ret = 0;
    switch(fd_type) {
        case PROX_FDTYPE_VNODE:
            ret = handle_vnode(state, pid, fd, out);
            break;
        case PROX_FDTYPE_SOCKET:
            ret = handle_socket(state, pid, fd, out);
            break;
        case PROX_FDTYPE_PIPE:
            ret = handle_pipe(state, pid, fd, out);
            break;
        case PROX_FDTYPE_ATALK:
        case PROX_FDTYPE_PSHM:
        case PROX_FDTYPE_PSEM:
        case PROX_FDTYPE_KQUEUE:
        case PROX_FDTYPE_FSEVENTS:
        case PROX_FDTYPE_NETPOLICY:
        case PROX_FDTYPE_CHANNEL:
        case PROX_FDTYPE_NEXUS:
            // unimplemented
            break;
    };

    if (ret < 0) {
        Py_DECREF(out);
        return NULL;
    }
    return out;
}


static int miniproc_exec(PyObject *module) 
{
    //printf("miniproc_exec mod=%p state=%p\n", module, PyModule_GetState(module));
    ModuleState& state = get_module_state(module);

    // note that even in the case of us giving an error return, miniproc_free() is still
    // called, which will clean up. We just have to leave the state
    // sane enough for it to work. Python guarantees that state will be zeroed before 
    // calling us (PEP 3121) so don't have to worry about garbage getting in.

    PyObject* ipaddr_mod = PyImport_ImportModule("ipaddress");
    if (ipaddr_mod == NULL) {
        return -1;
    }

    // we keep a ref to the constructor functions for IP address objects to avoid
    // looking them up at runtime, as they're called during queries
    state.ipv4_ctor = PyObject_GetAttrString(ipaddr_mod, "IPv4Address");
    state.ipv6_ctor = PyObject_GetAttrString(ipaddr_mod, "IPv6Address");
    if (state.ipv4_ctor == NULL || state.ipv4_ctor == NULL) {
        return -1;
    }

    Py_CLEAR(ipaddr_mod);

    return build_enums(module);
}

static int miniproc_clear(PyObject* module) {
    //printf("miniproc clear mod=%p\n", module);
    ModuleState& state = get_module_state(module);
    return state.clear();
}

static int miniproc_traverse(PyObject *module, visitproc visit, void *arg) {
    //printf("miniproc traverse mod=%p\n", module);
    ModuleState& state = get_module_state(module);
    return state.traverse(visit, arg);
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
    .m_traverse = miniproc_traverse,
    .m_clear = miniproc_clear,
};

PyMODINIT_FUNC PyInit_miniproc(void) {
    return PyModuleDef_Init(&miniproc_module);
}

