
//#define Py_LIMITED_API 0x030d80000
#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <datetime.h> 

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

#include <libproc.h>
#include <sys/fcntl.h>

struct ModuleState {
    PyObject* ipv4_ctor;
    PyObject* ipv6_ctor;

    PyObject* fd_type_enums;
    PyObject* ifmt_enums;
    PyObject* address_family_enums;
    PyObject* tcp_state_enums;

    PyObject* soi_flags;
    PyObject* open_mode_flags;
    PyObject* proc_fp_flags;
    PyObject* proc_fi_guard_flags;

    int clear() {
        Py_XDECREF(ipv4_ctor);
        Py_XDECREF(ipv6_ctor);

        Py_XDECREF(fd_type_enums);
        Py_XDECREF(ifmt_enums);
        Py_XDECREF(address_family_enums);
        Py_XDECREF(tcp_state_enums);

        Py_XDECREF(soi_flags);
        Py_XDECREF(open_mode_flags);
        Py_XDECREF(proc_fp_flags);
        Py_XDECREF(proc_fi_guard_flags);

        return 0;
    }

    int traverse(visitproc visit, void *arg) {
        Py_VISIT(ipv4_ctor);
        Py_VISIT(ipv6_ctor);

        Py_VISIT(fd_type_enums);
        Py_VISIT(ifmt_enums);
        Py_VISIT(address_family_enums);
        Py_VISIT(tcp_state_enums);

        Py_VISIT(soi_flags);
        Py_VISIT(open_mode_flags);
        Py_VISIT(proc_fp_flags);
        Py_VISIT(proc_fi_guard_flags);

        return 0;
    }

private:
    // no copies
    ModuleState(ModuleState&);
};

static ModuleState& get_module_state(PyObject* module)
{
    assert(module);
    void* state = PyModule_GetState(module);
    assert(state != NULL);
    return *(ModuleState*)state;
}


static int set_dict_val_signed(PyObject* dict, const char* key, int64_t value) {
    PyObject* py_val = PyLong_FromLongLong(value);
    int ret = PyDict_SetItemString(dict, key, py_val);
    Py_DECREF(py_val);
    return ret;
}

static int set_dict_val_unsigned(PyObject* dict, const char* key, uint64_t value) {
    PyObject* py_val = PyLong_FromUnsignedLongLong(value);
    int ret = PyDict_SetItemString(dict, key, py_val);
    Py_DECREF(py_val);
    return ret;
}

static int set_dict_time(PyObject* dict, const char* key, int64_t sec, int64_t nsec) {
    double v = sec + (1e-9 * nsec);
    PyObject* f = PyFloat_FromDouble(v);
    PyObject* args = PyTuple_Pack(1, f);
    
    PyObject* dt = PyDateTime_FromTimestamp(args);
    int ret = PyDict_SetItemString(dict, key, dt);
    return ret;
}

// put obj in the dict without touching refcnt. Handles NULL for value
static int set_dict_val_obj(PyObject* dict, const char* key, PyObject* value) {
    assert(dict != NULL);
    assert(key!= NULL);
    if (value == NULL) {
        return -1;
    }

    int ret = PyDict_SetItemString(dict, key, value);
    return ret;
}

// steal the object value, and put it in the dict. Handles NULL for value
static int set_dict_val_steal_obj(PyObject* dict, const char* key, PyObject* value) {
    int ret = set_dict_val_obj(dict, key, value);
    Py_DECREF(value);
    return ret;
}

static int add_enum_value(PyObject* attrs, const char* name, int value, const char* docstring) {
    assert(attrs != NULL);
    assert(name != NULL);

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

static PyObject* make_reverse_enum(PyObject* this_enum_type, PyObject* values)
{
    assert(this_enum_type != NULL);
    assert(values != NULL);

    PyObject* key = NULL;
    PyObject* value = NULL;
    Py_ssize_t pos = 0;

    PyObject* ret = PyDict_New();
    if (ret == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to alloc enum reverse dict"); 
        return NULL;
    }

    while (PyDict_Next(values, &pos, &key, &value)) {
        PyObject* e = PyObject_GetAttr(this_enum_type, key);
        // FIXME: check item's not already set
        // FIXME: check error return
        //assert(idx < size);
        PyDict_SetItem(ret, value, e);
    }
    return ret;
}

static PyObject* create_enum_internal(PyObject* module, const char* py_typename, 
        const char* enum_name, PyObject* values) 
{
    PyObject* name = NULL, *args = NULL, *enum_mod = NULL;
    PyObject* enum_type = NULL, *this_enum_obj= NULL;

    name = PyUnicode_FromString(enum_name);
    args = PyTuple_Pack(2, name, values);

    if (name == NULL || args == NULL) {
        PyErr_Format(PyExc_MemoryError, "create_enum_internal failed to alloc"); 
        goto out;
    }

    enum_mod = PyImport_ImportModule("enum");
    if (enum_mod == NULL) {
        PyErr_Format(PyExc_ValueError, "create_enum_internal couldn't get enum module ref"); 
        goto out;
    }

    enum_type = PyObject_GetAttrString(enum_mod, py_typename);
    if (enum_type == NULL) {
        PyErr_Format(PyExc_TypeError, 
            "create_enum_internal couldn't find type '%s' in enum mod", py_typename); 
        goto out;
    }
    
    this_enum_obj = PyObject_Call(enum_type, args, NULL);
    if (this_enum_obj == NULL) {
        // exception should already be raised..
        goto out;
    }

    // Ok, enum is built.. thwack it in the module.
    if (PyObject_SetAttr(module, name, this_enum_obj) < 0) {
        PyErr_Format(PyExc_RuntimeError, "failed to add object to module");
        Py_CLEAR(this_enum_obj);
    }

out:
    Py_XDECREF(name);
    Py_XDECREF(args);
    Py_XDECREF(enum_mod);
    Py_XDECREF(enum_type);
    return this_enum_obj;
}

static PyObject* create_flags(PyObject* module, const char* enum_name, PyObject* values)
{
    return create_enum_internal(module, "Flag", enum_name, values);
}

static PyObject* create_enum(PyObject* module, const char* enum_name, PyObject* values)
{
    PyObject* enum_obj = create_enum_internal(module, "Enum", enum_name, values);
    if (enum_obj == NULL) {
        return NULL;
    }

    PyObject* ret = make_reverse_enum(enum_obj, values);
    return ret;
}

static PyObject* get_enum_value(PyObject* enum_list, int idx) {
    assert(enum_list);
    PyObject* o = PyLong_FromLong(idx);
    return PyDict_GetItem(enum_list, o);
}

static PyObject* get_flags_object(PyObject* flags_type, int flags) {
    assert(flags_type != NULL);

    PyObject* value = PyLong_FromLong(flags);
    PyObject* args = PyTuple_Pack(1, value);
    if (value == NULL || args == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for get_flags_object");
        Py_XDECREF(value);
        Py_XDECREF(args);
        return NULL;
    }

    PyObject* ret = PyObject_Call(flags_type, args, NULL);
    PyObject* ex = PyErr_GetRaisedException();

    if (ex) {
        assert(ret == NULL);
        // re-raise exception ...
        // SetRaisedException steals ex
        PyErr_SetRaisedException(ex);
    }

    Py_XDECREF(value);
    Py_XDECREF(args);
    return ret;
}

static int build_enum_tcp_state(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for enum tcp_state");
        return -1;
    }

    add_enum_value(attrs, "CLOSED", TSI_S_CLOSED, "closed");
    add_enum_value(attrs, "LISTEN", TSI_S_LISTEN, "listening for connection");
    add_enum_value(attrs, "SENT", TSI_S_SYN_SENT, "active, have sent syn");
    add_enum_value(attrs, "SYN_RECEIVED", TSI_S_SYN_RECEIVED, "have send and received syn");
    add_enum_value(attrs, "ESTABLISHED", TSI_S_ESTABLISHED, "established");
    add_enum_value(attrs, "CLOSE_WAIT", TSI_S__CLOSE_WAIT, "rcvd fin, waiting for close");
    add_enum_value(attrs, "FIN_WAIT_1", TSI_S_FIN_WAIT_1, "have closed, sent fin");
    add_enum_value(attrs, "CLOSING", TSI_S_CLOSING, "closed xchd FIN; await FIN ACK");
    add_enum_value(attrs, "LAST_ACK", TSI_S_LAST_ACK, "had fin and close; await FIN ACK");
    add_enum_value(attrs, "FIN_WAIT_2", TSI_S_FIN_WAIT_2, "have closed, fin is acked");
    add_enum_value(attrs, "TIME_WAIT", TSI_S_TIME_WAIT, "in 2*msl quiet wait after close");

    struct ModuleState& state = get_module_state(module);
    state.tcp_state_enums = create_enum(module, "TcpState", attrs);

    Py_DECREF(attrs);
    return state.tcp_state_enums == NULL ? -1 : 0;
};

static int build_enum_fd_type(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for enum fd_type");
        return -1;
    }

    add_enum_value(attrs, "ATALK", PROX_FDTYPE_ATALK, "");
    add_enum_value(attrs, "VNODE", PROX_FDTYPE_VNODE, "");
    add_enum_value(attrs, "SOCKET", PROX_FDTYPE_SOCKET, "");
    add_enum_value(attrs, "PSHM", PROX_FDTYPE_PSHM, "");
    add_enum_value(attrs, "PSEM", PROX_FDTYPE_PSEM, "");
    add_enum_value(attrs, "KQUEUE", PROX_FDTYPE_KQUEUE, "");
    add_enum_value(attrs, "PIPE", PROX_FDTYPE_PIPE, "");
    add_enum_value(attrs, "FSEVENTS", PROX_FDTYPE_FSEVENTS, "");
    add_enum_value(attrs, "NETPOLICY", PROX_FDTYPE_NETPOLICY, "");
    add_enum_value(attrs, "CHANNEL", PROX_FDTYPE_CHANNEL, "");
    add_enum_value(attrs, "NEXUS", PROX_FDTYPE_NEXUS, "");

    struct ModuleState& state = get_module_state(module);

    state.fd_type_enums = create_enum(module, "FDType", attrs);

    Py_DECREF(attrs);
    return state.fd_type_enums == NULL ? -1 : 0;
};

static int build_enum_ifmt(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for enum ifmt");
        return -1;
    }

    add_enum_value(attrs, "FIFO", S_IFIFO, "named pipe (fifo)");
    add_enum_value(attrs, "CHR", S_IFCHR, "character special");
    add_enum_value(attrs, "DIR", S_IFDIR, "directory");
    add_enum_value(attrs, "BLK", S_IFBLK, "block special");
    add_enum_value(attrs, "REG", S_IFREG, "regular");
    add_enum_value(attrs, "LNK", S_IFLNK, "symbolic link");
    add_enum_value(attrs, "SOCK", S_IFSOCK, "socket");

    struct ModuleState& state = get_module_state(module);

    state.ifmt_enums = create_enum(module, "IFMT", attrs);

    Py_DECREF(attrs);
    return state.ifmt_enums == NULL ? -1 : 0;
};


static int build_address_family(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for build_address_family");
        return -1;
    }
    add_enum_value(attrs, "UNSPEC", AF_UNSPEC, "unspecified");
    add_enum_value(attrs, "UNIX", AF_UNIX, "local to host (pipes)");
    add_enum_value(attrs, "INET", AF_INET,"internetwork: UDP, TCP, etc.");
    add_enum_value(attrs, "IMPLINK", AF_IMPLINK,"arpanet imp addresses");
    add_enum_value(attrs, "PUP", AF_PUP,"pup protocols: e.g. BSP");
    add_enum_value(attrs, "CHAOS", AF_CHAOS,"mit CHAOS protocols");
    add_enum_value(attrs, "NS", AF_NS,"XEROX NS protocols");
    add_enum_value(attrs, "ISO", AF_ISO,"ISO protocols");
    add_enum_value(attrs, "ECMA", AF_ECMA,"European computer manufacturers");
    add_enum_value(attrs, "DATAKit", AF_DATAKIT,"datakit protocols");
    add_enum_value(attrs, "CCITT", AF_CCITT,"CCITT protocols, X.25 etc");
    add_enum_value(attrs, "SNA", AF_SNA,"IBM SNA");
    add_enum_value(attrs, "DECnet", AF_DECnet,"DECnet");
    add_enum_value(attrs, "DLI", AF_DLI,"DEC Direct data link interface");
    add_enum_value(attrs, "LAT", AF_LAT,"LAT");
    add_enum_value(attrs, "HYLINK", AF_HYLINK,"NSC Hyperchannel");
    add_enum_value(attrs, "APPLETALK", AF_APPLETALK,"Apple Talk");
    add_enum_value(attrs, "ROUTE", AF_ROUTE,"Internal Routing Protocol");
    add_enum_value(attrs, "LINK", AF_LINK,"Link layer interface");
    add_enum_value(attrs, "COIP", AF_COIP,"connection-oriented IP, aka ST II");
    add_enum_value(attrs, "CNT", AF_CNT,"Computer Network Technology");
    add_enum_value(attrs, "IPX", AF_IPX,"Novell Internet Protocol");
    add_enum_value(attrs, "SIP", AF_SIP ,"Simple Internet Protocol");
    add_enum_value(attrs, "NDRV", AF_NDRV,"Network Driver 'raw' access");
    add_enum_value(attrs, "ISDN", AF_ISDN,"Integrated Services Digital Network");
    add_enum_value(attrs, "INET6", AF_INET6 ,"IPv6");
    add_enum_value(attrs, "NATM", AF_NATM,"native ATM access");
    add_enum_value(attrs, "SYSTEM", AF_SYSTEM,"Kernel event messages");
    add_enum_value(attrs, "NETBIOS", AF_NETBIOS,"NetBIOS");
    add_enum_value(attrs, "PPP", AF_PPP,"PPP communication protocol");
    add_enum_value(attrs, "RESEVED_36", AF_RESERVED_36,"Reserved for internal usage");
    add_enum_value(attrs, "IEEE80211", AF_IEEE80211,"IEEE 802.11 protocol");
    add_enum_value(attrs, "UTUN", AF_UTUN,"");
    add_enum_value(attrs, "SOCKTES", AF_VSOCK,"Sockets");

    struct ModuleState& state = get_module_state(module);

    state.address_family_enums = create_enum(module, "AddressFamily", attrs);

    Py_DECREF(attrs);
    return state.address_family_enums == NULL ? -1 : 0;
}

static int build_flags_proc_fp(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for flags fp");
        return -1;
    }
    add_enum_value(attrs, "SHARED", PROC_FP_SHARED, "shared by more than one fd");
    add_enum_value(attrs, "CLEXEC", PROC_FP_CLEXEC, "close on exec");
    add_enum_value(attrs, "GUARDED", PROC_FP_GUARDED, "guarded fd");
    add_enum_value(attrs, "CLFORK", PROC_FP_CLFORK, "close on fork");

    struct ModuleState& state = get_module_state(module);
    state.proc_fp_flags = create_flags(module, "ProcFP", attrs);

    Py_DECREF(attrs);

    return state.proc_fp_flags == NULL ? -1 : 0;
};

static int build_flags_proc_fi_guard(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for flags fp");
        return -1;
    }

    add_enum_value(attrs, "CLOSE", PROC_FI_GUARD_CLOSE, "");
    add_enum_value(attrs, "DUP", PROC_FI_GUARD_DUP, "");
    add_enum_value(attrs, "SOCKET_IPC", PROC_FI_GUARD_SOCKET_IPC, "");
    add_enum_value(attrs, "FILEPORT", PROC_FI_GUARD_FILEPORT, "");

    struct ModuleState& state = get_module_state(module);
    state.proc_fi_guard_flags = create_flags(module, "ProcFIGuard", attrs);

    Py_DECREF(attrs);

    return state.proc_fi_guard_flags == NULL ? -1 : 0;
};

static int build_flags_soi(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for enum soi");
        return -1;
    }

    add_enum_value(attrs, "NOFDREF", SOI_S_NOFDREF, "no file table ref any more");
    add_enum_value(attrs, "ISCONNECTED", SOI_S_ISCONNECTED, "socket connected to a peer");
    add_enum_value(attrs, "ISCONNECTING", SOI_S_ISCONNECTING, "in process of connecting to peer");
    add_enum_value(attrs, "ISDISCONNECTED", SOI_S_ISDISCONNECTED, "in process of disconnecting");
    add_enum_value(attrs, "CANTSENDMODE", SOI_S_CANTSENDMORE, "can't send more data to peer");
    add_enum_value(attrs, "CANTREVCMODE", SOI_S_CANTRCVMORE, "can't receive more data from peer");
    add_enum_value(attrs, "RCVATMARK", SOI_S_RCVATMARK, "at mark on input");
    add_enum_value(attrs, "PRIV", SOI_S_PRIV, "privileged for broadcast, raw...");
    add_enum_value(attrs, "NBIO", SOI_S_NBIO , "non-blocking ops");
    add_enum_value(attrs, "ASYNC", SOI_S_ASYNC, "async i/o notify");
    add_enum_value(attrs, "INCOMP", SOI_S_INCOMP, "Unaccepted, incomplete connection");
    add_enum_value(attrs, "COMP", SOI_S_COMP, "unaccepted, complete connection");
    add_enum_value(attrs, "ISDISCONNECTED", SOI_S_ISDISCONNECTED, "socket disconnected from peer");
    add_enum_value(attrs, "DRAINING", SOI_S_DRAINING, "close waiting for blocked system calls to drain");

    struct ModuleState& state = get_module_state(module);
    state.soi_flags = create_flags(module, "SOI", attrs);

    Py_DECREF(attrs);

    return state.soi_flags == NULL ? -1 : 0;
};



static int build_flags_open_mode(PyObject* module) 
{
    PyObject* attrs = PyDict_New();
    if (attrs == NULL) {
        PyErr_Format(PyExc_MemoryError, "failed to allocate for enum open_mode");
        return -1;
    }

    add_enum_value(attrs, "FREAD", FREAD, "");
    add_enum_value(attrs, "FWRITE", FWRITE, "");
    add_enum_value(attrs, "O_NONBLOCK", O_NONBLOCK, "delay");
    add_enum_value(attrs, "O_APPEND", O_APPEND, "set append mode");
    add_enum_value(attrs, "O_SYNC", O_SYNC,"synch I/O file integrity");
    add_enum_value(attrs, "O_SHLOCK", O_SHLOCK, "open with shared file lock");
    add_enum_value(attrs, "O_EXLOCK", O_EXLOCK, "open with exclusive file lock");
    add_enum_value(attrs, "O_ASYNC", O_ASYNC, "signal pgrp when data ready");
    add_enum_value(attrs, "O_NOFOLLOW", O_NOFOLLOW, "don't follow symlinks");
    add_enum_value(attrs, "O_CREAT", O_CREAT, "create if nonexistant");
    add_enum_value(attrs, "O_TRUNC", O_TRUNC, "truncate to zero length");
    add_enum_value(attrs, "O_EXCL", O_EXCL, "error if already exists");
    add_enum_value(attrs, "O_RESOLVE_BENEATH", O_RESOLVE_BENEATH, "only for open(2), same value as FMARK");
    add_enum_value(attrs, "O_UNIQUE", O_UNIQUE, "only for open(2), same value as FDEFER");
    add_enum_value(attrs, "O_EVTONLY", O_EVTONLY, "descriptor requested for event notifications only");

    add_enum_value(attrs, "O_NOCTTY", O_NOCTTY, "don't assign controlling terminal");
    add_enum_value(attrs, "O_DIRECTORY", O_DIRECTORY, "");;
    add_enum_value(attrs, "O_DSYNC", O_DSYNC, "synch I/O data integrity");;
    add_enum_value(attrs, "O_CLOEXEC", O_CLOEXEC, "implicitly set FD_CLOEXEC");
    add_enum_value(attrs, "O_NOFOLLOW_ANY", O_NOFOLLOW_ANY, "no symlinks allowed in path");
    add_enum_value(attrs, "O_EXEC", O_EXEC, "open file for execute only");

    // these values are defined in fcntl.h but guarded by #ifdef KERNEL
    // however we see these flags via libproc...
    add_enum_value(attrs, "FWASWRITTEN", 0x10000, "descriptor was written");
    add_enum_value(attrs, "FNOCACHE", 0x00040000, "fcntl(F_NOCACHE, 1)");
    add_enum_value(attrs, "FNORDAHEAD", 0x00080000, "fcntl(F_RDAHEAD, 0)");
    add_enum_value(attrs, "FNODIRECT", 0x00800000, "fcntl(F_NODIRECT, 1)");
    add_enum_value(attrs, "FENCRYPTED", 0x02000000, "");
    add_enum_value(attrs, "FSINGLE_WRITER", 0x04000000, "fcntl(F_SINGLE_WRITER, 1)");
    add_enum_value(attrs, "O_CLOFORK", 0x08000000, "implicitly set FD_CLOFORK");
    add_enum_value(attrs, "FUNENCRYPTED", 0x10000000, "");;

    struct ModuleState& state = get_module_state(module);
    state.open_mode_flags = create_flags(module, "OpenMode", attrs);

    Py_DECREF(attrs);

    return state.open_mode_flags == NULL ? -1 : 0;
};

static PyObject* get_fd_type(ModuleState& state, int fd_type) {
    return get_enum_value(state.fd_type_enums, fd_type);
}

static PyObject* get_ifmt(ModuleState& state, int ifmt) {
    return get_enum_value(state.ifmt_enums, ifmt);
}

static PyObject* get_address_family(ModuleState& state, int family) {
    return get_enum_value(state.address_family_enums, family);
}

static PyObject* get_tcp_state(ModuleState& state, int tcp_state) {
    return get_enum_value(state.tcp_state_enums, tcp_state);
}

static PyObject* get_soi_flags_value(ModuleState& state, int flags) {
    return get_flags_object(state.soi_flags, flags);
}

static PyObject* get_open_mode_flags_value(ModuleState& state, int flags) {
    return get_flags_object(state.open_mode_flags, flags);
}

static PyObject* get_proc_fp_flags_value(ModuleState& state, int flags) {
    return get_flags_object(state.proc_fp_flags, flags);
}

static PyObject* get_proc_fi_guard_flags_value(ModuleState& state, int flags) {
    return get_flags_object(state.proc_fi_guard_flags, flags);
}

static int build_enums(PyObject* module) 
{
    if (build_enum_fd_type(module) < 0 || 
        build_enum_ifmt(module) < 0 || 
        build_address_family(module) < 0 || 
        build_enum_tcp_state(module) < 0 || 
        build_flags_open_mode(module) < 0 || 
        build_flags_soi(module) < 0 ||
        build_flags_proc_fi_guard(module) < 0 ||
        build_flags_proc_fp(module) < 0) {

        return -1;
    }
    return 0;
}

static bool inet_is_ipv4(const socket_info& si) 
{
    const int family = si.soi_family;
    assert(family == AF_INET || family == AF_INET6);
    return family == AF_INET;
}

// extract ipv4 address
static PyObject* extract_address(ModuleState& state, const in4in6_addr& addr)
{
    assert(state.ipv4_ctor);

    uint32_t a = ntohl(addr.i46a_addr4.s_addr);

    PyObject* b = PyLong_FromLong(a);
    PyObject* args = PyTuple_Pack(1, b);
    PyObject* py_addr = PyObject_Call(state.ipv4_ctor, args, NULL);

    Py_XDECREF(args);
    Py_XDECREF(b);
    // FIXME: catch errors
    return py_addr;
}

// extract ipv6 address
static PyObject* extract_address(ModuleState& state, const in6_addr& addr)
{
    assert(state.ipv6_ctor);

    // FIXME: byte order ?
    PyObject* array = PyBytes_FromStringAndSize((const char*)addr.__u6_addr.__u6_addr8, 16);
    PyObject* args = PyTuple_Pack(1, array);

    PyObject* py_addr = PyObject_Call(state.ipv6_ctor, args, NULL);

    Py_XDECREF(args);
    Py_XDECREF(array);
    // FIXME: catch errors
    return py_addr;
}

template<typename T>
PyObject* extract_address(ModuleState& state, const T& addr, bool is_ipv4)
{
    return is_ipv4 ? 
        extract_address(state, addr.ina_46) :
        extract_address(state, addr.ina_6);
}

static int handle_tcp_socket(ModuleState& state, const socket_info& si, PyObject* out) 
{
    const bool is_ipv4 = inet_is_ipv4(si);

    //FIXME: leaks
    PyDict_SetItemString(out, "kind", PyUnicode_FromString("tcp"));

    set_dict_val_steal_obj(out, "local_addr", 
            extract_address(state, si.soi_proto.pri_tcp.tcpsi_ini.insi_laddr, is_ipv4));

    set_dict_val_steal_obj(out, "remote_addr", 
            extract_address(state, si.soi_proto.pri_tcp.tcpsi_ini.insi_faddr, is_ipv4));

    set_dict_val_signed(out, "local_port", ntohs(si.soi_proto.pri_tcp.tcpsi_ini.insi_lport));
    set_dict_val_signed(out, "remote_port", ntohs(si.soi_proto.pri_tcp.tcpsi_ini.insi_fport));

    const long tcp_state = si.soi_proto.pri_tcp.tcpsi_state;
    set_dict_val_obj(out, "tcp_state", get_tcp_state(state, tcp_state));
    return 0;
}

int handle_in_socket(ModuleState& state, const socket_info& si, PyObject* out) 
{
    const bool is_ipv4 = inet_is_ipv4(si);

    set_dict_val_steal_obj(out, "local_addr", 
        extract_address(state, si.soi_proto.pri_in.insi_laddr, is_ipv4));

    set_dict_val_steal_obj(out, "remote_addr", 
        extract_address(state, si.soi_proto.pri_in.insi_faddr, is_ipv4));

    set_dict_val_signed(out, "local_port", ntohs(si.soi_proto.pri_in.insi_lport));
    set_dict_val_signed(out, "remote_port", ntohs(si.soi_proto.pri_in.insi_fport));

    return 0;
}

#if 0
#define TSI_T_REXMT             0       /* retransmit */
#define TSI_T_PERSIST           1       /* retransmit persistence */
#define TSI_T_KEEP              2       /* keep alive */
#define TSI_T_2MSL              3       /* 2*msl quiet time timer */
#define TSI_T_NTIMERS           4
enum {
	SOCKINFO_GENERIC        = 0,
	SOCKINFO_IN             = 1,
	SOCKINFO_TCP            = 2,
	SOCKINFO_UN             = 3,
	SOCKINFO_NDRV           = 4,
	SOCKINFO_KERN_EVENT     = 5,
	SOCKINFO_KERN_CTL       = 6,
	SOCKINFO_VSOCK          = 7,
};
#endif

static PyObject* handle_inet_socket(ModuleState& state, const socket_fdinfo& si)
{
    PyObject* out = PyDict_New();
    if(out == NULL) {
        return NULL;
    }

    int family = si.psi.soi_family;
    assert(family == AF_INET || family == AF_INET6);

    switch(si.psi.soi_kind) {
        case SOCKINFO_TCP: // tcp socket
            handle_tcp_socket(state, si.psi, out);
            break;
        case SOCKINFO_IN: // inet, non-tcp socket
            handle_in_socket(state, si.psi, out);
            break;
        default:
            PyErr_Format(PyExc_RuntimeError, 
                "handle_socket_addr: Unhandled soi_kind %d", si.psi.soi_kind);
            Py_DECREF(out);
            return NULL;
    };
    return out;
}


static PyObject* handle_unix_socket(ModuleState& state, const socket_fdinfo& si)
{
    PyObject* out = PyDict_New();
    if(out == NULL) {
        return NULL;
    }

    // extract the socket's path(s)... 
    // lsof does some pretty whack things here.. we'll just take the simple route
    set_dict_val_steal_obj(out, "path", 
        PyUnicode_FromString(si.psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path));

    set_dict_val_steal_obj(out, "cpath", 
        PyUnicode_FromString(si.psi.soi_proto.pri_un.unsi_caddr.ua_sun.sun_path));

    return out;
}

static int handle_si_common(ModuleState& state, const proc_fileinfo& pfi, PyObject* out)
{
    // handle data common to all fd types..
    set_dict_val_obj(out, "open_flags", get_open_mode_flags_value(state, pfi.fi_openflags));
    set_dict_val_signed(out, "offset", pfi.fi_offset);
    set_dict_val_obj(out, "status", get_proc_fp_flags_value(state, pfi.fi_status));
    set_dict_val_obj(out, "guard_flags", get_proc_fi_guard_flags_value(state, pfi.fi_guardflags));
    return 0;
}

static int handle_dev(PyObject* out, const char* name, int32_t val) 
{
    // FIXME create dict here
    PyObject* dev = PyDict_New();
    if (dev == NULL) {
        return -1;
    }
    set_dict_val_unsigned(dev, "major", major(val));
    set_dict_val_unsigned(dev, "minor", minor(val));

    return set_dict_val_steal_obj(out, name, dev);
}

// extract details from vinfo_stat
static int handle_vnode_stat(ModuleState& state, const char* key, vinfo_stat vi_stat, PyObject* out) 
{
    assert(socket != NULL);
    PyObject* stat = PyDict_New();
    if (stat == NULL) {
        return -1;
    }

    set_dict_val_unsigned(stat, "inode", vi_stat.vst_ino);

    const uint16_t ifmt = vi_stat.vst_mode & S_IFMT;
    set_dict_val_obj(stat, "mode", get_ifmt(state, ifmt));

    // def not defined for FIFO
    if (ifmt != S_IFIFO) {
        handle_dev(stat, "dev", vi_stat.vst_dev);
    }

    // rdev only defined for BLK/CHR
    if (ifmt == S_IFBLK || ifmt == S_IFCHR) {
        handle_dev(stat, "rdev", vi_stat.vst_rdev);
    }

    set_dict_val_unsigned(stat, "nlink", vi_stat.vst_nlink);
    set_dict_val_unsigned(stat, "uid", vi_stat.vst_uid);
    set_dict_val_unsigned(stat, "gid", vi_stat.vst_gid);

    set_dict_time(stat, "atime", vi_stat.vst_atime, vi_stat.vst_atimensec);
    set_dict_time(stat, "mtime", vi_stat.vst_mtime, vi_stat.vst_mtimensec);
    set_dict_time(stat, "ctime", vi_stat.vst_ctime, vi_stat.vst_ctimensec);
    set_dict_time(stat, "birthtime", vi_stat.vst_birthtime, vi_stat.vst_birthtimensec);
    
    set_dict_val_signed(stat, "size", vi_stat.vst_size);
    set_dict_val_signed(stat, "blocks", vi_stat.vst_uid);
    set_dict_val_signed(stat, "blksize", vi_stat.vst_blksize);
    set_dict_val_unsigned(stat, "flags", vi_stat.vst_flags);
    set_dict_val_unsigned(stat, "gen", vi_stat.vst_gen);

    return set_dict_val_steal_obj(out, key, stat);
}

static int handle_sockbuf_info(ModuleState& state, const char* key, const sockbuf_info& info, 
        PyObject* out) 
{
    assert(socket != NULL);
    PyObject* buff_info = PyDict_New();
    if (buff_info== NULL) {
        return -1;
    }

    set_dict_val_unsigned(buff_info, "cc", info.sbi_cc);
    set_dict_val_unsigned(buff_info, "hiwat", info.sbi_hiwat);
    set_dict_val_unsigned(buff_info, "mbcnt", info.sbi_mbcnt);
    set_dict_val_unsigned(buff_info, "mbmax", info.sbi_mbmax);
    set_dict_val_unsigned(buff_info, "lowat", info.sbi_lowat);
    set_dict_val_signed(buff_info, "flags", info.sbi_flags);
    set_dict_val_signed(buff_info, "timeo", info.sbi_timeo);

    return set_dict_val_steal_obj(out, key, buff_info);
}

static int handle_socket(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    socket_fdinfo si;
    const int size = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
                "proc_pidfdinfo: PROC_PIDFDSOCKETINFO failed, errno %d", errno);
        return -1;
    }

    // FIXME: catch error
    handle_si_common(state, si.pfi, out);

    PyObject* socket = PyDict_New();
    if (socket == NULL) {
        return -1;
    }

    const int family = si.psi.soi_family;

    set_dict_val_obj(socket, "family", get_address_family(state, family));

    // there is a stat field here, but not sure when it makes sense to include it...
    // handle_vnode_stat(state, "stat", si.psi.soi_stat, socket);
    set_dict_val_unsigned(socket, "so", si.psi.soi_so);
    set_dict_val_unsigned(socket, "pcb", si.psi.soi_pcb);
    set_dict_val_signed(socket, "type", si.psi.soi_type);
    set_dict_val_signed(socket, "protocol", si.psi.soi_protocol);
    set_dict_val_signed(socket, "family", si.psi.soi_family);

    // FIXME: options.. a flag?
    set_dict_val_signed(socket, "options", si.psi.soi_options);
    set_dict_val_signed(socket, "linger", si.psi.soi_linger); 
    set_dict_val_obj(socket, "state", get_soi_flags_value(state, si.psi.soi_state));
    set_dict_val_signed(socket, "qlen", si.psi.soi_qlen);
    set_dict_val_signed(socket, "incqlen", si.psi.soi_incqlen);
    set_dict_val_signed(socket, "qlimit", si.psi.soi_qlimit);
    set_dict_val_signed(socket, "timeo", si.psi.soi_timeo);
    set_dict_val_unsigned(socket, "error", si.psi.soi_error);
    set_dict_val_unsigned(socket, "oobmark", si.psi.soi_oobmark);
    handle_sockbuf_info(state, "rcv_buff", si.psi.soi_rcv, socket);
    handle_sockbuf_info(state, "snd_buff", si.psi.soi_snd, socket);
    set_dict_val_signed(socket, "kind", si.psi.soi_kind);

    PyObject* details = NULL;
    const char* keyname = NULL;

    // address families for which we have specific handling
    switch (family) {
    case AF_INET:
    case AF_INET6:
        details = handle_inet_socket(state, si);
        keyname = "inet_socket";
        break;
    case AF_UNIX:
        details = handle_unix_socket(state, si);
        keyname = "unix_socket";
        break;
    };

    if (keyname != NULL) {
        // FIXME:If details == NULL, error occoured
        set_dict_val_steal_obj(socket, keyname, details);
    }
   
    set_dict_val_steal_obj(out, "socket", socket);
    return 0;
}

static int handle_vnode_info(ModuleState& state, const char* key, const vnode_info& info,
        PyObject* out) 
{
    PyObject* vnode_info = PyDict_New();
    if (vnode_info == NULL) {
        return -1;
    }

    // fIXME: catch errors
    handle_vnode_stat(state, "stat", info.vi_stat, vnode_info);
    set_dict_val_signed(vnode_info, "type", info.vi_type);

    set_dict_val_steal_obj(out, "fsid", 
        Py_BuildValue("(ii)", 
            info.vi_fsid.val[0], info.vi_fsid.val[1]));

    return set_dict_val_steal_obj(out, key, vnode_info);
}

static int handle_vnode(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    vnode_fdinfowithpath vi;
    size_t size = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
            "proc_pidfdinfo PROC_PIDFDVNODEPATHINFO failed, errno %d", errno);
        return -1;
    } else if (size < sizeof(vi)) {
        PyErr_Format(PyExc_RuntimeError, 
           "proc_pidfdinfo PROC_PIDFDVNODEPATHINFO: return value wrong size (%d)", size);
        return -1;
    }

    PyObject* vnode = PyDict_New();
    if (vnode == NULL) {
        return -1;
    }

    // FIXME: catch errors
    handle_si_common(state, vi.pfi, out);

    // FIXME: is this the correct conversion for FS encoding?
    set_dict_val_steal_obj(vnode, "path", PyUnicode_FromString(vi.pvip.vip_path));

    handle_vnode_info(state, "vnode_info", vi.pvip.vip_vi, vnode);
    set_dict_val_steal_obj(out, "vnode", vnode);

    return 0;
}

template<typename BufferType>
static int call_proc_pidfdinfo(pid_t pid, int fd, int flavor, BufferType& buffer) 
{
    size_t size = proc_pidfdinfo(pid, fd, flavor, &buffer, sizeof(buffer));
    if (size <= 0) {
        PyErr_Format(PyExc_OSError, 
            "proc_pidfdinfo() flavor %d failed: errno %d size %d", 
            flavor, errno, sizeof(buffer));
        return -1;
    } else if (size < sizeof(buffer)) {
        PyErr_Format(PyExc_RuntimeError, 
            "proc_pidfdinfo() flavor %d: return value wrong size %d vs %d", 
            flavor, size, sizeof(buffer));
        return -1;
    }
    return 0;
}

static int handle_pipe(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    struct pipe_fdinfo pi;
    if (call_proc_pidfdinfo(pid, fd, PROC_PIDFDPIPEINFO, pi) < 0) {
        return -1;
    }

    // FIXME: catch errors
    handle_si_common(state, pi.pfi, out);
    handle_vnode_stat(state, "stat", pi.pipeinfo.pipe_stat, out);
    set_dict_val_unsigned(out, "handle", pi.pipeinfo.pipe_handle);
    set_dict_val_unsigned(out, "peerhandle", pi.pipeinfo.pipe_peerhandle);
    set_dict_val_signed(out, "status", pi.pipeinfo.pipe_status);
    return 0;
}

static int handle_kqueue(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    struct kqueue_fdinfo kqi;
    if (call_proc_pidfdinfo(pid, fd, PROC_PIDFDKQUEUEINFO, kqi) < 0) {
        return -1;
    }

    // FIXME: catch error
    handle_si_common(state, kqi.pfi, out);
    handle_vnode_stat(state, "stat", kqi.kqueueinfo.kq_stat, out);
    return 0;
}

static int handle_pshm(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    struct pshm_fdinfo pshmi;
    size_t size  = proc_pidfdinfo(pid, fd, PROC_PIDFDPSHMINFO, &pshmi, sizeof(pshmi));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
            "proc_pidfdinfo PROC_PIDFDPSHMINFO: failed, errno %d", errno);
        return -1;
    } else if (size < sizeof(pshmi)) {
        PyErr_Format(PyExc_RuntimeError, 
            "proc_pidfdinfo PROC_PIDFDPSHMINFO: return value wrong size (%d)", size);
        return -1;
    }

    handle_si_common(state, pshmi.pfi, out);
    handle_vnode_stat(state, "stat", pshmi.pshminfo.pshm_stat, out);
    set_dict_val_unsigned(out, "mapaddr", pshmi.pshminfo.pshm_mappaddr);
    set_dict_val_steal_obj(out, "name", PyUnicode_FromString(pshmi.pshminfo.pshm_name));

    return 0;
}

static int handle_psem(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    struct psem_fdinfo psemi;
    size_t size  = proc_pidfdinfo(pid, fd, PROC_PIDFDPSEMINFO, &psemi, sizeof(psemi));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
            "proc_pidfdinfo PROC_PIDFDPSHMINFO: failed, errno %d", errno);
        return -1;
    } else if (size < sizeof(psemi)) {
        PyErr_Format(PyExc_RuntimeError, 
            "proc_pidfdinfo PROC_PIDFDPSHMINFO: return value wrong size (%d)", size);
        return -1;
    }

    return 0;
}

static int handle_fd_channel(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    struct psem_fdinfo psemi;
    size_t size  = proc_pidfdinfo(pid, fd, PROC_PIDFDPSEMINFO, &psemi, sizeof(psemi));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
            "proc_pidfdinfo PROC_PIDFDPSHMINFO: failed, errno %d", errno);
        return -1;
    } else if (size < sizeof(psemi)) {
        PyErr_Format(PyExc_RuntimeError, 
            "proc_pidfdinfo PROC_PIDFDPSHMINFO: return value wrong size (%d)", size);
        return -1;
    }

    return 0;
}
//#define PROC_PIDFDATALKINFO             8
//#define PROC_PIDFDCHANNELINFO           10

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
        case PROX_FDTYPE_KQUEUE:
            ret = handle_kqueue(state, pid, fd, out);
            break;
        case PROX_FDTYPE_PSHM:
            ret = handle_pshm(state, pid, fd, out);
            break;
        case PROX_FDTYPE_FSEVENTS:
        case PROX_FDTYPE_PSEM:
        case PROX_FDTYPE_ATALK:
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
    PyDateTime_IMPORT; 
    
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
    printf("miniproc clear mod=%p\n", module);
    ModuleState& state = get_module_state(module);
    return state.clear();
}

static int miniproc_traverse(PyObject *module, visitproc visit, void *arg) {
    printf("miniproc traverse mod=%p\n", module);
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

