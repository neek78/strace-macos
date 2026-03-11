
//#define Py_LIMITED_API 0x030d80000
#define PY_SSIZE_T_CLEAN

#include <Python.h>

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

    int clear() {
        Py_XDECREF(ipv4_ctor);
        Py_XDECREF(ipv6_ctor);

        Py_XDECREF(fd_type_enums);
        Py_XDECREF(ifmt_enums);
        Py_XDECREF(address_family_enums);
        Py_XDECREF(tcp_state_enums);
        Py_XDECREF(soi_flags);
        Py_XDECREF(open_mode_flags);

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

        return 0;
    }

private:
    // no copies
    ModuleState(ModuleState&);
};

ModuleState& get_module_state(PyObject* module)
{
    assert(module);
    void* state = PyModule_GetState(module);
    assert(state != NULL);
    return *(ModuleState*)state;
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

    PyObject* reverse = create_enum(module, "FDType", attrs);
    state.fd_type_enums = reverse;

    Py_DECREF(attrs);
    return reverse == NULL ? -1 : 0;
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
    add_enum_value(attrs, "BOGUS", 0x10000, "bogus");
    add_enum_value(attrs, "O_NOCTTY", O_NOCTTY, "don't assign controlling terminal");
    add_enum_value(attrs, "O_DIRECTORY", O_DIRECTORY, "");;
    add_enum_value(attrs, "O_DSYNC", O_DSYNC, "synch I/O data integrity");;
    add_enum_value(attrs, "O_CLOEXEC", O_CLOEXEC, "implicitly set FD_CLOEXEC");
    add_enum_value(attrs, "O_NOFOLLOW_ANY", O_NOFOLLOW_ANY, "no symlinks allowed in path");
    add_enum_value(attrs, "O_EXEC", O_EXEC, "open file for execute only");

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

static int build_enums(PyObject* module) 
{
    if (build_enum_fd_type(module) < 0 || 
        build_enum_ifmt(module) < 0 || 
        build_address_family(module) < 0 || 
        build_enum_tcp_state(module) < 0 || 
        build_flags_open_mode(module) < 0 || 
        build_flags_soi(module) < 0 ) {
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

    Py_XDECREF(args);
    Py_XDECREF(b);
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

    Py_XDECREF(args);
    Py_XDECREF(array);
    // FIXME: catch errors
    return py_addr;
}

template<typename T>
PyObject* extract_address(ModuleState& state, const T& addr, bool is_ipv4)
{
    return is_ipv4 ? 
        extract_ipv4_address(state, addr.ina_46) :
        extract_ipv6_address(state, addr.ina_6);
}

int handle_tcp_socket(ModuleState& state, const socket_fdinfo& si, PyObject* out) 
{
    const int family = si.psi.soi_family;
    const bool is_ipv4 = family == AF_INET;

    //FIXME: leaks
    PyDict_SetItemString(out, "kind", PyUnicode_FromString("tcp"));

    PyObject* local_addr = extract_address(state, si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr, is_ipv4);
    PyObject* remote_addr = extract_address(state, si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr, is_ipv4);

    PyDict_SetItemString(out, "local_addr", local_addr);
    PyDict_SetItemString(out, "remote_addr", remote_addr);

    Py_CLEAR(local_addr);
    Py_CLEAR(remote_addr);

    long local_port = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
    long remote_port = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport);

    //FIXME: leaks
    PyDict_SetItemString(out, "local_port", PyLong_FromLong(local_port));
    PyDict_SetItemString(out, "remote_port", PyLong_FromLong(remote_port));

    long tcp_state = si.psi.soi_proto.pri_tcp.tcpsi_state;
    PyDict_SetItemString(out, "tcp_state", get_tcp_state(state, tcp_state));
    return 0;
}

int handle_in_socket(ModuleState& state, const socket_fdinfo& si, PyObject* out) 
{
    const int family = si.psi.soi_family;
    const bool is_ipv4 = family == AF_INET;

    PyObject* local_addr = extract_address(state, si.psi.soi_proto.pri_in.insi_laddr, is_ipv4);
    PyObject* remote_addr = extract_address(state, si.psi.soi_proto.pri_in.insi_faddr, is_ipv4);

    PyDict_SetItemString(out, "local_addr", local_addr);
    PyDict_SetItemString(out, "remote_addr", remote_addr);

    long local_port = ntohs(si.psi.soi_proto.pri_in.insi_lport);
    long remote_port = ntohs(si.psi.soi_proto.pri_in.insi_fport);

    PyDict_SetItemString(out, "local_port", PyLong_FromLong(local_port));
    PyDict_SetItemString(out, "remote_port", PyLong_FromLong(remote_port));
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

    int family = si.psi.soi_family;

    PyObject* details = NULL;
    switch (family) {
    case AF_INET:
    case AF_INET6:
        details = handle_inet_socket(state, si);
        break;
    // case AF_UNIX:
    //    break;
    default:
        PyErr_Format(PyExc_RuntimeError, 
                "proc_pidfdinfo: handle_socket unhandled family %d", family);
        return -1;
    };

    PyObject* soi_state = get_soi_flags_value(state, si.psi.soi_state);
    PyDict_SetItemString(details, "soi_state", soi_state);

    PyObject* py_family = get_address_family(state, family);
    PyDict_SetItemString(out, "family", py_family);

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
    } else if (size < sizeof(vi)) {
        PyErr_Format(PyExc_RuntimeError, 
           "proc_pidfdinfo PROC_PIDFDVNODEPATHINFO: return value wrong size (%d)", size);
        return -1;
    }

    PyObject* details = PyDict_New();
    if (details == NULL) {
        return -1;
    }

    // FIXME: is this the correct conversion for FS encoding?
    // fIXME: catch errors
    PyObject* value = PyUnicode_FromString(vi.pvip.vip_path);
    PyDict_SetItemString(details, "path", value);
    PyDict_SetItemString(out, "vnode", details);

    PyObject* ifmt = get_ifmt(state, vi.pvip.vip_vi.vi_stat.vst_mode & S_IFMT);
    PyDict_SetItemString(details, "ifmt", ifmt);

    PyObject* inode = PyLong_FromUInt64(vi.pvip.vip_vi.vi_stat.vst_ino);
    PyDict_SetItemString(details, "inode", inode);

    PyDict_SetItemString(details, "open_mode", get_open_mode_flags_value(state, vi.pfi.fi_openflags));

#if 0
	uint32_t                fi_openflags;
	uint32_t                fi_status;
	off_t                   fi_offset;
	int32_t                 fi_type;
	uint32_t                fi_guardflags;

    f = pfi->fi_openflags & (FREAD | FWRITE);
    if (f == FREAD)
        Lf->access = LSOF_FILE_ACCESS_READ;
    else if (f == FWRITE)
        Lf->access = LSOF_FILE_ACCESS_WRITE;
     //.* Save the offset / size
    Lf->off = (SZOFFTYPE)pfi->fi_offset;
    Lf->off_def = 1;

    // * Save file structure information as requested.
    Lf->ffg = (long)pfi->fi_openflags;
    Lf->fsv |= FSV_FG;
#endif
    return 0;
}

static int handle_pipe(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    // struct pipe_fdinfo pi;
    // size_t size = proc_pidfdinfo(pid, fd, PROC_PIDFDPIPEINFO, &pi, sizeof(pi));
    return -1;
}

static int handle_kqueue(ModuleState& state, pid_t pid, int fd, PyObject* out) 
{
    // struct kqueue_fdinfo kq;
    // size_t size  = proc_pidfdinfo(pid, fd, PROC_PIDFDKQUEUEINFO, &kq, sizeof(kq));
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
        case PROX_FDTYPE_KQUEUE:
            ret = handle_kqueue(state, pid, fd, out);
            break;
        case PROX_FDTYPE_ATALK:
        case PROX_FDTYPE_PSHM:
        case PROX_FDTYPE_PSEM:
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

