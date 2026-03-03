
#define Py_LIMITED_API 0x030d80000
#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

#include <libproc.h>

static void handle_vnode(pid_t pid, int fd, PyObject* out) 
{
    struct vnode_fdinfowithpath vi;

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

static void handle_socket(pid_t pid, int fd, PyObject* out) 
{
    struct socket_fdinfo si;
    int size = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
    if (size <= 0) {
        PyErr_Format(PyExc_RuntimeError, 
                "proc_pidfdinfo PROC_PIDFDSOCKETINFO failed, errno %d", errno);
        return;
    }

    PyObject* state = PyLong_FromLong(si.psi.soi_state);
    PyDict_SetItemString(out, "state", state);

#if 0
    switch ((si.psi.soi_family)) {
    case AF_INET:
    case AF_INET6:
    };
#endif
}

static PyObject* get_fd_info(PyObject* *self, PyObject *args)  
{
    int fd = -1;
    pid_t pid;
    if (!PyArg_ParseTuple(args, _Py_PARSE_PID _Py_PARSE_INTPTR, &pid, &fd))
        return NULL;

    // FIXME: heap alloc
    struct proc_fdinfo buffer[1024];

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

    PyObject* out = PyDict_New();

    printf("kind %d\n", kind);
    switch(kind) {
        case PROX_FDTYPE_VNODE:
            handle_vnode(pid, fd, out);
            break;
        case PROX_FDTYPE_SOCKET:
            handle_socket(pid, fd, out);
            break;
    };
    //switch ((int)(vip->vip_vi.vi_stat.vst_mode & S_IFMT)) {

    return out;
}

#if 0
static int proc_wrapper_exec(PyObject *module) 
{
    printf("proc_wrapper_exec mod=%p\n", module);
    return 0;
}
#endif

static PyMethodDef proc_wrapper_methods[] = {
    {"get_fd_info", (PyCFunction) get_fd_info, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL} 
};

static PyModuleDef_Slot proc_wrapper_slots[] = {
    //{Py_mod_exec, proc_wrapper_exec},
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
    {0, NULL}
};

static struct PyModuleDef proc_wrapper_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "proc_wrapper",
    .m_doc  = "docstring FIXME",
    .m_size = 0, 
    .m_slots = proc_wrapper_slots,
    .m_methods = proc_wrapper_methods
};

PyMODINIT_FUNC PyInit_proc_wrapper(void) {
    return PyModuleDef_Init(&proc_wrapper_module);
}

