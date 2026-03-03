"""Setup file for strace-macos."""

import setuptools

proc_wrapper = setuptools.Extension(
    "proc_wrapper",
    sources=["strace_macos/proc_wrapper.cpp"],
    #library_dirs=['../lib'],
    #libraries=["lsof"],
    #extra_compile_args=['-g','-O0'],
    #extra_objects=objects
)

kwargs = dict(ext_modules=[proc_wrapper])

setuptools.setup(**kwargs)

