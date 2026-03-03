"""Setup file for strace-macos."""

import setuptools

miniproc = setuptools.Extension(
    "miniproc",
    sources=["strace_macos/miniproc.cpp"],
    extra_compile_args=['-g','-O0'],
    macros=[],
    undef_macros = [ "NDEBUG" ],
    #library_dirs=['../lib'],
    #libraries=["lsof"],
    #extra_compile_args=['-g','-O0'],
    #extra_objects=objects
)

kwargs = dict(ext_modules=[miniproc])

setuptools.setup(**kwargs)

