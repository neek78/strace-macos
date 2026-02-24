import psutil

#from strace_macos.syscalls.definitions import DecodeContext

from dataclasses import dataclass, field

class Annotation():
    pass

@dataclass
class FDAnnotation(Annotation):
    path: str

    def __str__(self) -> str:
        return self.path 

    def value(self):
        """get the contents of this annotation in an appropriate form for json outout"""
        return self.path 

#def annotate_fd(ctx: DecodeContext, fd: int) -> FDAnnotation:
def annotate_fd(ctx, fd: int) -> FDAnnotation:
    pid = ctx.process.id
    proc = psutil.Process(pid)

    for f in proc.open_files():
        if f.fd == fd:
            return FDAnnotation(path = f.path)
    return None
