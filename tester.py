#!/Users/nick/inst/python.debug/bin/python3

#import IPython 
import pprint
import miniproc 

print('miniproc file: ', miniproc.__file__)
print()

for i in range(8):
    pprint.pp(miniproc.get_fd_info(6743, i))
    print("yep", i)

