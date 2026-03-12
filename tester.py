
import pprint
import miniproc 

print('miniproc file: ', miniproc.__file__)
print()

pprint.pp(miniproc.get_fd_info(77538, 5))
print()

pprint.pp(miniproc.get_fd_info(77538, 7))
print()

pprint.pp(miniproc.get_fd_info(85499, 3))
print()

pprint.pp(miniproc.get_fd_info(73846, 11))
print()

pprint.pp(miniproc.get_fd_info(73846, 20))
print()

pprint.pp(miniproc.get_fd_info(73846, 1))
print()

pprint.pp(miniproc.get_fd_info(73846, 3))
print()

pprint.pp(miniproc.get_fd_info(78793, 1))
print()

pprint.pp(miniproc.get_fd_info(78793, 2))
print()
