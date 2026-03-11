
import miniproc 

print('miniproc file: ', miniproc.__file__)
print("fd 5")
print(miniproc.get_fd_info(77538, 5))
print("fd 7")
print(miniproc.get_fd_info(77538, 7))


print(miniproc.get_fd_info(85499, 3))

