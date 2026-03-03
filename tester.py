
import proc_wrapper

print("fd 5")
print(proc_wrapper.get_fd_info(16761, 5))
print("fd 7")
print(proc_wrapper.get_fd_info(16761, 7))
