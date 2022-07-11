# GhostInjector
Performs APC Injection from kernel to user and hides VAD memory region

# Requirements
-  Visual Studio 2019 with latest Windows WDK and relevant packages.
-  Windbg for kernel mode Debugging

# How to use
- 1. Compile kapc_injector driver and load kapc_injector driver by creating its service.
- 2. send IOCTL CONTROL CODE with KGHOST_INJECTOR with xghost_mem structure
