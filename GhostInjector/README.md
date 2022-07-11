# GhostInjector
GhostInjector attempts to hide VAD regions for an injected shellcode/DLL/Payload etc...
# How does this work ?
 code is pretty self explainatory, I don't do spoon feeding :)

# Requirements
-  Visual Studio 2019 with latest Windows WDK and relevant packages.
-  Windbg for kernel mode Debugging

# How to use
- 1. Compile ghost_injector driver and load ghost_injector driver by creating its service.
- 2. send IOCTL CONTROL CODE with KGHOST_INJECTOR with xghost_mem structure
