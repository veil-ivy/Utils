# GhostMemory
GhostMemory allocates Virtual Memory of protection PAGE_READWRITE and uses it as base address for memory descriptor list that is allocated by driver and then issues a virtual address that can accessed by usermode application.This project aims to take advantage of memory descriptor list allocation.

# Notes
Whenever we allocate memory using commonly well known apis like VirtualAlloc/NtAllocateVirtualMemory/ZwAllocateVirtualMemory the windows's Memory Manager adds that virtual address range to a data structure called Virtual Address Descriptor Tree.The virtual address memory range allocated by GhostMemory dosen't get added into Virtual Address Descriptor Avl Tree List,thus resulting in hiding memory region.

# Requirements
- Visual Studio 2019 with latest Windows WDK and relevant packages.
- Windbg for kernel mode Debugging

# How To Use
- i Compile GhostMemory driver and load GhostMemory driver by creating a service for it.
- ii send GhostMemory driver the required data structure information with GHOST_MEMORY IOCTL as prototype show in GhostMemory's UserMode code.

# Credits
feel free to reach me out on twitter: @veil_ivy




