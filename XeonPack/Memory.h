#ifndef MEMORY_H
#define MEMORY_H
#include <Windows.h>
#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)
#define MemAlloc(dwbytes) (HeapAlloc(GetProcessHeap(),HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY,dwbytes))
#define MemReAlloc(Mem,dwbytes) (HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,Mem,dwbytes))
#define MemFree(Mem) (HeapFree(GetProcessHeap(),0,Mem))
#define VMAlloc(dwbytes)(VirtualAlloc(NULL,dwbytes,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE))
#define VMFree(VMEM)  (VirtualFree(VMEM,NULL,MEM_FREE))
#define ZEROMEM(mem,size)(ZeroMemory(mem,size))

//#define VMReAlloc()

#endif