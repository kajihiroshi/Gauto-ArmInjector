#ifndef HOOK_H
#define HOOK_H 1

unsigned long libhook_replace_func( unsigned long address, unsigned long newFunc);
void libhook_get_libue4_addr(unsigned long  *startAddr, unsigned long  *endAddr);
unsigned long libhook_writeMemory( unsigned long address, void* buf, unsigned size);
#endif
