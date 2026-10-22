#include "myhook.h"
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>
#include "Ihook.h"


unsigned long libhook_writeMemory( unsigned long address, void* buf, unsigned size)
{
    if (ChangePageProperty((void*)address, size) == false)
        return 0;
    unsigned long orgapiaddr = *(unsigned long*)(address);    

    memcpy((unsigned long*)address, buf, size);

    return orgapiaddr;
}

unsigned long  hex2longl(char *hex) {
    unsigned long val = 0;

    while (*hex) {
        // get current character then increment
        uint8_t byte = *hex++;         
        if (byte == '-')
            break;
        // transform hex character to the 4bit equivalent number, using the ascii table indexes
        if (byte >= '0' && byte <= '9') byte = byte - '0';
        else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
        else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;    

        // shift 4 to make space for new digit, and add the 4 bits of the new digit 
        val = (val << 4) | (byte & 0xF);
    }
    return val;
}

void libhook_get_libue4_addr(unsigned long  *startAddr, unsigned long  *endAddr) {
    char buffer[1024] = {0};
    //ulongptr_t address;

    unsigned blockStep = 0;
    unsigned catchStep = 0;

    *startAddr = 0;
    *endAddr = 0;

    FILE *fp = fopen( "/proc/self/maps", "rt" );
    if( fp == NULL ){
        perror("fopen");
        goto done;
    }

    while( fgets( buffer, sizeof(buffer), fp ) ) {
        //LOGI( "map line. buffer: %s", buffer );
        if(strstr(buffer, "libUE4.so") ) {
            LOGI( "get_libue4_addr. startAddr: %x", 1);
            *startAddr = hex2longl(buffer);
            break;
        }
    }

    done:

    if(fp){
        fclose(fp);
    }
}