#ifndef UTILS_H
#define UTILS_H

#include <iostream>

void report_hex(uint8_t* buf, size_t len);
void fwrite_hex(FILE* fp, uint8_t* buf, size_t len);
void dump_file(char* fileName, uint8_t* buffer, size_t len);
float uint_to_float(unsigned value);
unsigned float_to_uint(float value);
unsigned char16len(uint16_t* array);
char* char16_to_char(uint16_t* array);
uint16_t* char_to_char16(char* array);
void fwrite_char16(FILE* fp, uint16_t* buffer);
void fwrite_char16(FILE* fp, uint16_t* buffer, unsigned len);

#endif
