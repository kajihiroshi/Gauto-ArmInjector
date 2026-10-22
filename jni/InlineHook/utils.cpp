#include "utils.h"
#include "Ihook.h"
#include <pthread.h>

pthread_mutex_t mutex;

void report_hex(uint8_t* buf, size_t len)
{
    pthread_mutex_lock(&mutex);

    unsigned remain_length = len;
	char hex_line[100] = "";
	while (remain_length > 0)
	{
		unsigned hex_length = remain_length;
		if (remain_length > 16)
			hex_length = 16;

		for (unsigned i = 0; i < hex_length; i++)
		{
			char aa = *(char*)buf;
			buf++;
			char temp[10];
			sprintf(temp, "%02X ", aa);
			strcat(hex_line, temp);
		}
		LOGI("%s", hex_line);
		remain_length -= hex_length;
		strcpy(hex_line, "");
	}

    pthread_mutex_unlock(&mutex);
}

void fwrite_hex(FILE* fp, uint8_t* buf, size_t len)
{
    pthread_mutex_lock(&mutex);

    unsigned remain_length = len;
	char hex_line[100] = "";
	while (remain_length > 0)
	{
		unsigned hex_length = remain_length;
		if (remain_length > 16)
			hex_length = 16;

		for (unsigned i = 0; i < hex_length; i++)
		{
			char aa = *(char*)buf;
			buf++;
			char temp[10];
			sprintf(temp, "%02X ", aa);
			strcat(hex_line, temp);
		}
        fwrite(hex_line, 1, strlen(hex_line), fp);
        char enter = '\n';
        fwrite(&enter, 1, 1, fp);
		remain_length -= hex_length;
		strcpy(hex_line, "");
	}

    pthread_mutex_unlock(&mutex);
}

void dump_file(char* fileName, uint8_t* buffer, size_t len)
{
	FILE* fp = fopen(fileName, "wb+");
	if (fp == NULL)
	{
		LOGI("fopen failed name=%s", fileName);
		return;
	}

	fwrite(buffer, 1, len, fp);
	fclose(fp);
	LOGI("dump file success name=%s, len=0x%lx", fileName, len);
}

float uint_to_float(unsigned value)
{
    union FloatOrUInt
    {
        float asFloat;
        unsigned int asUInt;
    } fu;

    fu.asUInt = value;
    return fu.asFloat;
}

unsigned float_to_uint(float value)
{
    union FloatOrUInt
    {
        float asFloat;
        unsigned int asUInt;
    } fu;

    fu.asFloat = value;
    return fu.asUInt;
}

unsigned char16len(uint16_t* array)
{
    unsigned len = 0;
    while (array[len])
    {
        len++;
    }
    return len;
}

char* char16_to_char(uint16_t* array)
{
    unsigned len = char16len(array);
    char* result = new char[len + 1];
    for (unsigned i = 0; i < len; i++)
    {
        result[i] = array[i] & 0xFF;
    }
    result[len] = '\0';
    return result;
}

uint16_t* char_to_char16(char* array)
{
	unsigned len = strlen(array);
	uint16_t* result = new uint16_t[len + 1];
	for (unsigned i = 0; i < len; i++)
	{
		result[i] = array[i];
	}
	result[len] = '\0';
	return result;
}

void fwrite_char16(FILE* fp, uint16_t* buffer)
{
	unsigned len = char16len(buffer);
	fwrite(buffer, 2, len, fp);
}

void fwrite_char16(FILE* fp, uint16_t* buffer, unsigned len)
{
	fwrite(buffer, 2, len, fp);
}