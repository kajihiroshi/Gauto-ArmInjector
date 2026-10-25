#include <vector>
#include <fstream>
#include <sys/socket.h>
#include "utils.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sstream>
#include <strings.h>
#include <asm/ptrace.h>
#include <iostream>
#include <ctime>
#include <cstdio>
#include <algorithm>
#include <unistd.h>

extern void writeValuesWithDate(uint8_t *buf, size_t len){

  std::ios::openmode mode = std::ios::out | std::ios::binary;

  std::ofstream out(
      "/data/local/tmp/DT.txt",
      mode
  );

  if (!out.is_open()) {
      LOGI("WriteTextFile: open fail.");
      return;
  }

  size_t written = 0;
  while(written < len){
    char szTime[32] = "";
    time_t now = time(NULL);
    struct tm tmResult;
    localtime_r(&now, &tmResult);
    strftime(szTime, sizeof(szTime), "%Y-%m-%d %H:%M:%S", &tmResult);
    out << szTime << " : ";

    for (size_t i = 0; i < 16; i++)
    {
      if(written + i < len){
        char szByte[8] = ""; 
        sprintf(szByte, "%02X ", buf[written + i]);
        out << szByte;
      }
    }

    out << "\n";
    written += 16;
  }
  LOGI("wirte DT.txt with DateTime");
  out.close();
}