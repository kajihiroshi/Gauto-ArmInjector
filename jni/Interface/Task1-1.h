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

extern "C"
{
#include "Ihook.h"
}

//reand any text and write
extern void openAndWriteFile(){

  const std::string filename = "/data/local/tmp/1.txt";
  std::string strContent;

  std::ifstream in(filename.c_str(), std::ios::binary | std::ios::in);
  if (!in.is_open()) {
      LOGI("ReadTextFile: open fail. path=%s errno=%d", filename.c_str(), errno);
      return;
  }

  std::stringstream ss;
  ss << in.rdbuf();
  strContent = ss.str();
  in.close();

  std::ios::openmode mode = std::ios::out | std::ios::binary;

  std::ofstream out(
      "/data/local/tmp/2.txt",
      mode
  );

  if (!out.is_open()) {
      LOGI("WriteTextFile: open fail. path=%s", filename.c_str());
      return;
  }

  out << strContent;
  bool bRet = out.good();
  out.close();
}