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

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_START(addr) (~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr) (addr | 1)
#define CLEAR_BIT0(addr) (addr & 0xFFFFFFFE)
#define TEST_BIT0(addr) (addr & 1)

#define ACTION_ENABLE 0
#define ACTION_DISABLE 1

extern "C"
{
#include "Ihook.h"
#include "myhook.h"
}

#define qword_value(_var_) *((unsigned long *)((unsigned long)(_var_)))
#define dword_value(_var_) *((unsigned *)((unsigned long)(_var_)))
#define word_value(_var_) *((unsigned short *)((unsigned long)(_var_)))
#define byte_value(_var_) *((unsigned char *)((unsigned long)(_var_)))
#define float_value(_var_) *((float *)((unsigned long)(_var_)))

typedef std::vector<INLINE_HOOK_INFO *> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;

struct AddressModel
{
  uint64_t startAdd;
  uint64_t endAdd;
};

bool InlineHook(void *pHookAddr, void (*onCallBack)(struct user_pt_regs *))
{
  bool bRet = false;
  LOGI("InlineHook");

  if (pHookAddr == NULL || onCallBack == NULL)
  {
    return bRet;
  }

  INLINE_HOOK_INFO *pstInlineHook = new INLINE_HOOK_INFO();
  pstInlineHook->pHookAddr = pHookAddr;
  pstInlineHook->onCallBack = onCallBack;

  if (HookArm(pstInlineHook) == false)
  {
    LOGI("HookArm fail.");
    delete pstInlineHook;
    return bRet;
  }

  gs_vecInlineHookInfo.push_back(pstInlineHook);
  return true;
}

bool UnInlineHook(void *pHookAddr)
{
  bool bRet = false;

  if (pHookAddr == NULL)
  {
    return bRet;
  }

  InlineHookInfoPVec::iterator itr = gs_vecInlineHookInfo.begin();
  InlineHookInfoPVec::iterator itrend = gs_vecInlineHookInfo.end();

  for (; itr != itrend; ++itr)
  {
    if (pHookAddr == (*itr)->pHookAddr)
    {
      INLINE_HOOK_INFO *pTargetInlineHookInfo = (*itr);

      gs_vecInlineHookInfo.erase(itr);
      if (pTargetInlineHookInfo->pStubShellCodeAddr != NULL)
      {
        delete pTargetInlineHookInfo->pStubShellCodeAddr;
      }
      if (pTargetInlineHookInfo->ppOldFuncAddr)
      {
        delete *(pTargetInlineHookInfo->ppOldFuncAddr);
      }
      delete pTargetInlineHookInfo;
      bRet = true;
    }
  }

  return bRet;
}

uint64_t g_modulebase = 0;
uint64_t g_modulebase1 = 0;

void find_address(char *soname, uint64_t &startAddr, uint64_t &endAddr)
{
  int step = 0;
  char buffer[1024] = "";

  FILE *fp = fopen("/proc/self/maps", "rt");
  if (fp == NULL)
  {
    perror("fopen");
    goto done;
  }

  while (fgets(buffer, sizeof(buffer), fp))
  {
    if (strstr(buffer, soname))
    {
      step++;
      LOGI("%s", buffer);
      if (step == 1)
      {
        startAddr = strtoul(buffer, NULL, 16);
        LOGI("startAddr=0x%lx", startAddr);
      }
      else if (step == 3)
      {
        endAddr = strtoul(strchr(buffer, '-') + 1, NULL, 16);
        LOGI("endAddr=0x%lx", endAddr);
      }
    }
  }

  done:

    if (fp)
    {
      fclose(fp);
    }
}

void on_hit(struct user_pt_regs *regs)
{
    // x0..x30
    LOGI("x0=0x%llx x1=0x%llx x2=0x%llx", regs->regs[0], regs->regs[1], regs->regs[2]);
    LOGI("x30(lr)=0x%llx sp=0x%llx pc=0x%llx", regs->regs[30], regs->sp, regs->pc);
}

void on_hit1(struct user_pt_regs *regs)
{
    // x0..x30
    // LOGI("x0=0x%llx x1=0x%llx x2=0x%llx", regs->regs[0], regs->regs[1], regs->regs[2]);
    LOGI("product_x30(lr)=0x%llx product_sp=0x%llx product_pc=0x%llx", regs->regs[30], regs->sp, regs->pc);
}

void writeValuesWithDate(uint8_t *buf, size_t len){

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

void *my_hook_thread(void *arg)
{
  LOGI("hook_thread start %s", "");
  sleep(0);

  uint64_t endAddr;
  char library_name[] = "libil2cpp.so";
  unsigned libhooked = 0;

  {
    uint8_t hexbuf[100];
    for (unsigned i = 0; i < sizeof(hexbuf); i++)
      hexbuf[i] = (uint8_t)i;

    LOGI("report_hex self-test (%zu bytes, 16/line):", sizeof(hexbuf));
    report_hex(hexbuf, sizeof(hexbuf));

    FILE *fpHex = fopen("/data/local/tmp/hex.txt", "wb");
    if (fpHex)
    {
      fwrite_hex(fpHex, hexbuf, sizeof(hexbuf));
      fclose(fpHex);
      LOGI("fwrite_hex self-test -> /data/local/tmp/hex.txt");
    }

    writeValuesWithDate(hexbuf, sizeof(hexbuf));
  }

  AddressModel *addModel = new AddressModel();
  addModel->startAdd = 0;
  addModel->endAdd = 0;
  while (true)
  {
    if (libhooked == 0)
    {
      // find_address(library_name, addModel->startAdd, addModel->endAdd);
      find_address(library_name, g_modulebase1, endAddr);
      if (g_modulebase1 != 0)
      {
        LOGI("libdxbase g_modulebase1=%lx", g_modulebase1);
        LOGI("Insert Code1 by GruLucy. Get Arm64 Registers Value. Start Signal");
        uint64_t target = g_modulebase1 + 0x3279AB4;
        InlineHook((void *)target, on_hit);
        LOGI("Insert Code2 by GruLucy. Get Arm64 Registers Value. Login Signal");
        uint64_t target1 = g_modulebase1 + 0x327AD1C;
        InlineHook((void *)target1, on_hit);

        LOGI("Insert Code2 by GruLucy. Get Arm64 Registers Value. GetPruductData Signal");
        uint64_t target2 = g_modulebase1 + 0x327E6A8;
        InlineHook((void *)target2, on_hit1);
        break;
      }
    }
    sleep(1);
  }
  return NULL;
}

void openAndWriteFile(){

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

int Sum()
{
  int sum = 0;
  for (int i = 1; i <= 100; i++)
  {
    sum += i;
  }
  return sum;
}

void __attribute__((constructor)) libhook_main()
{
  LOGI("LIBRARY LOADED FROM PID  BNS OK %d.", getpid());

  openAndWriteFile();

  LOGI("Sum = %d", Sum());

  pthread_t thread;
  pthread_create(&thread, NULL, my_hook_thread, NULL);
}