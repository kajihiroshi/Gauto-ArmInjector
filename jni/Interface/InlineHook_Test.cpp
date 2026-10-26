#include <vector>
#include <fstream>
#include <sys/socket.h>
#include "utils.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sstream>
#include <strings.h>
#include <time.h>

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

// Header-only helper library (read/write text files, timestamped hex dumps,
// module lookup, SumOneToHundred). See GautoUtils.h for full per-function docs.
#include "GautoUtils.h"

#define qword_value(_var_) *((unsigned long *)((unsigned long)(_var_)))
#define dword_value(_var_) *((unsigned *)((unsigned long)(_var_)))
#define word_value(_var_) *((unsigned short *)((unsigned long)(_var_)))
#define byte_value(_var_) *((unsigned char *)((unsigned long)(_var_)))
#define float_value(_var_) *((float *)((unsigned long)(_var_)))

typedef std::vector<INLINE_HOOK_INFO *> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;

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

void *my_hook_thread(void *arg)
{
  LOGI("hook_thread start %s", "");
  sleep(0);

  uint64_t endAddr;
  char library_name[] = "libil2cpp.so";
  unsigned libhooked = 0;

  // Self-test: sum of 1..100 (expect 5050).
  LOGI("sum 1..100 = %d", SumOneToHundred());

  // Self-test: use the ModuleInfo struct.
  ModuleInfo stInfo;
  GetModuleInfo("libc.so", &stInfo);

  // Self-test: dump 100+ bytes as hex, 16 values per line, via existing utils.
  {
    uint8_t hexbuf[137];
    for (unsigned i = 0; i < sizeof(hexbuf); i++)
      hexbuf[i] = (uint8_t)i;

    LOGI("report_hex self-test (%zu bytes, 16/line):", sizeof(hexbuf));
    report_hex(hexbuf, sizeof(hexbuf));

    FILE *fpHex = fopen("/data/local/tmp/gauto_hex_test.txt", "wb");
    if (fpHex)
    {
      fwrite_hex(fpHex, hexbuf, sizeof(hexbuf));
      fclose(fpHex);
      LOGI("fwrite_hex self-test -> /data/local/tmp/gauto_hex_test.txt");
    }

    // Write the same 100+ values with a date-time stamp on every line.
    WriteValuesWithTimestamp("/data/local/tmp/gauto_ts_test.txt",
                             hexbuf, sizeof(hexbuf), false);
  }

  // Self-test: verify ReadTextFile / WriteTextFile work on-device.
  const char *pszTestPath = "/data/local/tmp/gauto_fileio_test.txt";
  if (WriteTextFile(pszTestPath, "gauto file io test line 1\n", false) &&
      WriteTextFile(pszTestPath, "appended line 2\n", true))
  {
    std::string strReadBack = ReadTextFile(pszTestPath);
    LOGI("fileio self-test readback (%zu bytes):\n%s",
         strReadBack.size(), strReadBack.c_str());
  }
  else
  {
    LOGI("fileio self-test: write failed, path=%s", pszTestPath);
  }

  while (true)
  {
    if (libhooked == 0)
    {
      find_address(library_name, g_modulebase1, endAddr);
      if (g_modulebase1 != 0)
      {
        LOGI("libdxbase g_modulebase1=%lx", g_modulebase1);
        break;
      }
    }
    sleep(1);
  }
  return NULL;
}

void __attribute__((constructor)) libhook_main()
{
  LOGI("LIBRARY LOADED FROM PID  BNS OK %d.", getpid());
  pthread_t thread;
  pthread_create(&thread, NULL, my_hook_thread, NULL);
}