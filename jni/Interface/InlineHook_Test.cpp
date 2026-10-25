#include <vector>
#include <fstream>
#include <sys/socket.h>
#include "utils.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sstream>
#include <strings.h>
#include "FileIO.h"
#include "HexDump.h"
#include "HexFileLog.h"
#include "SumCalc.h"

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

/*
 * TestFileIO
 * ----------
 * Demo of FileIO.h: writes user text to a .txt file, appends one more line,
 * then reads the file back (whole and line by line) and logs the result.
 * Check the output with:  adb logcat | grep <LOG_TAG>
 * Change `path` / `userText` to write your own file and text.
 */
void TestFileIO()
{
  const char *path = "/data/data/com.asobimo.EternalOfficial/files/gauto_test.txt";
  std::string userText = "Hello from Gauto ArmInjector\n";

  // Overwrite the file with the first line, then append a second one.
  if (!WriteTextFile(path, userText, false))
  {
    LOGI("WriteTextFile failed: %s", path);
    return;
  }
  WriteTextFile(path, "Appended line\n", true);

  std::string content;
  if (ReadTextFile(path, content))
  {
    LOGI("ReadTextFile:\n%s", content.c_str());
  }

  std::vector<std::string> lines;
  if (ReadTextLines(path, lines))
  {
    for (size_t i = 0; i < lines.size(); i++)
    {
      LOGI("ReadTextLines[%zu]: %s", i, lines[i].c_str());
    }
  }
}

/*
 * TestHexDump
 * -----------
 * Demo of HexDump.h, 16 hex values per line:
 *   1) the bytes of the text in `userText` (change it to your own text),
 *   2) `byteCount` bytes counting 00, 01, 02 ... (128 -> 8 full lines),
 *      to show 100+ values including 80..FF.
 * Check the output with:  adb logcat -s LIBHOOK
 */
void TestHexDump()
{
  std::string userText = "Hello from Gauto ArmInjector";
  LOGI("HexDump of \"%s\" (%zu bytes):", userText.c_str(), userText.size());
  std::vector<std::string> lines = HexDump(userText.data(), userText.size(), false);
  for (size_t i = 0; i < lines.size(); i++)
  {
    LOGI("%s", lines[i].c_str());
  }

  const size_t byteCount = 128;
  std::vector<unsigned char> buffer(byteCount);
  for (size_t i = 0; i < byteCount; i++)
  {
    buffer[i] = (unsigned char)i;
  }
  LOGI("HexDump of %zu counting bytes:", byteCount);
  lines = HexDump(&buffer[0], buffer.size(), true);
  for (size_t i = 0; i < lines.size(); i++)
  {
    LOGI("%s", lines[i].c_str());
  }
}

/*
 * TestHexFileLog
 * --------------
 * Demo of HexFileLog.h: writes 256 RANDOM bytes to a .txt file as
 * 16 lines of 16 hex values, each line starting with the date and time.
 * The random generator is seeded with the time and process id, so every
 * game start writes different values.
 * The file is APPENDED, so every game start adds a new block with a new
 * time. The file is then read back and logged.
 * Check the file with:
 *   adb shell su -c cat /data/data/com.asobimo.EternalOfficial/files/gauto_hex.txt
 */
void TestHexFileLog()
{
  const char *path = "/data/data/com.asobimo.EternalOfficial/files/gauto_hex.txt";

  const size_t byteCount = 256;
  std::vector<unsigned char> buffer(byteCount);
  srand((unsigned)time(NULL) ^ (unsigned)getpid());
  for (size_t i = 0; i < byteCount; i++)
  {
    buffer[i] = (unsigned char)(rand() & 0xFF);
  }

  if (!WriteHexDumpToFile(path, &buffer[0], buffer.size(), true, true))
  {
    LOGI("WriteHexDumpToFile failed: %s", path);
    return;
  }

  std::vector<std::string> lines;
  if (ReadTextLines(path, lines))
  {
    LOGI("%s now has %zu lines:", path, lines.size());
    for (size_t i = 0; i < lines.size(); i++)
    {
      LOGI("%s", lines[i].c_str());
    }
  }
}

void *my_hook_thread(void *arg)
{
  LOGI("hook_thread start %s", "");
  sleep(0);

  uint64_t endAddr;
  char library_name[] = "libil2cpp.so";
  unsigned libhooked = 0;

  while (true)
  {
    if (libhooked == 0)
    {
      find_address(library_name, g_modulebase1, endAddr);
      if (g_modulebase1 != 0)
      {
        LOGI("libdxbase g_modulebase1=%lx", g_modulebase1);
        TestFileIO();
        TestHexDump();
        TestHexFileLog();
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

  // Sum 1..100 (expected 5050). Runs as soon as libzc.so is loaded.
  // In IDA Pro: open libzc.so -> Exports -> SumRange.
  int sum = SumRange(1, 100);
  LOGI("SumRange(1, 100) = %d", sum);

  pthread_t thread;
  pthread_create(&thread, NULL, my_hook_thread, NULL);
}