#ifndef GAUTO_UTILS_H
#define GAUTO_UTILS_H

/* ===========================================================================
 * GautoUtils.h
 * ---------------------------------------------------------------------------
 * A small, self-contained collection of helper functions used by the
 * Gauto-ArmInjector project.
 *
 * HOW TO USE THIS FILE
 *   This is a "header-only" library: every function is fully implemented
 *   right here, so you only need to:
 *       #include "GautoUtils.h"
 *   You do NOT need to add any .cpp file to the build or change any Makefile.
 *
 * REQUIREMENTS
 *   - C++ (the file uses std::string / std::fstream).
 *   - Built for Android/Linux (GetModuleInfo reads "/proc/self/maps").
 *
 * LOGGING
 *   Every function prints a short progress/result line through GAUTO_LOGI.
 *   - On Android it goes to logcat under the tag "GAUTO" (view it with:
 *         adb logcat -s GAUTO
 *     ).
 *   - On any other platform it falls back to printf on stdout.
 *   You can silence or redirect logging by #define-ing GAUTO_LOGI yourself
 *   BEFORE including this header.
 * ===========================================================================
 */

#include <string>    /* std::string                         */
#include <fstream>   /* std::ifstream / std::ofstream        */
#include <sstream>   /* std::stringstream                    */
#include <stdint.h>  /* uint8_t, uint64_t                    */
#include <stddef.h>  /* size_t                               */
#include <stdio.h>   /* FILE, fopen, fgets, sprintf          */
#include <string.h>  /* strncpy, strstr, strchr              */
#include <stdlib.h>  /* strtoul                              */
#include <errno.h>   /* errno                                */
#include <time.h>    /* time, localtime_r, strftime          */

/* ---------------------------------------------------------------------------
 * GAUTO_LOGI : internal logging macro (printf-style formatting).
 * Define your own before including this header to override it.
 * ------------------------------------------------------------------------- */
#ifndef GAUTO_LOGI
  #if defined(__ANDROID__)
    #include <android/log.h>
    #define GAUTO_LOGI(...) __android_log_print(ANDROID_LOG_INFO, "GAUTO", __VA_ARGS__)
  #else
    #define GAUTO_LOGI(...) printf(__VA_ARGS__)
  #endif
#endif


/* ===========================================================================
 * ReadTextFile
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Read the ENTIRE contents of a text file into memory.
 *
 * INPUT
 *   pszPath : C-string, full path to the file to read.
 *             Example: "/data/local/tmp/notes.txt"
 *             May be NULL (handled safely -> returns "").
 *
 * OUTPUT (return value)
 *   std::string containing the whole file, byte-for-byte (newlines kept).
 *   - On success : the file content. Use .c_str() for a C-string, or
 *                  .size() for the length in bytes.
 *   - On failure : an EMPTY string ("") and an error line is logged.
 *     NOTE: an empty return can also mean the file simply was empty; if you
 *     must tell the two apart, check that the file exists first.
 *
 * EXAMPLE
 *   std::string text = ReadTextFile("/sdcard/in.txt");
 *   GAUTO_LOGI("read %zu bytes", text.size());
 * ========================================================================= */
inline std::string ReadTextFile(const char *pszPath)
{
  std::string strContent;

  if (pszPath == NULL)
  {
    return strContent;
  }

  std::ifstream ifs(pszPath, std::ios::in | std::ios::binary);
  if (!ifs.is_open())
  {
    GAUTO_LOGI("ReadTextFile: open fail. path=%s errno=%d", pszPath, errno);
    return strContent;
  }

  std::stringstream ss;
  ss << ifs.rdbuf();
  strContent = ss.str();
  ifs.close();

  GAUTO_LOGI("ReadTextFile: path=%s size=%zu", pszPath, strContent.size());
  return strContent;
}


/* ===========================================================================
 * WriteTextFile
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Write a string of text to a file.
 *
 * INPUT
 *   pszPath : C-string, full path to the file to write.
 *   pszText : C-string, the text to write. It is written verbatim, so include
 *             any '\n' line breaks you want yourself.
 *   bAppend : true  -> add to the END of the file (create it if missing).
 *             false -> OVERWRITE: truncate the file to empty first (or create).
 *   (pszPath or pszText may be NULL -> the call does nothing, returns false.)
 *
 * OUTPUT (return value)
 *   bool :
 *     true  -> the text was written successfully.
 *     false -> the file could not be opened or the write failed (logged).
 *
 * OUTPUT (side effect / file format)
 *   The file contains exactly the bytes of pszText. No timestamp, no
 *   formatting is added. (If you want a hex dump with timestamps, use
 *   WriteValuesWithTimestamp instead.)
 *
 * EXAMPLE
 *   WriteTextFile("/sdcard/out.txt", "hello\nworld\n", false); // overwrite
 *   WriteTextFile("/sdcard/out.txt", "one more line\n", true); // append
 * ========================================================================= */
inline bool WriteTextFile(const char *pszPath, const char *pszText, bool bAppend)
{
  if (pszPath == NULL || pszText == NULL)
  {
    return false;
  }

  std::ios::openmode mode = std::ios::out | std::ios::binary;
  mode |= bAppend ? std::ios::app : std::ios::trunc;

  std::ofstream ofs(pszPath, mode);
  if (!ofs.is_open())
  {
    GAUTO_LOGI("WriteTextFile: open fail. path=%s errno=%d", pszPath, errno);
    return false;
  }

  ofs << pszText;
  bool bRet = ofs.good();
  ofs.close();

  GAUTO_LOGI("WriteTextFile: path=%s append=%d ok=%d", pszPath, (int)bAppend, (int)bRet);
  return bRet;
}


/* ===========================================================================
 * WriteValuesWithTimestamp
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Write a block of raw byte values to a text file as HEX, laid out
 *   16 values per line, with the current DATE and TIME stamped at the start
 *   of every line. Handy for logging memory dumps that you can match to when
 *   they happened.
 *
 * INPUT
 *   pszPath : C-string, full path to the output .txt file.
 *   pBuf    : pointer to the bytes to write (const uint8_t *).
 *   len     : how many bytes from pBuf to write (size_t).
 *   bAppend : true  -> add to the END of the file (create if missing).
 *             false -> OVERWRITE the file first.
 *   (pszPath or pBuf may be NULL -> does nothing, returns false.)
 *
 * OUTPUT (return value)
 *   bool : true on success, false if the file could not be opened / written.
 *
 * OUTPUT (file format)
 *   One line per group of up to 16 bytes:
 *
 *     YYYY-MM-DD HH:MM:SS | B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF
 *     YYYY-MM-DD HH:MM:SS | C0 C1 ...
 *
 *   - Each byte is 2 upper-case hex digits followed by one space.
 *   - The last line holds the remainder (e.g. 137 bytes => 8 full lines of 16
 *     plus 1 line of 9).
 *   - The timestamp uses the DEVICE clock and local timezone.
 *
 * EXAMPLE
 *   uint8_t buf[137];
 *   for (int i = 0; i < 137; i++) buf[i] = (uint8_t)i;
 *   WriteValuesWithTimestamp("/data/local/tmp/dump.txt", buf, sizeof(buf), false);
 * ========================================================================= */
inline bool WriteValuesWithTimestamp(const char *pszPath, const uint8_t *pBuf,
                                     size_t len, bool bAppend)
{
  if (pszPath == NULL || pBuf == NULL)
  {
    return false;
  }

  std::ios::openmode mode = std::ios::out | std::ios::binary;
  mode |= bAppend ? std::ios::app : std::ios::trunc;

  std::ofstream ofs(pszPath, mode);
  if (!ofs.is_open())
  {
    GAUTO_LOGI("WriteValuesWithTimestamp: open fail. path=%s errno=%d", pszPath, errno);
    return false;
  }

  size_t written = 0;
  while (written < len)
  {
    /* Timestamp prefix for this line: "YYYY-MM-DD HH:MM:SS | " */
    char szTime[32] = "";
    time_t now = time(NULL);
    struct tm tmResult;
    localtime_r(&now, &tmResult);
    strftime(szTime, sizeof(szTime), "%Y-%m-%d %H:%M:%S", &tmResult);
    ofs << szTime << " | ";

    /* Up to 16 values on this line. */
    size_t lineLen = len - written;
    if (lineLen > 16)
      lineLen = 16;

    for (size_t i = 0; i < lineLen; i++)
    {
      char szByte[8] = "";
      sprintf(szByte, "%02X ", pBuf[written + i]);
      ofs << szByte;
    }
    ofs << "\n";
    written += lineLen;
  }

  bool bRet = ofs.good();
  ofs.close();

  GAUTO_LOGI("WriteValuesWithTimestamp: path=%s bytes=%zu append=%d ok=%d",
             pszPath, len, (int)bAppend, (int)bRet);
  return bRet;
}


/* ===========================================================================
 * SumOneToHundred
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Calculate the sum of all integers from 1 to 100 inclusive. Mostly a
 *   simple self-test / example function.
 *
 * INPUT
 *   (none)
 *
 * OUTPUT (return value)
 *   int : always 5050 (= 1 + 2 + ... + 100).
 *
 * EXAMPLE
 *   int total = SumOneToHundred();   // total == 5050
 * ========================================================================= */
inline int SumOneToHundred()
{
  int sum = 0;
  for (int i = 1; i <= 100; i++)
  {
    sum += i;
  }
  return sum;
}


/* ===========================================================================
 * ModuleInfo  (data structure)
 * ---------------------------------------------------------------------------
 * Holds the location of one shared library (.so) as it is mapped into the
 * current process. Filled in by GetModuleInfo().
 *
 * FIELDS
 *   name[64]  : the library name you searched for (truncated to 63 chars).
 *   startAddr : lowest mapped address of the library (0 if not found).
 *   endAddr   : highest mapped address of the library (0 if not found).
 *
 * The in-memory size of the library is (endAddr - startAddr).
 * ========================================================================= */
struct ModuleInfo
{
  char     name[64];
  uint64_t startAddr;
  uint64_t endAddr;
};


/* ===========================================================================
 * GetModuleInfo
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Find where a shared library (.so) is loaded in the CURRENT process by
 *   scanning "/proc/self/maps", and fill a ModuleInfo with its address range.
 *
 * INPUT
 *   soname : C-string, the library name (or any unique part of its map line).
 *            Example: "libc.so", "libil2cpp.so", "libUE4.so".
 *   pInfo  : pointer to a ModuleInfo you own; it is filled in on success.
 *   (soname or pInfo may be NULL -> does nothing, returns false.)
 *
 * OUTPUT (return value)
 *   bool :
 *     true  -> the library was found; pInfo->startAddr / endAddr are set.
 *     false -> not found (or bad arguments); pInfo->startAddr/endAddr are 0.
 *
 * OUTPUT (via pInfo)
 *   pInfo->name      = the name you searched for.
 *   pInfo->startAddr = first mapped address of the library.
 *   pInfo->endAddr   = last  mapped address of the library.
 *   Size in bytes    = pInfo->endAddr - pInfo->startAddr.
 *
 * NOTES
 *   - Addresses are only valid inside THIS process (they come from
 *     /proc/self/maps).
 *   - endAddr is taken from the end of the library's mappings; if the library
 *     is split across mappings this is the end of the last matching line seen.
 *
 * EXAMPLE
 *   ModuleInfo info;
 *   if (GetModuleInfo("libc.so", &info))
 *       GAUTO_LOGI("libc base = 0x%lx", (unsigned long)info.startAddr);
 * ========================================================================= */
inline bool GetModuleInfo(const char *soname, ModuleInfo *pInfo)
{
  if (soname == NULL || pInfo == NULL)
  {
    return false;
  }

  strncpy(pInfo->name, soname, sizeof(pInfo->name) - 1);
  pInfo->name[sizeof(pInfo->name) - 1] = '\0';
  pInfo->startAddr = 0;
  pInfo->endAddr = 0;

  FILE *fp = fopen("/proc/self/maps", "rt");
  if (fp == NULL)
  {
    GAUTO_LOGI("GetModuleInfo: cannot open /proc/self/maps errno=%d", errno);
    return false;
  }

  char buffer[1024] = "";
  while (fgets(buffer, sizeof(buffer), fp))
  {
    /* Each maps line looks like:
     *   7f1234a000-7f1234b000 r-xp 00000000 fd:00 1234  /path/libc.so
     */
    if (strstr(buffer, soname))
    {
      uint64_t lineStart = strtoull(buffer, NULL, 16);
      char *dash = strchr(buffer, '-');
      uint64_t lineEnd = (dash != NULL) ? strtoull(dash + 1, NULL, 16) : 0;

      if (pInfo->startAddr == 0)
        pInfo->startAddr = lineStart;   /* first matching line  */
      if (lineEnd > pInfo->endAddr)
        pInfo->endAddr = lineEnd;       /* keep the highest end */
    }
  }

  fclose(fp);

  bool bFound = (pInfo->startAddr != 0);
  GAUTO_LOGI("GetModuleInfo: name=%s start=0x%lx end=0x%lx size=%lu found=%d",
             pInfo->name, (unsigned long)pInfo->startAddr,
             (unsigned long)pInfo->endAddr,
             (unsigned long)(pInfo->endAddr - pInfo->startAddr), (int)bFound);
  return bFound;
}

#endif /* GAUTO_UTILS_H */
