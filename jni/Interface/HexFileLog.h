/*
 * HexFileLog.h - write bytes to a .txt file as hex, 16 values per line,
 * with the current date and time at the start of EVERY line:
 *
 *   [2026-10-25 14:03:07.123] 00000000: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
 *
 * Builds on the other helpers instead of repeating them:
 *   HexDump.h - turns the bytes into lines of 16 hex values.
 *   FileIO.h  - writes the finished text to the file.
 *
 * This is a header-only file: every function is defined here as `inline`,
 * so you only need to `#include "HexFileLog.h"` - no extra .cpp file and no
 * change to Android.mk is required.
 */
#ifndef HEX_FILE_LOG_H
#define HEX_FILE_LOG_H

#include <stdio.h>
#include <string>
#include <sys/time.h>
#include <time.h>
#include <vector>

#include "FileIO.h"
#include "HexDump.h"

/*
 * GetDateTime
 * -----------
 * Returns the current LOCAL date and time (the phone's time zone) as text:
 *
 *   "2026-10-25 14:03:07.123"   (year-month-day hour:minute:second.milliseconds)
 *
 * The milliseconds make it possible to tell apart lines written within
 * the same second.
 *
 * Parameters: none.
 *
 * Returns:
 *   The date/time string. If the clock cannot be read it returns
 *   "0000-00-00 00:00:00.000" instead of failing.
 *
 * Example:
 *   LOGI("now: %s", GetDateTime().c_str());
 */
inline std::string GetDateTime()
{
  struct timeval now;
  struct tm local;
  if (gettimeofday(&now, NULL) != 0 || localtime_r(&now.tv_sec, &local) == NULL)
  {
    return "0000-00-00 00:00:00.000";
  }

  char date[32];
  strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &local);

  // strftime has no milliseconds, so add them from tv_usec (microseconds).
  char result[40];
  snprintf(result, sizeof(result), "%s.%03ld", date, (long)(now.tv_usec / 1000));
  return result;
}

/*
 * WriteHexDumpToFile
 * ------------------
 * Writes `size` bytes to a .txt file as hex, 16 values per line, and puts
 * the current date/time in front of every line. One line in the file:
 *
 *   showOffset = false:  [2026-10-25 14:03:07.123] 00 11 22 ... FF
 *   showOffset = true :  [2026-10-25 14:03:07.123] 00000010: 00 11 22 ... FF
 *
 * The time is read once per line, so a long dump shows how long it took.
 * All lines are collected first and written in ONE file write, so the
 * file never ends up with half a dump if the game is busy.
 *
 * Parameters:
 *   path       - full path of the .txt file, e.g.
 *                "/data/data/<package>/files/hex.txt". The folder must exist.
 *   data       - pointer to the first byte to write (any data type).
 *   size       - number of bytes to write. 100 bytes -> 6 full lines + 1 line
 *                of 4 values.
 *   showOffset - true: add the position of each line's first byte
 *                ("00000010: "), handy for long dumps.
 *   append     - false: OVERWRITE - the file holds only this dump.
 *                true : APPEND    - add this dump to the end of the file,
 *                                   older dumps are kept.
 *
 * Returns:
 *   true  - all lines were written.
 *   false - nothing to write (data is NULL or size is 0), or the file could
 *           not be written (folder missing / no permission / disk full).
 *
 * Example:
 *   unsigned char buf[128] = {...};
 *   if (!WriteHexDumpToFile("/data/data/pkg/files/hex.txt", buf, sizeof(buf), true, true))
 *     LOGI("hex write failed");
 *
 * Note: only pass memory that is really readable. Dumping a bad address
 * (e.g. an unmapped game pointer) crashes the process.
 */
inline bool WriteHexDumpToFile(const char *path, const void *data, size_t size,
                               bool showOffset, bool append)
{
  std::vector<std::string> lines = HexDump(data, size, showOffset);
  if (lines.empty())
  {
    return false;
  }

  std::string text;
  for (size_t i = 0; i < lines.size(); i++)
  {
    text += "[" + GetDateTime() + "] " + lines[i] + "\n";
  }
  return WriteTextFile(path, text, append);
}

#endif
