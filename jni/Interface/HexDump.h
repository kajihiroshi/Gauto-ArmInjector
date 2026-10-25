/*
 * HexDump.h - turn raw bytes into readable hex text, 16 values per line:
 *
 *     00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
 *
 * This is a header-only file: every function is defined here as `inline`,
 * so you only need to `#include "HexDump.h"` - no extra .cpp file and no
 * change to Android.mk is required.
 *
 * The functions only BUILD the text and return it; they do not print.
 * The caller decides where it goes (LOGI, a .txt file via FileIO.h, ...).
 */
#ifndef HEX_DUMP_H
#define HEX_DUMP_H

#include <stdio.h>
#include <string>
#include <vector>

/* Number of byte values shown on one line. */
#define HEX_BYTES_PER_LINE 16

/*
 * HexLine
 * -------
 * Formats a few bytes as ONE line of upper-case hex values separated by a
 * space, e.g. {0x00, 0x1F, 0xAB} -> "00 1F AB".
 *
 * Parameters:
 *   data  - pointer to the first byte. Any data type can be passed
 *           (it is read byte by byte).
 *   count - how many bytes to format. Normally 1..16 (one line); a larger
 *           value still works but gives one long line.
 *
 * Returns:
 *   The formatted line. No trailing space and no '\n' at the end.
 *   Returns "" when data is NULL or count is 0.
 *
 * Example:
 *   unsigned char b[] = {0xDE, 0xAD, 0xBE, 0xEF};
 *   std::string s = HexLine(b, 4);   // "DE AD BE EF"
 */
inline std::string HexLine(const void *data, size_t count)
{
  std::string line;
  if (data == NULL || count == 0)
  {
    return line;
  }

  // Read as UNSIGNED bytes: a signed char would turn 0x80..0xFF into
  // negative numbers and print as "FFFFFF80".
  const unsigned char *bytes = (const unsigned char *)data;
  char hex[4];
  for (size_t i = 0; i < count; i++)
  {
    snprintf(hex, sizeof(hex), "%02X", bytes[i]);
    if (i > 0)
    {
      line += ' ';
    }
    line += hex;
  }
  return line;
}

/*
 * HexDump
 * -------
 * Splits a buffer of ANY length into lines of 16 hex values each
 * (the last line holds whatever is left, e.g. 100 bytes -> 6 full lines
 * + 1 line of 4 values).
 *
 * Parameters:
 *   data       - pointer to the first byte to show.
 *   size       - total number of bytes to show.
 *   showOffset - false: each line is only the values
 *                       "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"
 *                true : each line starts with the position of its first
 *                       byte, which helps when reading long dumps
 *                       "00000010: 00 11 22 33 ..."
 *
 * Returns:
 *   A vector with one string per line. Empty when data is NULL or size is 0.
 *
 * Example (print every line to logcat):
 *   std::vector<std::string> lines = HexDump(buffer, 128, true);
 *   for (size_t i = 0; i < lines.size(); i++)
 *     LOGI("%s", lines[i].c_str());
 *
 * Note: only pass memory that is really readable. Dumping a bad address
 * (e.g. an unmapped game pointer) crashes the process.
 */
inline std::vector<std::string> HexDump(const void *data, size_t size, bool showOffset)
{
  std::vector<std::string> lines;
  if (data == NULL || size == 0)
  {
    return lines;
  }

  const unsigned char *bytes = (const unsigned char *)data;
  for (size_t offset = 0; offset < size; offset += HEX_BYTES_PER_LINE)
  {
    // The last line may have fewer than 16 bytes.
    size_t count = size - offset;
    if (count > HEX_BYTES_PER_LINE)
    {
      count = HEX_BYTES_PER_LINE;
    }

    std::string line;
    if (showOffset)
    {
      char prefix[32];
      snprintf(prefix, sizeof(prefix), "%08zX: ", offset);
      line = prefix;
    }
    line += HexLine(bytes + offset, count);
    lines.push_back(line);
  }
  return lines;
}

#endif
