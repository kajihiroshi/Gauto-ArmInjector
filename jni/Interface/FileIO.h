/*
 * FileIO.h - simple helpers to read and write plain .txt files.
 *
 * This is a header-only file: every function is defined here as `inline`,
 * so you only need to `#include "FileIO.h"` - no extra .cpp file and no
 * change to Android.mk is required.
 *
 * IMPORTANT (Android): this library runs inside the game process, so it can
 * only write where the game itself is allowed to write. The safest place is
 * the app's private folder, e.g.
 *     /data/data/<package name>/files/
 * Writing to /sdcard/ only works if the game has storage permission.
 * The folder must already exist; these functions do not create folders.
 */
#ifndef FILE_IO_H
#define FILE_IO_H

#include <fstream>
#include <sstream>
#include <string>

/*
 * ReadString
 * ----------
 * Reads the WHOLE content of a text file and returns it as one string.
 *
 * Parameters:
 *   path - full path of the file to read, e.g. "/data/data/pkg/files/a.txt".
 *
 * Returns:
 *   The file content (including line breaks).
 *   Returns "" (empty string) when the file does not exist or cannot be
 *   opened (no permission). Note: an empty file also returns "".
 *
 * Example:
 *   std::string text = ReadString("/data/data/pkg/files/a.txt");
 *   if (!text.empty())
 *     LOGI("file says: %s", text.c_str());
 */
inline std::string ReadString(const char *path)
{
  std::ifstream file(path);
  if (!file.is_open())
  {
    return "";
  }

  // Copy the whole file buffer into a string stream in one go.
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

/*
 * WriteString
 * -----------
 * Writes a string to a text file. The string is whatever the caller types /
 * passes in; it is written exactly as given (add "\n" yourself if you want a
 * line break).
 *
 * Parameters:
 *   path   - full path of the file to write. The file is created if it does
 *            not exist (but its folder must exist).
 *   text   - the text to write.
 *   append - false: OVERWRITE - old content is deleted, file holds only `text`.
 *            true : APPEND    - `text` is added to the end of the old content.
 *
 * Returns:
 *   true  - the text was written successfully.
 *   false - the file could not be opened (folder missing / no permission)
 *           or the write failed (e.g. disk full).
 *
 * Example:
 *   WriteString("/data/data/pkg/files/a.txt", "first line\n", false);  // new file
 *   WriteString("/data/data/pkg/files/a.txt", "second line\n", true);  // add to it
 */
inline bool WriteString(const char *path, const std::string &text, bool append)
{
  std::ios_base::openmode mode = std::ios_base::out;
  mode |= append ? std::ios_base::app : std::ios_base::trunc;

  std::ofstream file(path, mode);
  if (!file.is_open())
  {
    return false;
  }

  file << text;
  file.flush();
  return file.good();
}

#endif
