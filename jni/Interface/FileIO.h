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
#include <vector>

/*
 * ReadTextFile
 * ------------
 * Reads the WHOLE content of a text file into one string.
 *
 * Parameters:
 *   path       - full path of the file to read, e.g. "/data/data/pkg/files/a.txt".
 *   outContent - [out] receives the file content (including line breaks).
 *                It is cleared first, so old data is never mixed in.
 *
 * Returns:
 *   true  - the file was opened and read.
 *   false - the file does not exist or cannot be opened (no permission).
 *           outContent is left empty.
 *
 * Example:
 *   std::string text;
 *   if (ReadTextFile("/data/data/pkg/files/a.txt", text))
 *     LOGI("file says: %s", text.c_str());
 */
inline bool ReadTextFile(const char *path, std::string &outContent)
{
  outContent.clear();

  std::ifstream file(path);
  if (!file.is_open())
  {
    return false;
  }

  // Copy the whole file buffer into a string stream in one go.
  std::stringstream buffer;
  buffer << file.rdbuf();
  outContent = buffer.str();
  return true;
}

/*
 * ReadTextLines
 * -------------
 * Reads a text file LINE BY LINE; each line becomes one item in a vector.
 * Useful when every line is a separate value (a list of names, settings...).
 *
 * Parameters:
 *   path     - full path of the file to read.
 *   outLines - [out] receives one string per line. Line break characters
 *              ('\n' and a trailing '\r' from Windows files) are removed.
 *              It is cleared first.
 *
 * Returns:
 *   true  - the file was opened and read (an empty file gives 0 lines).
 *   false - the file does not exist or cannot be opened. outLines is empty.
 *
 * Example:
 *   std::vector<std::string> lines;
 *   if (ReadTextLines("/data/data/pkg/files/a.txt", lines))
 *     for (size_t i = 0; i < lines.size(); i++)
 *       LOGI("line %zu: %s", i, lines[i].c_str());
 */
inline bool ReadTextLines(const char *path, std::vector<std::string> &outLines)
{
  outLines.clear();

  std::ifstream file(path);
  if (!file.is_open())
  {
    return false;
  }

  std::string line;
  while (std::getline(file, line))
  {
    // Files edited on Windows end lines with "\r\n"; drop the '\r'.
    if (!line.empty() && line[line.size() - 1] == '\r')
    {
      line.erase(line.size() - 1);
    }
    outLines.push_back(line);
  }
  return true;
}

/*
 * WriteTextFile
 * -------------
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
 *   WriteTextFile("/data/data/pkg/files/a.txt", "first line\n", false);  // new file
 *   WriteTextFile("/data/data/pkg/files/a.txt", "second line\n", true);  // add to it
 */
inline bool WriteTextFile(const char *path, const std::string &text, bool append)
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
