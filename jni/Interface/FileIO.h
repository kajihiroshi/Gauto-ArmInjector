#ifndef GAUTO_FILE_IO_H
#define GAUTO_FILE_IO_H

/* ===========================================================================
 * FileIO.h
 * ---------------------------------------------------------------------------
 * Simple string <-> file helpers used by the Gauto-ArmInjector project.
 *
 * HOW TO USE THIS FILE
 *   This is a "header-only" library: every function is fully implemented
 *   right here, so you only need to:
 *       #include "FileIO.h"
 *   You do NOT need to add any .cpp file to the build or change any Makefile.
 *   It can be included together with GautoUtils.h.
 *
 * REQUIREMENTS
 *   - C++ (the file uses std::string / std::fstream). C++98 compatible, so it
 *     builds with the project's gnustl_static STL.
 *
 * DATA FORMAT
 *   Files are opened in BINARY mode, so the bytes in the file and the bytes
 *   in the std::string are always identical: no newline conversion, and
 *   embedded '\0' bytes are preserved.
 *
 * LOGGING
 *   Every function prints a short result line through GAUTO_LOGI.
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
#include <stddef.h>  /* size_t                               */
#include <stdio.h>   /* printf                               */
#include <errno.h>   /* errno                                */

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
 * ReadString
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Read the ENTIRE contents of a file into a std::string.
 *
 * INPUT
 *   pszPath : C-string, full path to the file to read.
 *             Example: "/data/local/tmp/config.txt"
 *             May be NULL (handled safely -> returns false).
 *   strOut  : reference to a std::string you own. It is always cleared
 *             first, then receives the file content on success.
 *
 * OUTPUT (return value)
 *   bool :
 *     true  -> the file was read completely. strOut holds the content
 *              (it may legitimately be "" if the file is empty).
 *     false -> bad argument, the file could not be opened, or the read
 *              failed (logged). strOut is left EMPTY.
 *   Unlike an "empty string means error" design, the bool lets you tell an
 *   empty file apart from a missing / unreadable one.
 *
 * EXAMPLE
 *   std::string text;
 *   if (ReadString("/sdcard/in.txt", text))
 *       GAUTO_LOGI("read %zu bytes: %s", text.size(), text.c_str());
 * ========================================================================= */
inline bool ReadString(const char *pszPath, std::string &strOut)
{
  strOut.clear();

  if (pszPath == NULL)
  {
    GAUTO_LOGI("ReadString: path is NULL");
    return false;
  }

  std::ifstream ifs(pszPath, std::ios::in | std::ios::binary);
  if (!ifs.is_open())
  {
    GAUTO_LOGI("ReadString: open fail. path=%s errno=%d", pszPath, errno);
    return false;
  }

  /* Find the file size so the whole content is read in one go. */
  ifs.seekg(0, std::ios::end);
  std::streampos endPos = ifs.tellg();
  ifs.seekg(0, std::ios::beg);

  if (endPos > 0 && ifs.good())
  {
    /* Regular file of known size: read it in a single call. */
    strOut.resize((size_t)endPos);
    ifs.read(&strOut[0], (std::streamsize)strOut.size());

    if ((size_t)ifs.gcount() != strOut.size())
    {
      GAUTO_LOGI("ReadString: read fail. path=%s expected=%zu got=%ld",
                 pszPath, strOut.size(), (long)ifs.gcount());
      strOut.clear();
      ifs.close();
      return false;
    }
  }
  else
  {
    /* Size unknown (e.g. /proc files report 0, or the stream is not
     * seekable): fall back to reading chunk by chunk until EOF. */
    ifs.clear();
    ifs.seekg(0, std::ios::beg);
    ifs.clear();

    char buffer[4096];
    while (ifs.read(buffer, sizeof(buffer)) || ifs.gcount() > 0)
    {
      strOut.append(buffer, (size_t)ifs.gcount());
    }

    if (ifs.bad())
    {
      GAUTO_LOGI("ReadString: read fail. path=%s errno=%d", pszPath, errno);
      strOut.clear();
      ifs.close();
      return false;
    }
  }

  ifs.close();

  GAUTO_LOGI("ReadString: path=%s size=%zu", pszPath, strOut.size());
  return true;
}


/* ===========================================================================
 * WriteString
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   Write a std::string to a file.
 *
 * INPUT
 *   pszPath : C-string, full path to the file to write.
 *             May be NULL (handled safely -> returns false).
 *   str     : the text to write. It is written verbatim (every byte,
 *             including any '\n' or '\0'), so add line breaks yourself.
 *   bAppend : true  -> add to the END of the file (create it if missing).
 *             false -> OVERWRITE: truncate the file to empty first (or
 *                      create it). This is the default.
 *
 * OUTPUT (return value)
 *   bool :
 *     true  -> all bytes of str were written and flushed to the file.
 *     false -> bad argument, the file could not be opened, or the write
 *              failed (e.g. disk full / no permission) (logged).
 *
 * OUTPUT (side effect / file format)
 *   The file contains exactly the bytes of str (appended or replacing the
 *   old content). Nothing else is added.
 *
 * EXAMPLE
 *   WriteString("/sdcard/out.txt", "hello\n");          // overwrite
 *   WriteString("/sdcard/out.txt", "world\n", true);    // append
 *
 *   std::string s;
 *   if (ReadString("/sdcard/out.txt", s))   // s == "hello\nworld\n"
 *       ...
 * ========================================================================= */
inline bool WriteString(const char *pszPath, const std::string &str, bool bAppend = false)
{
  if (pszPath == NULL)
  {
    GAUTO_LOGI("WriteString: path is NULL");
    return false;
  }

  std::ios::openmode mode = std::ios::out | std::ios::binary;
  mode |= bAppend ? std::ios::app : std::ios::trunc;

  std::ofstream ofs(pszPath, mode);
  if (!ofs.is_open())
  {
    GAUTO_LOGI("WriteString: open fail. path=%s errno=%d", pszPath, errno);
    return false;
  }

  if (!str.empty())
  {
    ofs.write(str.data(), (std::streamsize)str.size());
  }
  ofs.flush();
  bool bRet = ofs.good();
  ofs.close();
  bRet = bRet && !ofs.fail();   /* close() can fail when flushing to disk */

  if (!bRet)
  {
    GAUTO_LOGI("WriteString: write fail. path=%s errno=%d", pszPath, errno);
  }

  GAUTO_LOGI("WriteString: path=%s size=%zu append=%d ok=%d",
             pszPath, str.size(), (int)bAppend, (int)bRet);
  return bRet;
}

#endif /* GAUTO_FILE_IO_H */
