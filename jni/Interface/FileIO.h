// FileIO.h : read / write a whole file as a std::string (header-only).

#include <string>
#include <fstream>

extern "C"
{
    #include "Ihook.h"   // LOGI
}

// Read the whole file into strOut. Returns false if the file can't be opened or read.
inline bool ReadString(const char *pszPath, std::string &strOut)
{
  strOut.clear();

  if (pszPath == NULL)
  {
    LOGI("ReadString: path is NULL");
    return false;
  }

  std::ifstream ifs(pszPath, std::ios::in | std::ios::binary);
  if (!ifs.is_open())
  {
    LOGI("ReadString: open fail. path=%s errno=%d", pszPath, errno);
    return false;
  }

  // Read in chunks until EOF (also works for /proc files that report size 0).
  char buffer[4096];
  while (ifs.read(buffer, sizeof(buffer)) || ifs.gcount() > 0)
  {
    strOut.append(buffer, (size_t)ifs.gcount());
  }

  if (ifs.bad())
  {
    LOGI("ReadString: read fail. path=%s errno=%d", pszPath, errno);
    strOut.clear();
    return false;
  }

  LOGI("ReadString: path=%s size=%zu", pszPath, strOut.size());
  return true;
}

// Write str to the file. bAppend = true appends, false overwrites. Returns false on failure.
inline bool WriteString(const char *pszPath, const std::string &str, bool bAppend = false)
{
  if (pszPath == NULL)
  {
    LOGI("WriteString: path is NULL");
    return false;
  }

  std::ios::openmode mode = std::ios::out | std::ios::binary;
  mode |= bAppend ? std::ios::app : std::ios::trunc;

  std::ofstream ofs(pszPath, mode);
  if (!ofs.is_open())
  {
    LOGI("WriteString: open fail. path=%s errno=%d", pszPath, errno);
    return false;
  }

  ofs.write(str.data(), (std::streamsize)str.size());
  ofs.close();
  bool bRet = !ofs.fail();

  LOGI("WriteString: path=%s size=%zu append=%d ok=%d", pszPath, str.size(), (int)bAppend, (int)bRet);
  return bRet;
}
