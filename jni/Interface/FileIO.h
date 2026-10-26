#include <fstream>
#include <sstream>
#include <string>
#include <iostream>
#include <stdexcept>

extern "C"
{
    #include "Ihook.h"
}

std::string readString(const std::string& path)
{
    std::ifstream in(path.c_str(), std::ios::in | std::ios::binary);
    if (!in){
        LOGI("ReadTextFile: open fail.");
        throw std::runtime_error("Could not open file: " + path);
    }

    std::ostringstream ss;
    ss << in.rdbuf();                        // whole file at once
    in.close();
    return ss.str();
}

bool writeString(const std::string& path, const std::string& content) {
    std::ofstream out(path.c_str(), std::ios::out | std::ios::binary);
    if (!out) {
        LOGI("WriteTextFile: open fail");
        throw std::runtime_error("Cannot open file: " + path);
    }
    out << content;
    bool bRet = out.good();
    out.close();
    return bRet;
}