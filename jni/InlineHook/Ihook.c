#include "Ihook.h"
#include "fixPCOpcode.h"

#define ALIGN_PC(pc)	(pc & 0xFFFFFFFC)

bool ChangePageProperty(void *pAddress, size_t size)
{
    bool bRet = false;
    
    if(pAddress == NULL)
    {
        LOGI("change page property error.");
        return bRet;
    }
    
    unsigned long ulPageSize = sysconf(_SC_PAGESIZE);
    int iProtect = PROT_READ | PROT_WRITE | PROT_EXEC;
    unsigned long ulNewPageStartAddress = (unsigned long)(pAddress) & ~(ulPageSize - 1); //pAddress & 0x1111 0000 0000 0000
    long lPageCount = (size / ulPageSize) + 1;
    
    long l = 0;
    while(l < lPageCount)
    {
        int iRet = mprotect((void *)(ulNewPageStartAddress), ulPageSize, iProtect);
        if(-1 == iRet)
        {
            LOGI("mprotect error:%s", strerror(errno));
            return bRet;
        }
        l++; 
    }
    
    return true;
}

void * GetModuleBaseAddr(pid_t pid, char* pszModuleName)
{
    FILE *pFileMaps = NULL;
    unsigned long ulBaseValue = 0;
    char szMapFilePath[256] = {0};
    char szFileLineBuffer[1024] = {0};
    LOGI("first fork(): I'am father pid=%d", getpid());

    LOGI("Pid is %d\n",pid);

    if (pid < 0)
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath), "/proc/self/maps");
    }
    else
    {
        snprintf(szMapFilePath, sizeof(szMapFilePath),  "/proc/%d/maps", pid);
    }

    pFileMaps = fopen(szMapFilePath, "r");
    if (NULL == pFileMaps)
    {
        return (void *)ulBaseValue;
    }
    LOGI("%d",(int)pFileMaps);

    LOGI("Get map.\n");

    while (fgets(szFileLineBuffer, sizeof(szFileLineBuffer), pFileMaps) != NULL)
    {
        //LOGI("%s\n",szFileLineBuffer);
        //LOGI("%s\n",pszModuleName);
        if (strstr(szFileLineBuffer, pszModuleName))
        {
            LOGI("%s\n",szFileLineBuffer);
            char *pszModuleAddress = strtok(szFileLineBuffer, "-");
            if (pszModuleAddress)
            {
                ulBaseValue = strtoul(pszModuleAddress, NULL, 16);

                if (ulBaseValue == 0x8000)
                    ulBaseValue = 0;

                break;
            }
        }
    }
    fclose(pFileMaps);
    return (void *)ulBaseValue;
}

bool InitArmHookInfo(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    uint32_t *currentOpcode = pstInlineHook->pHookAddr;

    for(int i=0;i<BACKUP_CODE_NUM_MAX;i++){
        pstInlineHook->backUpFixLengthList[i] = -1;
    }
    //LOGI("pstInlineHook->szbyBackupOpcodes is at %x",pstInlineHook->szbyBackupOpcodes);

    if(pstInlineHook == NULL)
    {
        LOGI("pstInlineHook is null");
        return bRet;
    }

    pstInlineHook->backUpLength = 24;
    
    memcpy(pstInlineHook->szbyBackupOpcodes, pstInlineHook->pHookAddr, pstInlineHook->backUpLength);

    for(int i=0;i<6;i++){
        //currentOpcode += i; //GToad BUG
        //LOGI("Arm64 Opcode to fix %d : %x",i,*currentOpcode);
        //LOGI("Fix length : %d",lengthFixArm32(*currentOpcode));
        pstInlineHook->backUpFixLengthList[i] = lengthFixArm64(*currentOpcode);
        currentOpcode += 1; //GToad BUG
    }
    
    return true;
}

bool BuildStub(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        
        void *p_shellcode_start_s = &_shellcode_start_s;
        void *p_shellcode_end_s = &_shellcode_end_s;
        void *p_hookstub_function_addr_s = &_hookstub_function_addr_s;
        void *p_old_function_addr_s = &_old_function_addr_s;

        size_t sShellCodeLength = p_shellcode_end_s - p_shellcode_start_s;
        
        //make jmp code
        void *pNewShellCode = malloc(sShellCodeLength);
        if(pNewShellCode == NULL)
        {
            LOGI("shell code malloc fail.");
            break;
        }
        memcpy(pNewShellCode, p_shellcode_start_s, sShellCodeLength);
        
        //change memory property
        if(ChangePageProperty(pNewShellCode, sShellCodeLength) == false)
        {
            LOGI("change shell code page property fail.");
            break;
        }

        //jmp + myHookFunc + originCodes 
        //LOGI("_hookstub_function_addr_s : %llx",p_hookstub_function_addr_s);
        void **ppHookStubFunctionAddr = pNewShellCode + (p_hookstub_function_addr_s - p_shellcode_start_s);
        *ppHookStubFunctionAddr = pstInlineHook->onCallBack;
        //LOGI("ppHookStubFunctionAddr : %llx",ppHookStubFunctionAddr);
        //LOGI("*ppHookStubFunctionAddr : %llx",*ppHookStubFunctionAddr);
        
        pstInlineHook->ppOldFuncAddr  = pNewShellCode + (p_old_function_addr_s - p_shellcode_start_s);
            
        pstInlineHook->pStubShellCodeAddr = pNewShellCode;

        bRet = true;
        break;
    }
    
    return bRet;
}

bool BuildArmJumpCode(void *pCurAddress , void *pJumpAddress)
{
    //LOGI("LIVE4.3.1");
    bool bRet = false;
    while(1)
    {
        //LOGI("LIVE4.3.2");
        if(pCurAddress == NULL || pJumpAddress == NULL)
        {
            LOGI("address null.");
            break;
        }    
        //LOGI("LIVE4.3.3");    
        //LDR PC, [PC, #-4]
        //addr
        //BYTE szLdrPCOpcodes[8] = {0x04, 0xF0, 0x1F, 0xE5};

        //STP X1, X0, [SP, #-0x10]
        //LDR X0, 8
        //BR X0
        //ADDR(64)
        //LDR X0, [SP, -0x8]
        BYTE szLdrPCOpcodes[24] = {0xe1, 0x03, 0x3f, 0xa9, 0x40, 0x00, 0x00, 0x58, 0x00, 0x00, 0x1f, 0xd6};
        memcpy(szLdrPCOpcodes + 12, &pJumpAddress, 8);
        szLdrPCOpcodes[20] = 0xE0;
        szLdrPCOpcodes[21] = 0x83;
        szLdrPCOpcodes[22] = 0x5F;
        szLdrPCOpcodes[23] = 0xF8;
        //LOGI("LIVE4.3.4");
        
        memcpy(pCurAddress, szLdrPCOpcodes, 24);
        //LOGI("LIVE4.3.5");
        //__flush_cache(*((uint32_t*)pCurAddress), 20);
        //__builtin___clear_cache (*((uint64_t*)pCurAddress), *((uint64_t*)(pCurAddress+20)));
        //cacheflush(*((uint32_t*)pCurAddress), 20, 0);
        //LOGI("LIVE4.3.6");
        bRet = true;
        break;
    }
    //LOGI("LIVE4.3.7");
    return bRet;
}

bool BuildOldFunction(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;

    void *fixOpcodes;
    int fixLength;
    //LOGI("LIVE3.1");

    fixOpcodes = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    //LOGI("LIVE3.2");
    while(1)
    {
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        //LOGI("LIVE3.3");
        
        void * pNewEntryForOldFunction = malloc(200);
        if(pNewEntryForOldFunction == NULL)
        {
            LOGI("new entry for old function malloc fail.");
            break;
        }
        //LOGI("LIVE3.4");

        pstInlineHook->pNewEntryForOldFunction = pNewEntryForOldFunction;
        //LOGI("%llx",pNewEntryForOldFunction);
        
        if(ChangePageProperty(pNewEntryForOldFunction, 200) == false)
        {
            LOGI("change new entry page property fail.");
            break;
        }
        //LOGI("LIVE3.5");
        
        fixLength = fixPCOpcodeArm(fixOpcodes, pstInlineHook);
        memcpy(pNewEntryForOldFunction, fixOpcodes, fixLength);
        //LOGI("LIVE3.6");
        //memcpy(pNewEntryForOldFunction, pstInlineHook->szbyBackupOpcodes, 8);
        if(BuildArmJumpCode(pNewEntryForOldFunction + fixLength, pstInlineHook->pHookAddr + pstInlineHook->backUpLength - 4) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        //LOGI("LIVE3.7");
        *(pstInlineHook->ppOldFuncAddr) = pNewEntryForOldFunction;
        //LOGI("LIVE3.8");
        
        bRet = true;
        break;
    }
    //LOGI("LIVE3.9");
    
    return bRet;
}

bool RebuildHookTarget(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    
    while(1)
    {
        //LOGI("LIVE4.1");
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null");
            break;
        }
        //LOGI("LIVE4.2");
        if(ChangePageProperty(pstInlineHook->pHookAddr, 24) == false)
        {
            LOGI("change page property error.");
            break;
        }
        //LOGI("LIVE4.3");
        if(BuildArmJumpCode(pstInlineHook->pHookAddr, pstInlineHook->pStubShellCodeAddr) == false)
        {
            LOGI("build jump opcodes for new entry fail.");
            break;
        }
        //LOGI("LIVE4.4");
        bRet = true;
        break;
    }
    //LOGI("LIVE4.5");
    
    return bRet;
}

bool HookArm(INLINE_HOOK_INFO* pstInlineHook)
{
    bool bRet = false;
    //LOGI("HookArm()");
    
    while(1)
    {
        //LOGI("pstInlineHook is null 1.");
        if(pstInlineHook == NULL)
        {
            LOGI("pstInlineHook is null.");
            break;
        }
        //LOGI("LIVE1");

        //LOGI("Init Arm HookInfo fail 1.");
        if(InitArmHookInfo(pstInlineHook) == false)
        {
            LOGI("Init Arm HookInfo fail.");
            break;
        }
        //LOGI("LIVE2");
        
        //LOGI("BuildStub fail 1.");
        if(BuildStub(pstInlineHook) == false)
        {
            LOGI("BuildStub fail.");
            break;
        }
        //LOGI("LIVE3");
        
        //LOGI("BuildOldFunction fail 1.");
        
        if(BuildOldFunction(pstInlineHook) == false)
        {
            LOGI("BuildOldFunction fail.");
            break;
        }
        //LOGI("LIVE4");
        
        //LOGI("RebuildHookAddress fail 1.");
        if(RebuildHookTarget(pstInlineHook) == false)
        {
            LOGI("RebuildHookAddress fail.");
            break;
        }
        //LOGI("LIVE5");
        
        bRet = true;
        break;
    }
    //LOGI("LIVE6");

    return bRet;
}
