#include <vector>
#include <fstream>
#include <sys/socket.h>
#include "utils.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sstream>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)

#define ACTION_ENABLE	0
#define ACTION_DISABLE	1

extern "C"
{
    #include "Ihook.h"
    #include "myhook.h"
}

#define qword_value(_var_) *((unsigned long*)((unsigned long)(_var_)))
#define dword_value(_var_) *((unsigned*)((unsigned long)(_var_)))
#define word_value(_var_) *((unsigned short*)((unsigned long)(_var_)))
#define byte_value(_var_) *((unsigned char*)((unsigned long)(_var_)))
#define float_value(_var_) *((float*)((unsigned long)(_var_)))
#define double_value(_var_) *((double*)((unsigned long)(_var_)))

typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;

bool memcpyHookStart = false;
bool InlineHook(void *pHookAddr, void (*onCallBack)(struct user_pt_regs *))
{
    bool bRet = false;
    LOGI("InlineHook");

    if(pHookAddr == NULL || onCallBack == NULL)
    {
        return bRet;
    }

    INLINE_HOOK_INFO* pstInlineHook = new INLINE_HOOK_INFO();
    pstInlineHook->pHookAddr = pHookAddr;
    pstInlineHook->onCallBack = onCallBack;

    if(HookArm(pstInlineHook) == false)
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

    if(pHookAddr == NULL)
    {
        return bRet;
    }

    InlineHookInfoPVec::iterator itr = gs_vecInlineHookInfo.begin();
    InlineHookInfoPVec::iterator itrend = gs_vecInlineHookInfo.end();

    for (; itr != itrend; ++itr)
    {
        if (pHookAddr == (*itr)->pHookAddr)
        {
            INLINE_HOOK_INFO* pTargetInlineHookInfo = (*itr);

            gs_vecInlineHookInfo.erase(itr);
            if(pTargetInlineHookInfo->pStubShellCodeAddr != NULL)
            {
                delete pTargetInlineHookInfo->pStubShellCodeAddr;
            }
            if(pTargetInlineHookInfo->ppOldFuncAddr)
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

void find_address(char* soname, uint64_t& startAddr, uint64_t& endAddr)
{
    int step = 0;
    char buffer[1024] = "";

    FILE *fp = fopen( "/proc/self/maps", "rt" );
    if( fp == NULL ){
        perror("fopen");
        goto done;
    }

    while( fgets( buffer, sizeof(buffer), fp ) ) {
        if( strstr( buffer, soname ) ){
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

    if(fp){
        fclose(fp);
    }
}

/// @brief Api Hook////////////////////////////////////////////////////////////////////
/// @param sockfd 
/// @param buf 
/// @param len 
/// @param flags 
/// @return 

ssize_t apihook_mysend(int sockfd, const void *buf, size_t len, int flags)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    ssize_t ret = send(sockfd, buf, len, flags);
	LOGI("[Api_Send] len=%lx!, ret=%lx\n", (long unsigned int)ret, retaddr - g_modulebase);
    report_hex((unsigned char*)buf, ret);
    
	return ret;
}

ssize_t apihook_myRecv(int sockfd, void *buf, size_t len, int flags)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    ssize_t ret = recv(sockfd, buf, len, flags);
	LOGI("[Api_Recv] len=%lx, ret=%lx\n", (long unsigned int)ret, retaddr - g_modulebase);	
    report_hex((unsigned char*)buf, ret);

	return ret;
}

ssize_t apihook_mysendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addr_len)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    ssize_t ret = sendto(sockfd, buf, len, flags, addr, addr_len);
	LOGI("[Api_SendTo] fd=%d, len=%lx!, lr=0x%lx\n",sockfd, (long unsigned int)ret, retaddr - g_modulebase);
    if (ret > 0)
        report_hex((unsigned char*)buf, ret);
    
	return ret;
}

ssize_t apihook_myRecvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *addr_len)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    ssize_t ret = recvfrom(fd, buf, len, flags, addr, addr_len);
	LOGI("[Api_Recvfrom] len=%lx, ret=%lx\n", (long unsigned int)ret, retaddr - g_modulebase);	
    report_hex((unsigned char*)buf, ret);

	return ret;
}

ssize_t apihook_send_msg(int fd, const struct msghdr *message, int flags)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    ssize_t ret = sendmsg(fd, message, flags);
	LOGI("[ApiSendMsg] len=%lx, ret=%lx\n", (long unsigned int)ret, retaddr - g_modulebase);	

	return ret;
}

ssize_t apihook_recv_msg(int fd, struct msghdr *message, int flags)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    ssize_t ret = recvmsg(fd, message, flags);
	LOGI("[ApiRecvMsg] len=%lx, ret=%lx\n", (long unsigned int)ret, retaddr - g_modulebase);	

	return ret;
}

int api_connect(int fd, const struct sockaddr *addr, socklen_t len)
{   
    int ret = connect(fd, addr, len);
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    std::ostringstream s;
    if( addr_in->sin_family == 1 ){
        struct sockaddr_un *sun = (struct sockaddr_un *)addr;
        s << "unix://" << sun->sun_path;
    }
    else {
        s << "ip://" << inet_ntoa(addr_in->sin_addr);
        s << ",port:" << ntohs(addr_in->sin_port);
    }
    
    LOGI("[connect] fd=%d, ret=%d, ip=%s", fd, ret, s.str().c_str());
    return ret;
}

char* convertChar_16tochar_8(unsigned long adr)
{
    if (adr == 0)
        return NULL;

    char * tempName = (char *)malloc(2000);
    memset(tempName, 0, 2000);
    
    unsigned index = 0;
    unsigned value = 0;
    do
    {
        value = word_value(adr);
        if(value > 0xFF)
            return NULL;

        tempName[index++] = (char)value;
        adr += 2;
    }while(value != 0 && index < 2000);
    
    //LOGI(" name = %s", tempName);
    return tempName;
}

void* apihook_mymemcpy(void*dst, const void* src, size_t size)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    void* ret = memcpy(dst, src, size);
    retaddr = retaddr - g_modulebase;
    //if (size > 0x150 && size < 0x230)
    //if (retaddr == 0x44a43b8)
    //if(memcpyHookStart == true)
    char* strCont = convertChar_16tochar_8((unsigned long)src);
    if(strCont == NULL)
        return ret;

    if(strstr(strCont, "{") != NULL && strstr(strCont, "}") != NULL)
    {
        LOGI("[ApiMemCpy] len=%lx, ret=%lx, buf=%s", (long unsigned int)size, retaddr, strCont);	
        //LOGI("[ApiMemCpy] len=%lx, ret=%lx\n", (long unsigned int)size, retaddr);	
        //report_hex((unsigned char*)src, size);
    }

	return ret;
}

ssize_t apihook_mystrlen(const char *buf)
{
    unsigned long retaddr;
	asm volatile("mov %0, x30" : "=r" (retaddr));

    ssize_t ret = strlen(buf);
    unsigned long lr = retaddr - g_modulebase;
    //if(memcpyHookStart == true)
    //if(lr == 0x4CC5930)
    if(strstr(buf, "{") != NULL && strstr(buf, "}") != NULL)
    {
        LOGI("[apihook_mystrlen] len=%lx, ret=%lx, buf=%s", (long unsigned int)ret, lr, buf);
    }
	return ret;
}

void * my_hook_routine(void* arg)
{
    return NULL;
}

int api_thread_create(pthread_t * newthread, const pthread_attr_t * attr, void * (*start_routine)(void *), void *arg)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));
    unsigned long funcAddr = (unsigned long)start_routine - g_modulebase;
    LOGI("[api_thread_create] funcAddr=%lx, lr=%lx", funcAddr, retaddr - g_modulebase);

    int ret = pthread_create(newthread, attr, my_hook_routine, arg);
	return ret;
}
//-------------------------------------------------------------------------------------------
unsigned long libhook_replace_func( unsigned long address, unsigned long newFunc)
{
    if (ChangePageProperty((void*)address, 8) == false)
        return 0;

    LOGI("[libhook_replace_func]");
    unsigned long orgapiaddr = *(unsigned long*)(address);    
    *(unsigned long*)(address) = newFunc;
    return orgapiaddr;
}

FILE *g_fp = NULL;
int g_current_hour = 0;
char g_current_log_name[256];
unsigned long pktNum = 0;

tm* getLocalTime() {
	time_t timer;
	struct tm *t;
	timer = time(NULL);
	t = localtime(&timer);
	return t;
}

void init_log_file(int year, int mon, int day, int hour)
{
    sprintf(g_current_log_name, "/mnt/shared/Pictures/packetLog/%d-%02d-%02d_%02d_%s_sandy_nox.bin", year, mon, day, hour, "%ec%98%81%ec%9b%85%ed%98%b8%ea%b1%b805");
	g_fp = fopen(g_current_log_name, "ab+");
    if( g_fp == NULL ) {
		LOGI("fopen error name=%s", g_current_log_name);
		return;
	}
	g_current_hour = hour;
	LOGI("fopen sucess name=%s", g_current_log_name);
}

pthread_mutex_t lock;
void ToFile(unsigned nsize, unsigned char* buffer, int pktType, int pktOrder, tm* t)
{
    pthread_mutex_lock(&lock);
    if (g_fp == NULL) {
		init_log_file(t->tm_year+1900, t->tm_mon + 1, t->tm_mday, t->tm_hour);

		if( g_fp == NULL ){
			LOGI("fopen error name=%s", g_current_log_name);
			return;
		}
	}

	char timeStr[0xD];
	sprintf(timeStr, "%02d:%02d:%02d.000", t->tm_hour, t->tm_min, t->tm_sec);
    int timeLen = sizeof(timeStr);

    fwrite(&timeLen, 2, 1, g_fp);
    fwrite((const void*)timeStr, sizeof(char), timeLen, g_fp);
    fwrite(&pktType, 1, 1, g_fp);
    fwrite(&pktOrder, 4, 1, g_fp);
    fwrite(&nsize, 2, 1, g_fp);
	fwrite((const void*)buffer, sizeof(char), nsize, g_fp);
    fflush(g_fp);

    pthread_mutex_unlock(&lock);
}
///////////////////////////////////////////////Packet Name//////////////////////////////////////////////
typedef struct
{
    unsigned decHeader;
    char * header;
    unsigned long nameAddr;
    char * packetName;
}
packetLog;

packetLog Headers[1000];
unsigned hdrCounter = 0;

void LoadHeaderName()
{
    FILE * fp = fopen("/data/local/tmp/header.txt", "r");
	if (fp == NULL)
	{
        LOGI("[LoadHeaderName] header file not found! error=%x", 1);  
        return;
    }	

	char  line[150];
    while (fgets(line, 150, fp)) 
    {
        packetLog log;
        log.packetName = (char *)malloc(0x100);
        char * tempHeader = (char*)malloc(0x30);

        sscanf(line, "%s %s", log.packetName, tempHeader);
        log.decHeader = strtoul(tempHeader, NULL, 16);
        delete tempHeader;

        Headers[hdrCounter] = log;
        //LOGI("[LoadHeaderName] hdr=%x, name=%s, index=%d", log.decHeader, log.packetName, hdrCounter);  
        hdrCounter++;
    }

    fclose(fp);
	LOGI("[LoadHeaderName] Load Headers Success! %d", hdrCounter);  
}

char * GetPacketName(unsigned header){
    unsigned i = 0;
    for (i = 0; i < hdrCounter ; i++)
    {
        //LOGI("[GetPacketName] header=%x, SendName=%s", Headers[i].decHeader, Headers[i].packetName);
        if (Headers[i].decHeader == header)
            {
                //LOGI("[GetPacketName] header=%x, SendName=%s", Headers[i].decHeader, Headers[i].packetName);
                char* find = Headers[i].packetName;
                return find;
            } 
    }   

    return NULL;
}
////////////////////////////////////////////////Send&Recv////////////////////////////////////////////////////////
bool hookMapFlag = false;
void Real_Send(user_pt_regs *regs)
{
    unsigned long lr = regs -> regs[30] - g_modulebase;
    unsigned long x21 = regs -> regs[1];
    unsigned long buf = qword_value(x21 + 0x18);
    unsigned len = qword_value(x21 + 0x20);
    unsigned hdr = word_value(x21);
	if(hdr == 0x3b42)
        return;

    if (hdr != 0x7b66)
        return;

    hookMapFlag = true;
    /*char* pktName = GetPacketName(hdr);
    LOGI("[Send] hdr=0x%lx,%d, len=%lx, name=%s, lr=%lx", hdr,hdr, len, pktName, lr);
    report_hex((unsigned char*)buf, len);*/
}

void Real_Recv(user_pt_regs *regs)
{
    unsigned len = regs -> regs[22];

    unsigned long x19 = regs -> regs[19];
    unsigned long x25 = regs -> regs[25];
    unsigned x8 = qword_value(x25);

    unsigned offset = regs -> regs[23];
    unsigned long buf = x19 + x8 + 0x4A;

    unsigned hdr = word_value(buf);
    if (offset == 1)
        hdr = byte_value(buf);

	if(hdr == 0x5d20)
        return;
		

    char* pktName = GetPacketName(hdr);
    LOGI("[Recv] hdr=0x%lx,%d, len=%lx, offset=%lx, pktName=%s", hdr, hdr, len, offset, pktName);
    report_hex((unsigned char*)(buf + offset), len);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef unsigned long (CheckLocationReachable)(unsigned long a1, unsigned long a2,  unsigned long a9, unsigned int a10, unsigned long a11, unsigned long a12, unsigned long a13, double a3, double a4, double a5, double a6, double a7, double a8);
typedef CheckLocationReachable* LPCheckLocationReachable;
LPCheckLocationReachable checkLocationReachable = NULL;

void my_callback(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback] lr=0x%lx", lr);
}

void my_callback1(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback1] lr=0x%lx", lr);
}

void my_callback2(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback2] lr=0x%lx", lr);
}


void my_callback3(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback3] lr=0x%lx", lr);
}


void my_callback4(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback4] lr=0x%lx", lr);
}


void my_callback5(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback5] lr=0x%lx", lr);
}


void my_callback6(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback6] lr=0x%lx", lr);
}


void my_callback7(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback7] lr=0x%lx", lr);
}


void my_callback8(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback8] lr=0x%lx", lr);
}


void my_callback9(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback9] lr=0x%lx", lr);
}

void my_callback10(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback10] lr=0x%lx", lr);
}

void my_callback11(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    LOGI("[my_callback11] lr=0x%lx", lr);
}


void SendMove(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    unsigned long x0 = regs->regs[0];
    unsigned long x1 = regs->regs[1];

    LOGI("[SendMove] lr=0x%lx, x0=%lx, x1=%lx", lr, x0, x1);
    unsigned long param1 = qword_value(x1);
    LOGI("[SendMove] param1=%lx", param1);
    report_hex((unsigned char*)param1, 0x30);
    unsigned long param2 = qword_value(x1 + 0x20);
    LOGI("[SendMove] param2=%lx", param1);
    report_hex((unsigned char*)param2, 0x30);
    unsigned long param3 = qword_value(x1 + 0x28);
    LOGI("[SendMove] param3=%lx", param3);
    report_hex((unsigned char*)param3, 0x30);
    unsigned long param4 = qword_value(x1 + 0x30);
    LOGI("[SendMove] param4=%lx", param4);
    report_hex((unsigned char*)param4, 0x30);
}


void myhook1(user_pt_regs *regs)
{
    unsigned long x9 = regs->regs[9];
    unsigned long count = regs->regs[8];
    LOGI("[myhook1] posCnt=%lx, x9=%lx", count, x9);
    report_hex((unsigned char*)x9, 0x60);
}

void myhook2(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    unsigned long x2 = regs->regs[2];
    double px1 = double_value(x2);
    double py1 = double_value(x2 + 0x8);
    double pz1 = double_value(x2 + 0x10);
    LOGI("[myhook2] lr=%lx, pos=(%f,%f,%f)", lr, px1, py1, pz1);
}

void myhook3(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    unsigned long x24 = regs->regs[24];
    double px1 = double_value(x24);
    double py1 = double_value(x24 + 0x8);
    double pz1 = double_value(x24 + 0x10);
    LOGI("[myhook3] lr=%lx, pos=(%f,%f,%f)", lr, px1, py1, pz1);
}

void myhook5(user_pt_regs *regs)
{
    unsigned long x19 = regs->regs[19];
    unsigned long x0 = qword_value(x19 + 0x18);
    unsigned long x8 = qword_value(x0);
    unsigned long func = qword_value(x8 + 0x18);
    LOGI("[myhook5] func=%lx", func - g_modulebase);
}

void myhook6(user_pt_regs *regs)
{
    unsigned long x0 = regs->regs[0];
    unsigned long x8 = qword_value(x0);
    unsigned long func = qword_value(x8 + 0x10);
    LOGI("[myhook6] func=%lx", func - g_modulebase);
}

void myhook7(user_pt_regs *regs)
{
    unsigned long x19 = regs->regs[19];
    unsigned long x0 = qword_value(x19 + 0x30);
    unsigned long x8 = qword_value(x0);
    unsigned long func = qword_value(x8 + 0xB0);
    LOGI("[myhook7] func=%lx", func - g_modulebase);
    memcpyHookStart = true;
}

void CheckRayCast(unsigned long x0, unsigned long x1, unsigned long x2, unsigned int dir, unsigned long x4, unsigned long x5, unsigned long x6)
{
    LOGI("raycast test start~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ dir = %lx", dir);
    double tx = -48527.659677; 
    double ty = -57836.199670;
    double tz = 5000;
    dir = 0;
    bool result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty,tz - 2000);
    double rx = double_value(x1 + 0x10);
    double ry = double_value(x1 + 0x18);
    double rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 1;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty,tz - 2000);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 2;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty,tz - 2000);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 3;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty,tz - 2000);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    LOGI("test Axis x += 1000 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ dir = %lx", dir);
    dir = 0;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx + 1000,ty,tz);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 1;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx + 1000,ty,tz);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 2;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx + 1000,ty,tz);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 3;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx + 1000,ty,tz);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    LOGI("test Axis y += 1000 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ dir = %lx", dir);
    dir = 0;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty + 1000,tz);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 1;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty + 1000,tz);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 2;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty + 1000,tz);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 3;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty + 1000,tz);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    LOGI("test Axis z += 1000 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ dir = %lx", dir);
    dir = 0;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty,tz+ 1000);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 1;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty,tz+ 1000);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 2;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty,tz+ 1000);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

    dir = 3;
    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,dir,x4,x5,x6,tx,ty,tz,tx,ty,tz+ 1000);
    rx = double_value(x1 + 0x10);
    ry = double_value(x1 + 0x18);
    rz = double_value(x1 + 0x20);
    LOGI("raycast test  dir = %lx, result = %lx, retPos=(%f,%f,%f)", dir,result, rx,ry,rz);

	LOGI("test end ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ dir = %lx", dir);
}

bool mapHooked = false;
void hookMap(user_pt_regs *regs)
{
    if (hookMapFlag == false)
        return;

    unsigned long pos = regs->regs[2];
    unsigned long pos2 = regs->regs[3];
    double px1 = double_value(pos);
    double py1 = double_value(pos + 0x8);
    double pz1 = double_value(pos + 0x10);
    double px2 = double_value(pos2);
    double py2 = double_value(pos2 + 0x8);
    double pz2 = double_value(pos2 + 0x10);
    LOGI("[hookMap] pos1=(%f, %f, %f)", px1,py1,pz1);
    LOGI("[hookMap] pos2=(%f, %f, %f)", px2,py2,pz2);

    if(mapHooked == true)
        return;

    unsigned long x0 = regs->regs[22];
    unsigned long x1= regs->regs[23];
    unsigned long x2= regs->regs[29] - 0x40;
    unsigned long x3= regs->regs[21];
    unsigned long x4= regs->regs[20];
    unsigned long x5= regs->regs[19];
    unsigned long x6= regs->regs[6];
    
    //CheckRayCast(x0, x1, x2, 0, x4, x5, x6);
    FILE* datFile = fopen("/data/data/com.wemade.nightcrowsglobal/map/20001.dat", "wb");
	if (datFile == NULL)
	{
		LOGI("datFile open failed %s", "");
		return;
	}
	

	FILE* zmapFile = fopen("/data/data/com.wemade.nightcrowsglobal/map/20001.zmap", "wb");
	if (zmapFile == NULL)
	{
	 	LOGI("zmapFile open failed %s", "");
	 	return;
	}
	int BaseX = -20000;
	int BaseY = -20000;
	int MapWidth = 800;
	int MapHeight = 800;

	
	float scale = 50;
	fwrite(&scale, 4, 1, datFile);
	fwrite(&BaseX, 4, 1, datFile);
	fwrite(&BaseY, 4, 1, datFile);
	fwrite(&MapWidth, 4, 1, datFile);
	fwrite(&MapHeight, 4, 1, datFile);
	
	int zscale = 50;
	fwrite(&zscale, 4, 1, zmapFile);
	fwrite(&BaseX, 4, 1, zmapFile);
	fwrite(&BaseY, 4, 1, zmapFile);
	fwrite(&MapWidth, 4, 1, zmapFile);
	fwrite(&MapHeight, 4, 1, zmapFile);

    float FVector[3];
    double maxZ = 1000;
    double minZ = -1000;
    LOGI("start ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~x3=%x", x3);

    for (float y = 0; y < MapHeight ; y ++)
	{
		for (float x = 0; x < MapWidth ; x ++)
		{FVector[0] = BaseX + x * scale;
			FVector[1] = BaseY + y * scale;
			FVector[2] = -50000;

			bool result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,(unsigned int)x3,x4,x5,x6,(double)FVector[0], (double)FVector[1],maxZ,(double)FVector[0], (double)FVector[1],minZ);
            float wz = 0;
            if(result != 0)
            {
                double recheckX = double_value(x1 + 0x10);
                double recheckY = double_value(x1 + 0x18);
                double recheckZ = double_value(x1 + 0x20);
                LOGI("[printResult] pos=(%f, %f, %f)", recheckX,recheckY,recheckZ);

                wz = recheckZ;
                if(recheckZ >= maxZ )
                {
                    //recheckZ += 3000;
                    
                    result = 0;
                    wz = -1;
                }
                else
                {
                    result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,1,x4,x5,x6,recheckX, recheckY ,recheckZ + 100,recheckX + scale, recheckY + scale,recheckZ + 100);
                    result = result ^ 1;
                    if(result  != 0)
                    {
                        result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,1,x4,x5,x6,recheckX, recheckY ,recheckZ + 100,recheckX - scale, recheckY - scale,recheckZ + 100);
                        result = result ^ 1;
                        if(result  != 0)
                        {
                            result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,1,x4,x5,x6,recheckX, recheckY ,recheckZ + 100,recheckX + scale, recheckY - scale,recheckZ + 100);
                            result = result ^ 1;
                            if(result  != 0)
                            {
                                result = checkLocationReachable((unsigned long)x0, (unsigned long)x1, x2,1,x4,x5,x6,recheckX, recheckY ,recheckZ + 100,recheckX - scale, recheckY + scale,recheckZ + 100);
                                result = result ^ 1;
                            }
                        }
                    }
                }
            }
            fwrite(&wz, 4, 1, zmapFile);
            fwrite(&result, 1, 1, datFile);
		}
	}

	fclose(datFile);
	fclose(zmapFile);
    mapHooked = true;
    hookMapFlag = false;
	LOGI("end ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~%s", "");
}

void sendCharacterPos(float x, float y);
void ShowPos(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    unsigned long x1 = regs->regs[1];
    float px1 = float_value(x1 + 0x10);
    float py1 = float_value(x1 + 0x14);
    float pz1 = float_value(x1 + 0x18);
    if(lr == 0x43ECF5C) //53 1B 40 F9
    {
        LOGI("[ShowPos] lr=%lx, pos=(%f,%f,%f)", lr, px1, py1, pz1);
        sendCharacterPos(px1, py1);

        //float_value(x1 + 0x10) = px1 + 1000;
        //float_value(x1 + 0x14) = py1 + 1000;
        //float_value(x1 + 0x18) = pz1 + 1000;
    }
}
void DrawMoveLine(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    unsigned long x9 = regs->regs[9];
    unsigned long pathList = x9 + 0x8;
    LOGI("[DrawMoveLine] lr=0x%lx, pathList=%lx", lr, pathList);
    report_hex((unsigned char*)pathList, 0x50);
}

void ShowMessageProperty(user_pt_regs *regs)
{
    unsigned long x0 = regs->regs[0];
    unsigned long x1 = regs->regs[1];
    unsigned long x2 = regs->regs[2];
    unsigned long x3 = regs->regs[3];
    unsigned long x4 = regs->regs[4];
    char* name1 = convertChar_16tochar_8(x1);
    LOGI("[ShowMessageProperty] name1=%s", name1);  
}

void serializer(user_pt_regs *regs)
{
    unsigned long lr = regs -> regs[30] - g_modulebase;
    unsigned long len = regs -> regs[2];
    unsigned long obj = regs -> regs[0];

    unsigned long call = qword_value(qword_value(obj) + 0x60) - g_modulebase;
    LOGI("[serializer] len=%lx, lr=%lx, call=%lx", len, lr, call);

}


int socket_handle;
int socket_state;
char g_net_buffer[0xFFF];
char g_server_addr[40] = "";
int g_server_port = 0;

int write_socket(int s, char* buf, int size);

void sendCharacterPos(float x, float y)
{
	if (socket_state <= 0)
		return;
	
	char resultString[0x100] = {0};
	
	sprintf(resultString, "char_pos %f,%f", x, y);
	int len = strlen(resultString);
	resultString[len] = 0xD;		//개행문자
	resultString[len+1] = 0xA;
	resultString[len+2] = 0;
	
	int w_len = write_socket(socket_handle, resultString, strlen(resultString));
	if (w_len <= 0)
	{
		LOGI( "[processPacket] write string error w_len=%d", w_len );
	}   
}

int loadConfigFile()
{
	char line[260];

	std::ifstream config_fp("/data/data/com.wemade.nightcrowsglobal/config.txt");
	if (!config_fp.is_open())
	{
		LOGI( "net config file not found %s", "/data/data/com.wemade.nightcrowsglobal/config.txt" );
		return 0;
	}

	int config_found = 0;
	while (!config_fp.eof())
	{
		line[0] = 0;
		config_fp.getline(line, 260);

		LOGI( "net config contents: %s", line);
		sscanf(line, "%s %d", g_server_addr, &g_server_port);		
        LOGI( "net server url = %s : %d", g_server_addr, g_server_port);
		
		if ( strlen(g_server_addr) > 0 && g_server_port > 0)
		{
			config_found = 1;
			break;
		}
    }
    config_fp.close();

	return config_found;
}

#define LOCK() pthread_mutex_lock(&__netlock)
#define UNLOCK() pthread_mutex_unlock(&__netlock)
static pthread_mutex_t  __netlock = PTHREAD_MUTEX_INITIALIZER;

int write_socket(int s, char* buf, int size)
{
	char* p = buf;
	int len = size;
	int tryCount = 0;
	LOCK();
	while(len > 0)
	{
		int n = write(s, p, len);
		if (n <= 0)
		{
			if (tryCount++ >= 3)
			{
				size = -1;
				break;
			}
			continue;
		}
		len -= n;
		p += n;
	}
	UNLOCK();
	return size;
}

int sendString(const char* str)
{
	if (socket_state <= 0)
		return -1;
	
	char resultString[0x100] = {0};
	
	sprintf(resultString, "%s", str);
	int len = strlen(resultString);
	resultString[len] = 0xD;		//개행문자
	resultString[len+1] = 0xA;
	resultString[len+2] = 0;
	
	int w_len = write_socket(socket_handle, resultString, strlen(resultString));
	if (w_len <= 0)
	{
		LOGI( "[processPacket] write string error w_len=%d", w_len );
		return -1;
	}   
	return w_len;
}

void networkThreadMain()
{
    if (loadConfigFile() == 0)
	{
		LOGI( "libhook_nox load config file failed %d.", getpid() );
		return;
	}
	
	while (1)
	{		
		if ((socket_handle = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			socket_state = -1;
			LOGI( "[networkThreadMain] create socket error err=%d", 2 );
			printf("create socket error\n");
			sleep(2);
			continue;
		}
		
		struct sockaddr_in server_addr;
		memset((char *)&server_addr, 0, sizeof(server_addr));
		
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = inet_addr(g_server_addr);
		server_addr.sin_port = htons(g_server_port);
		
		struct timeval tv;
		tv.tv_sec = 7;  
		tv.tv_usec = 0;  
		setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv,sizeof(struct timeval));
		tv.tv_sec = 7;  
		tv.tv_usec = 0;  
		setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO , (const char*)&tv,sizeof(struct timeval));

		while (1)
		{
			LOGI( "[networkThreadMain] try to connect server... step =%d", socket_handle );
			if (connect(socket_handle, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
			{
				socket_state = -1;
				LOGI( "[networkThreadMain] failed to connect. err=%d", socket_handle );
				printf("failed to connect.\n");
				sleep(3);
			}
			else
			{
				socket_state = 1;
				LOGI( "[networkThreadMain] connected. err=%d", socket_handle );
				printf("connected.\n");
				break;
			}
		}

		while (1)
		{
			//HOOKLOG( "[networkThreadMain] try read packet length ... error =%d", 0 );
			if (sendString("ECHO test") <= 0)
			{
				LOGI( "[networkThreadMain] send echo message failed len=%d", 5 );
				break;
			}
			
			int len = recv(socket_handle, g_net_buffer, 0x100, 0);			
			//int len = read_socket(socket_handle, g_net_buffer, 0x100);
			if (len <= 0)
			{
				LOGI( "[networkThreadMain] read len error len=%d", len );
				break;
			}
			sleep(5);
		}

		socket_state = -1;
		close(socket_handle);
		LOGI( "[networkThreadMain] connection closed. err=%d", 0 );
		printf("connection closed.\n");		
	}
}

void* networkThreadWrapper(void *arg)
{
    sleep(10);
	networkThreadMain();
	return NULL;
}

void createNetThread()
{
	pthread_t tid;
	int err = pthread_create(&tid, NULL, networkThreadWrapper, NULL);
	if (err != 0)
    {
		LOGI("can't create thread :[%s]", strerror(err));
    }
	else
    {
		LOGI("Thread created successfully,%d",0);
    }
}
////////////////////////////////////////////////////////////////////////////////////////////////////////
void* hook_thread(void* arg)
{
    LOGI("hook_thread start %s", "");
	sleep(0);

    uint64_t endAddr;
	char libUE4_name[] = "libUnreal.so";
	char libGurad_name[] = "libdxbase.so";
    unsigned libhooked = 0;

    while (true)
    {
        if (libhooked == 0)
        {
            find_address(libGurad_name, g_modulebase, endAddr);
            if (g_modulebase != 0)
            {
                LOGI("libdxbase g_modulebase=%lx", g_modulebase);
                
                uint16_t org_addr101 = libhook_replace_func(0x37E08 + g_modulebase, (unsigned long)(api_thread_create));
                LOGI("hook succeed org=%lx, new=%lx\n", org_addr101, (unsigned long)(api_thread_create));

                libhooked = 1;
            }
        }
        
        if (libhooked == 1)
        {
            find_address(libUE4_name, g_modulebase, endAddr);
            if (g_modulebase != 0)
            {
                LOGI("g_modulebase=%lx", g_modulebase);

                InlineHook((void*)((uint64_t)g_modulebase + 0x6DDA3F4), hookMap); //checkLocationReachable 2th call back
                InlineHook((void*)((uint64_t)g_modulebase + 0x4E9C234), ShowPos); //80 16 40 BD 08 20 20 1E
                
                checkLocationReachable = (CheckLocationReachable*)(g_modulebase + 0x6DF2B5C); //STP             D11, D10, [SP,#-0x60+var_20]! 

                InlineHook((void*)((uint64_t)g_modulebase + 0x46379FC), Real_Send);     //42 7D AA 0A
                //InlineHook((void*)((uint64_t)g_modulebase + 0x4594020), Real_Recv);     //08 41 37 8B 01 29 01 91   

                libhooked = 2;
            }
        }

        if (libhooked == 2)
            break;

        sleep(1);
    }
    
	return NULL;
}

void __attribute__((constructor)) libhook_main()
{
    LOGI( "LIBRARY LOADED FROM PID  NightCrow OK %d.", getpid() );

    LoadHeaderName();

 	pthread_t thread;
	pthread_create(&thread, NULL, hook_thread, NULL);
    //createNetThread();
}