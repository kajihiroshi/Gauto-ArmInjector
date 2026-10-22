#include <vector>
#include <fstream>
#include <sys/socket.h>
#include "utils.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sstream>
#include <strings.h>

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


typedef std::vector<INLINE_HOOK_INFO*> InlineHookInfoPVec;
static InlineHookInfoPVec gs_vecInlineHookInfo;

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
uint64_t g_modulebase1 = 0;

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

#define LOCK() pthread_mutex_lock(&__lock)
#define UNLOCK() pthread_mutex_unlock(&__lock)
typedef enum {
    LOGCAT = 0
}
report_mode_t;

typedef struct {
    report_mode_t  mode;
    // for future use
    std::string    dest;
    unsigned short port;
}
report_options_t;

static report_options_t __opts = { LOGCAT, "", 0 };
static pthread_mutex_t  __lock = PTHREAD_MUTEX_INITIALIZER;

void log_to_file(FILE* fd, const char *buf)
{
	size_t len = strlen(buf);
	fwrite((const void*)buf, sizeof(char), len, fd);
}

void log_hex_string(FILE* fd, unsigned char *buf, size_t len)  {
    size_t line_len = 0;
	size_t i;
	
    LOCK();
	
    if( __opts.mode == LOGCAT ) {
        std::ostringstream s;
	
		#define MAX_LINE_BYTES  16 	
		
		char cBytes[3];
		cBytes[2] = '\0';
		while(len > 0)
		{
			line_len = (len < MAX_LINE_BYTES) ? len : MAX_LINE_BYTES;
			u_char utmp = *(u_char*)buf;			buf ++;			
			
			cBytes[1] = utmp & 0x0F;
			//first 4 bits
			if(cBytes[1] >= 0x0A)
				cBytes[1] = (cBytes[1] - 0x0A) + 'A';
			else
				cBytes[1] = cBytes[1] + '0';
			
			cBytes[0] = utmp >> 4;
			//last 4 bits
			if(cBytes[0] >= 0x0A)
				cBytes[0] = (cBytes[0] - 0x0A) + 'A';
			else
				cBytes[0] = cBytes[0] + '0';
			
			s << cBytes;
			for( i = 1; i < line_len; i ++) {
				u_char utmp = *(u_char*)buf;		buf ++;
								
				cBytes[1] = utmp & 0x0F;
				//first 4 bits
				if(cBytes[1] >= 0x0A)
					cBytes[1] = (cBytes[1] - 0x0A) + 'A';
				else
					cBytes[1] = cBytes[1] + '0';
				
				cBytes[0] = utmp >> 4;
				//last 4 bits
				if(cBytes[0] >= 0x0A)
					cBytes[0] = (cBytes[0] - 0x0A) + 'A';
				else
					cBytes[0] = cBytes[0] + '0';
				
				s << " " << cBytes;
			}

			s << '\n';
		

			len -= line_len;
		}
		
		log_to_file(fd, (const char*)(s.str().c_str()));
    }

    UNLOCK();
}

void init_log_file(int year, int mon, int day, int hour)
{
    sprintf(g_current_log_name, "/data/data/com.wemade.nightcrowsglobal/%d-%02d-%02d_%02d_%s_sandy_nox.bin", year, mon, day, hour, "pktLog");
	g_fp = fopen(g_current_log_name, "ab+");
    if( g_fp == NULL ) {
		LOGI("fopen error name=%s", g_current_log_name);
		return;
	}
	g_current_hour = hour;
	LOGI("fopen sucess name=%s", g_current_log_name);
}

void complete_log_file()
{
	fclose(g_fp);
	g_fp = NULL;
}

pthread_mutex_t lock;
void ToFile(unsigned nsize, unsigned char* buffer, unsigned char *recvName, tm* t, bool isNewLine)
{
	pthread_mutex_lock(&lock);

	char timeStr[50];
	if (g_fp == NULL || g_current_hour != t->tm_hour)
	{
		if (g_fp != NULL)
		{
			complete_log_file();
		}
		init_log_file(t->tm_year+1900, t->tm_mon + 1, t->tm_mday, t->tm_hour);

		if( g_fp == NULL ){
			//HOOKLOG("fopen error name=%s", g_current_log_name);
			return;
		}
	}

	sprintf( timeStr, "%02d-%02d %02d:%02d:%02d.000", t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

	char szlog[255];
	
    if (isNewLine == true)
    {
	    sprintf( szlog, "%s : %s\n", timeStr, recvName);
    }
    else
    {
        sprintf( szlog, "%s : %s   : ", timeStr, recvName);
    }
	
	log_to_file( g_fp, szlog );
    log_hex_string( g_fp, buffer, nsize );
	
	pthread_mutex_unlock(&lock);
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


    /*char packetinfo[255];
    sprintf( packetinfo, "[ApiRecv]length=%lx", ret);
    tm* t = getLocalTime();
	ToFile(ret, (unsigned char*)buf, (unsigned char*)packetinfo, t, true);*/

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

void* apihook_mymemcpy(void*dst, const void* src, size_t size)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    void* ret = memcpy(dst, src, size);
    retaddr = retaddr - g_modulebase;
    //if (size > 0x150 && size < 0x230)
    //if (retaddr == 0x44a43b8) //recv
    if (size > 0x3000 || retaddr == 0x3976d88)
    {
        LOGI("[ApiMemCpy] len=%lx, ret=%lx\n", (long unsigned int)size, retaddr);	
        report_hex((unsigned char*)src, 0x50);
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
    unsigned long funcAddr = (unsigned long)start_routine - g_modulebase1;
    LOGI("[api_thread_create] funcAddr=%lx, lr=%lx", funcAddr, retaddr - g_modulebase1);

    int ret = pthread_create(newthread, attr, my_hook_routine, arg);
	return ret;
}

int api_strcasecmp(const char *s1, const char *s2)
{
    unsigned long retaddr;		
	asm volatile("mov %0, x30" : "=r" (retaddr));

    int ret = strcasecmp(s1, s2);

    LOGI("[api_strcasecmp] s1=%s, s2=%s, lr=%lx", s1, s2, retaddr - g_modulebase);

	return ret;
}

//-------------------------------------------------------------------------------------------
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
    FILE * fp = fopen("/data/data/com.wemade.nightcrowsglobal/header.txt", "r");
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
void send_serializer(user_pt_regs *regs)
{
    unsigned long lr = regs -> regs[30] - g_modulebase;
    unsigned long len = regs -> regs[2];
    unsigned long obj = regs -> regs[0];
    unsigned long x1 = regs -> regs[1];

    unsigned long call = qword_value(qword_value(obj) + 0x60) - g_modulebase;
    LOGI("[Send_Serializer] len=%lx, lr=%lx, serializer=%lx", len, lr, call);
    /*LOGI("[Send_Serializer] x0=%lx", obj);
    report_hex((unsigned char*)obj, 0x300);
    unsigned long obj1 = qword_value(obj);
    LOGI("[Send_Serializer] obj1=%lx", obj1);
    report_hex((unsigned char*)obj1, 0x100);*/
}

void Real_Send(user_pt_regs *regs)
{
    /*unsigned long x19 = regs -> regs[0];
    unsigned long x9 = x19 + (0x200 << 12) + 0x50;

    unsigned w10 = dword_value(x9 + 0x8);
    unsigned w11 = dword_value(x9 + 0x14);
    unsigned long keybuf = qword_value(x9);

    LOGI("[enc_result] keybuf=%lx, w10=%lx, w11=%lx", keybuf, w10, w11);
    report_hex((unsigned char*)keybuf, 0x40); //*/

    unsigned long lr = regs -> regs[30] - g_modulebase;
    unsigned long x21 = regs -> regs[1];
    unsigned long buf = qword_value(x21 + 0x18);
    unsigned len = qword_value(x21 + 0x20);
    unsigned hdr = word_value(x21);

    if (hdr == 0x3B42)
        return;

    char* pktName = GetPacketName(hdr);
    LOGI("[Send] hdr=0x%lx,%d, len=%lx, name=%s, lr=%lx", hdr,hdr, len, pktName, lr);
    report_hex((unsigned char*)buf, len);

    //*
    char packetinfo[255];
    sprintf( packetinfo, "[Send] hdr=0x%lx,%d, len=%lx, name=%s, lr=%lx", hdr,hdr, len, pktName, lr);
    tm* t = getLocalTime();
	ToFile(len, (unsigned char*)buf, (unsigned char*)packetinfo, t, true); //*/
}

void Real_Recv(user_pt_regs *regs)
{
    unsigned len = regs -> regs[22];

    unsigned long x19 = regs -> regs[19];
    unsigned long x25 = regs -> regs[25];
    unsigned x8 = qword_value(x25);

    unsigned offset = regs -> regs[23];
    unsigned long buf = x19 + x8 + 0x6A;

    unsigned hdr = word_value(buf);
    if (offset == 1)
        hdr = byte_value(buf);

    if (hdr == 0x5d20)
        return;

    char* pktName = GetPacketName(hdr);
    LOGI("[Recv] hdr=0x%lx,%d, len=%lx, offset=%lx, pktName=%s", hdr, hdr, len, offset, pktName);
    report_hex((unsigned char*)(buf + offset), len);

    //*
    char packetinfo[255];
    sprintf(packetinfo, "[Recv] hdr=0x%lx,%d, len=%lx, offset=%lx, pktName=%s", hdr, hdr, len, offset, pktName);
    tm* t = getLocalTime();
	ToFile(len, (unsigned char*)(buf + offset), (unsigned char*)packetinfo, t, true); //*/
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

void my_hook1(user_pt_regs *regs)
{
    unsigned long w19 = regs -> regs[19];
    unsigned long w1 = regs -> regs[1];

    LOGI("[my_hook1] w19=%lx, w1=%lx", w19, w1);
}

void my_calladdr(user_pt_regs *regs)
{
    unsigned long x0 = regs->regs[20];
    unsigned long call = qword_value(qword_value(x0) + 0xD8)- g_modulebase;
    LOGI("[my_calladdr] x0=%lx, call=0x%lx", x0, call);
}

void enc_process(user_pt_regs *regs)
{
    unsigned long x19 = regs -> regs[19];
    unsigned long x9 = x19 + (0x200 << 12) + 0x70;

    unsigned w10 = dword_value(x9 + 0x8);
    unsigned w11 = dword_value(x9 + 0x14);
    unsigned long keybuf = qword_value(x9);

    LOGI("[enc_result] keybuf=%lx, w10=%lx, w11=%lx", keybuf, w10, w11);
    report_hex((unsigned char*)keybuf, 0x40);
}

void dec_process(user_pt_regs *regs)
{
    unsigned long x23 = regs -> regs[23];
    unsigned w10 = dword_value(x23 + 0x18);
    unsigned w11 = dword_value(x23 + 0x18);
    unsigned long keybuf = qword_value(x23 + 0x8);

    LOGI("[dec_result] keybuf=%lx, w10=%lx, w11=%lx", keybuf, w10, w11);
    report_hex((unsigned char*)keybuf, 0x40);
}

void serializing(user_pt_regs *regs)
{
    unsigned long lr = regs->regs[30] - g_modulebase;
    unsigned long x3 = regs -> regs[3];
    LOGI("[serializing] lr=0x%lx, memberName=%s", lr, x3);
}

void recv_serializer(user_pt_regs *regs)
{
    unsigned long x1 = regs -> regs[1];
    unsigned long obj = regs -> regs[12];
    unsigned long x8 = qword_value(obj + 0x20);
    unsigned long x9 = obj + 0x30;
    unsigned long call1 = 0;
    if (x8 == 0)
        call1 = qword_value(qword_value(x9) + 0x8) - g_modulebase;
    else
        call1 = qword_value(qword_value(x8) + 0x8) - g_modulebase;

    unsigned hdr = word_value(x1);
    LOGI("[recv_serializer] hdr=%lx, x12=%lx, x1=%lx, serializer=%lx", hdr, obj, x1, call1);
    report_hex((unsigned char*)x1, 0x100);
}

void printlog(user_pt_regs *regs)
{
    unsigned long x0 = regs -> regs[0];
    unsigned long ff = regs -> regs[8];

    unsigned long x8 = qword_value(x0);
    unsigned long call = qword_value(x8 + 0x3F8) - g_modulebase;

    unsigned long x20 = regs->regs[20];
    unsigned long dd = qword_value(x20 + 0x290);
    unsigned gg = qword_value(ff + 0x28);
    unsigned long hh = qword_value(ff);
    LOGI("[printlog] x0=%lx, call=%lx, x20=%lx", x0, call, x20);
    LOGI("[printlog] ff=%lx", ff);
    report_hex((unsigned char*)ff, 0x50);
    LOGI("[printlog] dd=%lx, gg=%lx", dd, gg);
    report_hex((unsigned char*)dd, 0x200);
}

void writestring(user_pt_regs *regs)
{
    unsigned long lr = regs -> regs[30] - g_modulebase;
    unsigned long x2 = regs -> regs[2];
    LOGI("[writestring] lr=%lx, str=%s", lr, x2);
}

void recv_parser(user_pt_regs *regs)
{
    unsigned long lr = regs -> regs[30] - g_modulebase;
    unsigned long len = regs -> regs[2];
    unsigned long obj = regs -> regs[0];
    unsigned long x1 = regs -> regs[1];

    unsigned long call1 = qword_value(qword_value(obj) + 0x48) - g_modulebase;
    unsigned long call = qword_value(qword_value(obj) + 0x60) - g_modulebase;
    LOGI("[recv_parser] len=%lx, lr=%lx, call1=%lx, parser=%lx", len, lr, call1, call);
}

unsigned char rawData[153] =
{
    0x0A, 0x11, 0x4C, 0x6F, 0x67, 0x69, 0x6E, 0x46, 0x6F, 0x72, 0x57, 0x65, 0x70, 0x6C, 0x61, 0x74, 
    0x52, 0x65, 0x71, 0x12, 0x14, 0x0A, 0x0C, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5F, 0x74, 0x6F, 
    0x6B, 0x65, 0x6E, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x12, 0x1F, 0x0A, 0x08, 0x70, 0x6C, 0x61, 
    0x74, 0x66, 0x6F, 0x72, 0x6D, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0E, 0x32, 0x0D, 0x2E, 0x50, 0x6C, 
    0x61, 0x74, 0x66, 0x6F, 0x72, 0x6D, 0x54, 0x79, 0x70, 0x65, 0x12, 0x24, 0x0A, 0x07, 0x76, 0x65, 
    0x72, 0x73, 0x69, 0x6F, 0x6E, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0B, 0x32, 0x13, 0x2E, 0x43, 0x32, 
    0x47, 0x53, 0x2E, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 
    0x12, 0x15, 0x0A, 0x03, 0x61, 0x67, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0E, 0x32, 0x08, 0x2E, 
    0x41, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0E, 0x0A, 0x06, 0x61, 0x70, 0x70, 0x5F, 0x69, 
    0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x12, 0x20, 
};

unsigned char rawData1[153] =
{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 
} ;

unsigned long targetAddr;
void break_binary(user_pt_regs *regs)
{
    LOGI("[break_binary] before break");
    report_hex((unsigned char*)targetAddr, 0x50);
    memcpy((void*)targetAddr, (void*)rawData1, 153);
    LOGI("[break_binary] break ok");
    report_hex((unsigned char*)targetAddr, 0x50);
}

void break_binary1()
{
    LOGI("[break_binary1] before break");
    report_hex((unsigned char*)targetAddr, 0x50);
    memcpy((void*)targetAddr, (void*)rawData1, 153);
    LOGI("[break_binary1] break ok");
    report_hex((unsigned char*)targetAddr, 0x50);
}

void restore_binary(user_pt_regs *regs)
{
    LOGI("[restore_binary] called222222222");

    LOGI("[restore_binary] before resotre");
    report_hex((unsigned char*)targetAddr, 0x50);
    memcpy((void*)targetAddr, (void*)rawData, 153);
    LOGI("[restore_binary] resotre ok");
    report_hex((unsigned char*)targetAddr, 0x50);
}

/// @brief ///////////////////////////////////////////////////////////////////
/// @param regs /
void mid_proc1(user_pt_regs *regs)
{
    unsigned long x8 = regs -> regs[8];
    unsigned long x9 = regs -> regs[9];
    unsigned long x10 = regs -> regs[10];
    LOGI("[mid_proc1] X8=%llx, X9=%llx, X10=%llx", x8, x9, x10);
}

void input_de(user_pt_regs *regs)
{
    unsigned long lr = regs -> regs[30] - g_modulebase;
    unsigned long x0 = regs->regs[0];
    
    LOGI("[input_de] x0=%lx, lr=%lx", x0, lr);
}

void mid_proc_de(user_pt_regs *regs)
{
    unsigned long x10 = regs->regs[10];
    unsigned long x8 = regs->regs[8];
    unsigned long x11 = regs->regs[11];
    
    LOGI("[mid_proc_de] x10=%lx, x8=%lx, x11=%lx", x10, x8, x11);
}

void input(user_pt_regs *regs)
{
    unsigned long lr = regs -> regs[30] - g_modulebase;
    unsigned long x0 = regs->regs[0];
    unsigned long x01 = qword_value(x0);
    
    LOGI("[input] x0=%lx, x01=%lx, lr=%lx", x0,x01, lr);
    report_hex((unsigned char*)x0, 0x50);
    LOGI("-----------------------------------------------");
    report_hex((unsigned char*)x0, 0x10);
    LOGI("-----------------------------------------------");
    report_hex((unsigned char*)x0+0x10, 0x8);
}

void output(user_pt_regs *regs)
{
    unsigned long x21 = regs -> regs[21];
    unsigned  w8 = dword_value(x21 + 0x14);
    unsigned long d0 = qword_value(x21 + 0x18);

    LOGI("[output] w8=%lx, d0=%llx", w8, d0);
    report_hex((unsigned char*)x21, 0x50);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////
void* hook_thread(void* arg)
{
	LOGI("hook_thread start %s", "");
	//sleep(0);

    uint64_t endAddr;
	//char libUE4_name[] = "libUnreal.so";
	char libUE4_name[] = "libdxbase.so";
    while (true)
    {
        find_address(libUE4_name, g_modulebase, endAddr);
        if (g_modulebase != 0)
        {
            LOGI("g_modulebase=%lx", g_modulebase);
            //report_hex((unsigned char*)g_modulebase, 0x100);
            
            //uint16_t org_addr0 = libhook_replace_func(0x89CCF80 + g_modulebase, (unsigned long)(api_connect)); // 0x89CBF10
            //LOGI("hook succeed org=%lx, new=%lx\n", org_addr0, (unsigned long)(api_connect));

            //uint16_t org_addr1 = libhook_replace_func(0x89CC648 + g_modulebase, (unsigned long)(apihook_mysend));
            //LOGI("hook succeed org=%lx, new=%lx\n", org_addr1, (unsigned long)(apihook_mysend));

            //uint16_t org_addr11 = libhook_replace_func(0x89CBF28 + g_modulebase, (unsigned long)(apihook_mysendto));
            //LOGI("hook succeed org=%lx, new=%lx\n", org_addr11, (unsigned long)(apihook_mysendto));

            //uint16_t org_addr2 = libhook_replace_func(0x89CC778 + g_modulebase, (unsigned long)(apihook_myRecv));
            //LOGI("hook succeed org=%lx, new=%lx\n", org_addr2, (unsigned long)(apihook_myRecv));

            //uint16_t org_addr21 = libhook_replace_func(0x89CBF30 + g_modulebase, (unsigned long)(apihook_myRecvfrom));
            //LOGI("hook succeed org=%lx, new=%lx\n", org_addr21, (unsigned long)(apihook_myRecvfrom));

            //uint16_t org_addr31 = libhook_replace_func(0x89CB720 + g_modulebase, (unsigned long)(apihook_mymemcpy));
            //LOGI("hook succeed org=%lx, new=%lx\n", org_addr31, (unsigned long)(apihook_mymemcpy));
            
            //uint16_t org_addr32 = libhook_replace_func(0x89CB808 + g_modulebase, (unsigned long)(apihook_mymemset));
            //LOGI("hook succeed org=%lx, new=%lx\n", org_addr32, (unsigned long)(apihook_mymemset));
            
            //InlineHook((void*)((uint64_t)g_modulebase + 0x4A26DC4), send_serializer);    // 0x4A23CE4
            //InlineHook((void*)((uint64_t)g_modulebase + 0x4593F0C), Real_Send);     //42 7D AA 0A
            //InlineHook((void*)((uint64_t)g_modulebase + 0x45F4C3C), recv_serializer);
            //InlineHook((void*)((uint64_t)g_modulebase + 0x45937A0), Real_Recv);     //08 41 37 8B 01 29 01 91

            //InlineHook((void*)((uint64_t)g_modulebase + 0x44A4BDC), enc_process);
            //InlineHook((void*)((uint64_t)g_modulebase + 0x44A33F4), dec_process);
            //InlineHook((void*)((uint64_t)g_modulebase + 0x4A4E2C0), serializing);
           
            /*targetAddr = g_modulebase + 0x2073f13;
            if (ChangePageProperty((void*)targetAddr, 8) == false)
            {
                LOGI("[ChangePageProperty] falied.");
            }

            //InlineHook((void*)((uint64_t)g_modulebase + 0x452E164), break_binary);
            //InlineHook((void*)((uint64_t)g_modulebase + 0x452E3E8), restore_binary);*/
            
            //InlineHook((void*)((uint64_t)g_modulebase + 0x4A23B5C), recv_parser);
            //InlineHook((void*)((uint64_t)g_modulebase + 0x43B0268), writestring);
            
            ////////////////////////////////////////
            /////////guard////////////////////
            //InlineHook((void*)((uint64_t)g_modulebase + 0x1F7D0), my_callback);
            InlineHook((void*)((uint64_t)g_modulebase + 0x926C), my_callback);
            //InlineHook((void*)((uint64_t)g_modulebase + 0x21288), my_callback1);
            
            /* ret
            char retBuffer[4] = { 0xC0,  0x03, 0x5F, 0xD6 };
            //char retBuffer[4] = { 0xD6 , 0x5F , 0x03, 0xC0 }; //*/
            //* nop
            //char retBuffer[4] = { 0x1F,  0x20, 0x03, 0xD5 };
            //char retBuffer[4] = { 0xD5, 0x03 , 0x20, 0x1F };    //*/

            /*
            unsigned long targetAddr11 = g_modulebase + 0x56C0;
            if (ChangePageProperty((void*)targetAddr11, 8) == false)
            {
                LOGI("[ChangePageProperty] falied.");
            }
            libhook_writeMemory(targetAddr11, (void*)retBuffer, 4);*/

            /*
            char retBuffer[4] = { 0x1F,  0x20, 0x03, 0xD5 };
            unsigned long targetAddr11 = g_modulebase + 0x8138;
            if (ChangePageProperty((void*)targetAddr11, 8) == false)
            {
                LOGI("[ChangePageProperty] falied.");
            }
            libhook_writeMemory(targetAddr11, (void*)retBuffer, 4); 
           
            targetAddr11 = g_modulebase + 0x21284;
            if (ChangePageProperty((void*)targetAddr11, 8) == false)
            {
                LOGI("[ChangePageProperty] falied.");
            }
            libhook_writeMemory(targetAddr11, (void*)retBuffer, 4);
            
            targetAddr11 = g_modulebase + 0xB378;
            if (ChangePageProperty((void*)targetAddr11, 8) == false)
            {
                LOGI("[ChangePageProperty] falied.");
            }
            libhook_writeMemory(targetAddr11, (void*)retBuffer, 4);   
            
            targetAddr11 = g_modulebase + 0x1ABA4;
            if (ChangePageProperty((void*)targetAddr11, 8) == false)
            {
                LOGI("[ChangePageProperty] falied.");
            }
            libhook_writeMemory(targetAddr11, (void*)retBuffer, 4); //*/

            //*
            uint16_t org_addr101 = libhook_replace_func(0x38E08 + g_modulebase, (unsigned long)(api_thread_create));
            LOGI("hook succeed org=%lx, new=%lx\n", org_addr101, (unsigned long)(api_thread_create)); //*/

            /*
            uint16_t org_addr102 = libhook_replace_func(0x38EC0 + g_modulebase, (unsigned long)(api_strcasecmp));
            LOGI("hook succeed org=%lx, new=%lx\n", org_addr102, (unsigned long)(api_strcasecmp)); //*/

            break;
        }

        sleep(1);
    }
    
	return NULL;
}

void* my_hook_thread(void* arg)
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
            find_address(libGurad_name, g_modulebase1, endAddr);
            if (g_modulebase1 != 0)
            {
                LOGI("libdxbase g_modulebase1=%lx", g_modulebase1);

                uint16_t org_addr101 = libhook_replace_func(0x37E08 + g_modulebase1, (unsigned long)(api_thread_create));
                LOGI("hook succeed org=%lx, new=%lx\n", org_addr101, (unsigned long)(api_thread_create)); 

                libhooked = 1;
            }
        }
        
        if (libhooked == 1)
        {
            find_address(libUE4_name, g_modulebase, endAddr);
            if (g_modulebase != 0)
            {

                uint16_t org_addr01 = libhook_replace_func(0x8C0F688 + g_modulebase, (unsigned long)(api_connect));
                LOGI("hook succeed org=%lx, new=%lx\n", org_addr01, (unsigned long)(api_connect));

                InlineHook((void*)((uint64_t)g_modulebase + 0x45BFB54), Real_Send);     //42 7D AA 0A    first address
                //InlineHook((void*)((uint64_t)g_modulebase + 0x4639418), my_callback);
                InlineHook((void*)((uint64_t)g_modulebase + 0x45BF3E8), Real_Recv);     //28 03 80 B9 E2 03 16 AA
                
                //InlineHook((void*)((uint64_t)g_modulebase + 0x4637AD4), enc_process);     //28 03 80 B9 E2 03 16 AA
                

                libhooked = 2;
                LOGI("hooking true");
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
    LOGI( "LIBRARY LOADED FROM PID  BNS OK %d.", getpid() );

    LoadHeaderName();

 	pthread_t thread;
	pthread_create(&thread, NULL, my_hook_thread, NULL);
}