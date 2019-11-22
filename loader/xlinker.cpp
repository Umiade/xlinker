#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "elf.h"
#include "xelf.h"
#include "logger.h"
#include "xlinker.h"
#include "cJSON.h"

/**
 * NOTE ON LOADING OF .bin WITH .plk
 *
 * A ".bin" file is encrypted pure code part of an ELF file.
 *
 * A ".plk" file contains all prelink info processed when
 * parse a normal ELF file to a bin file.
 *
 **/

#define REG_MAX 16

#define BUF_SIZE 4096
PlkInfo* xpltInfo;
PlkInfo* xgotInfo;
PlkInfo* xrodataInfo;
PlkInfo* xbssInfo;

xdyninfo* g_xi;
void* g_bss_base;

//int x_rodata_off;

static void install_segv_handler();

static void fix_ctx(ucontext_t* ctx)
{
	int* ctx_base = (int*)ctx;

	int idx;

	// Fix plt
	for (idx = 0; xpltInfo[idx].offset != 0; idx++)
	{
		for (int off = 0x20; off <= 0x5C; off += 4)
		{
			if (*((unsigned int*)((unsigned int)ctx + off)) == xpltInfo[idx].offset + (int)(g_xi->buffer))
			{
				void* imp = dlsym(RTLD_DEFAULT, xpltInfo[idx].value);
				LOGD("[*] Fix plt %s=0x%08X\n", xpltInfo[idx].value, imp);
				*((unsigned int*)((unsigned int)ctx + off)) = (unsigned int)imp;

				if ((unsigned int)imp % 2 == 1)
					// Force switch to thumb here, set T bit in CPSR
					*((unsigned int*)((unsigned int)ctx + 0x60)) = *((unsigned int*)((unsigned int)ctx + 0x60)) | 0b100000;
				else
					*((unsigned int*)((unsigned int)ctx + 0x60)) = *((unsigned int*)((unsigned int)ctx + 0x60)) & 0b11111111111111111111111111011111;
			}

		}
	}

	// Fix got
	for (idx = 0; xgotInfo[idx].offset != 0; idx++)
	{
		for (int off = 0x20; off <= 0x5C; off += 4)
		{
			if (*((unsigned int*)((unsigned int)ctx + off)) == xgotInfo[idx].offset + (int)(g_xi->buffer))
			{
				if (strcmp(xgotInfo[idx].value, "__stack_chk_guard_ptr") == 0)
				{
					unsigned int* scgp = (unsigned int*)malloc(sizeof(int));
					memset(scgp, 0, sizeof(int));
					LOGD("[*] Fix got %s=0x%08X\n", xgotInfo[idx].value, scgp);
					*((unsigned int*)((unsigned int)ctx + off)) = (int)&scgp;
				}
				else if (strcmp(xgotInfo[idx].value, "__sF") == 0)
				{
					// todo: need verify
					unsigned int* sf = (unsigned int*)malloc(sizeof(int));
					memset(sf, 0, sizeof(int));
					*sf = (int)stderr - 0xA8;
					LOGD("[*] Fix got %s=0x%08X\n", xgotInfo[idx].value, sf);
					*((unsigned int*)((unsigned int)ctx + off)) = (unsigned int)sf;
				}
			}

		}
	}

	// Fix rodata
	for (idx = 0; xrodataInfo[idx].offset != 0; idx++)
	{
		for (int off = 0x20; off <= 0x5c; off += 4)
		{
			if (*((unsigned int*)((unsigned int)ctx + off)) == xrodataInfo[idx].offset + (int)(g_xi->buffer))
			{
				LOGD("[*] Fix rodata %s=0x%08X\n", xrodataInfo[idx].value, xrodataInfo[idx].value);
				*((unsigned int*)((unsigned int)ctx + off)) = (unsigned int)(xrodataInfo[idx].value);
			}
		}
	}


	// Fix bss
	for (idx = 0; xbssInfo[idx].offset != 0; idx++)
	{
		for (int off = 0x20; off <= 0x5c; off += 4)
		{
			if (*((unsigned int*)((unsigned int)ctx + off)) == xbssInfo[idx].offset + (int)(g_xi->buffer))
			{
				int bss_offset = atoi(xbssInfo[idx].value);
				LOGD("[*] Fix bss file_offset=0x%08X, bss_offset=0x%08X\n", xbssInfo[idx].offset, bss_offset);
				*((unsigned int*)((unsigned int)ctx + off)) = (unsigned int)g_bss_base + bss_offset;
			}
		}
	}


}

static void _segv_handler(int signal_number, siginfo_t* si, void* context)
{
	if (signal_number != SIGSEGV)
	{
		return;
	}

	// install_segv_handler();

	//unsigned int x_r0, x_r1, x_r2, x_r3, x_r4, x_r5, x_r6, x_r7;
	//unsigned int x_reg[REG_MAX] = { 0 };
	//memset(x_reg, 0, sizeof(int) * REG_MAX);

	ucontext_t* ctx = (ucontext_t*)context;
	LOGD("memory writing to 0x%08X\n", si->si_addr);
	LOGD("[*] Before handle: R0=0x%08X, R1=0x%08X, R2=0x%08X, R3=0x%08X, R4=0x%08X, R5=0x%08X, R6=0x%08X, R7=0x%08X, R8=0x%08X, R9=0x%08X, R10=0x%08X, R11=0x%08X, R12=0x%08X, SP=0x%08X, LR=0x%08X, PC=0x%08X, CPSR=0x%08X\n",
		ctx->uc_mcontext.arm_r0, ctx->uc_mcontext.arm_r1, ctx->uc_mcontext.arm_r2, ctx->uc_mcontext.arm_r3,
		ctx->uc_mcontext.arm_r4, ctx->uc_mcontext.arm_r5, ctx->uc_mcontext.arm_r6, ctx->uc_mcontext.arm_r7,
		ctx->uc_mcontext.arm_r8, ctx->uc_mcontext.arm_r9, ctx->uc_mcontext.arm_r10, ctx->uc_mcontext.arm_fp,
		ctx->uc_mcontext.arm_ip, ctx->uc_mcontext.arm_sp, ctx->uc_mcontext.arm_lr, ctx->uc_mcontext.arm_pc,
		ctx->uc_mcontext.arm_cpsr
	);

	fix_ctx(ctx);

	//static char* xrel_str = (char*)malloc(16);
	//memset(xrel_str, 0, 16);
	//memcpy(xrel_str, "XREL SUCCESS!\n", 14);

	//x_reg[0] = ctx->uc_mcontext.arm_r0;
	//x_reg[1] = ctx->uc_mcontext.arm_r1;
	//x_reg[2] = ctx->uc_mcontext.arm_r2;
	//x_reg[3] = ctx->uc_mcontext.arm_r3;
	//x_reg[4] = ctx->uc_mcontext.arm_r4;
	//x_reg[5] = ctx->uc_mcontext.arm_r5;
	//x_reg[6] = ctx->uc_mcontext.arm_r6;
	//x_reg[7] = ctx->uc_mcontext.arm_r7;
	//x_reg[8] = ctx->uc_mcontext.arm_r8;
	//x_reg[9] = ctx->uc_mcontext.arm_r9;
	//x_reg[10] = ctx->uc_mcontext.arm_r10;
	//x_reg[11] = ctx->uc_mcontext.arm_fp;
	//x_reg[12] = ctx->uc_mcontext.arm_ip;
	//x_reg[13] = ctx->uc_mcontext.arm_sp;
	//x_reg[14] = ctx->uc_mcontext.arm_lr;
	//x_reg[15] = ctx->uc_mcontext.arm_pc;


	//for (int i = 0; i < REG_MAX; ++i)
	//{
	//	if (x_reg[i] == x_rodata_off)
	//		x_reg[i] = (int)xrel_str;
	//}

	//for (int off = 0x20; off <= 0x5C; off += 4)
	//{
	//	if (*((unsigned int*)((unsigned int)ctx + off)) == x_rodata_off)
	//	{
	//		*((unsigned int*)((unsigned int)ctx + off)) = (int)xrel_str;
	//	}
	//
	//}


	LOGD("[*] After handle: R0=0x%08X, R1=0x%08X, R2=0x%08X, R3=0x%08X, R4=0x%08X, R5=0x%08X, R6=0x%08X, R7=0x%08X, R8=0x%08X, R9=0x%08X, R10=0x%08X, R11=0x%08X, R12=0x%08X, SP=0x%08X, LR=0x%08X, PC=0x%08X, CPSR=0x%08X\n",
		ctx->uc_mcontext.arm_r0, ctx->uc_mcontext.arm_r1, ctx->uc_mcontext.arm_r2, ctx->uc_mcontext.arm_r3,
		ctx->uc_mcontext.arm_r4, ctx->uc_mcontext.arm_r5, ctx->uc_mcontext.arm_r6, ctx->uc_mcontext.arm_r7,
		ctx->uc_mcontext.arm_r8, ctx->uc_mcontext.arm_r9, ctx->uc_mcontext.arm_r10, ctx->uc_mcontext.arm_fp,
		ctx->uc_mcontext.arm_ip, ctx->uc_mcontext.arm_sp, ctx->uc_mcontext.arm_lr, ctx->uc_mcontext.arm_pc,
		ctx->uc_mcontext.arm_cpsr
	);





	//__asm__
	//(
	//	"mov r0, %0; \
	//	 ldr r2, [r0, #0x0]; \
	//	 ldr r1, [r0, #0x20]; \
	//	 mov r8, r1; \
	//	 ldr r1, [r0, #0x24]; \
	//	 mov r9, r1; \
	//	 ldr r1, [r0, #0x28]; \
	//	 mov r10, r1; \
	//	 ldr r1, [r0, #0x2C]; \
	//	 mov r11, r1; \
	//	 ldr r1, [r0, #0x30]; \
	//	 mov r12, r1; \
	//	 ldr r1, [r0, #0x34]; \
	//	 mov r13, r1; \
	//	 ldr r1, [r0, #0x38]; \
	//	 mov r14, r1; \
	//	 ldr r1, [r0, #0x3C]; \
	//	 mov r3, #1; \
	//	 orr r1, r3; \
	//	 push {r1}; \
	//	 push {r2}; \
	//	 ldr r1, [r0, #0x60]; \
	//	 \
	//	 ldr r1, [r0, #0x4]; \
	//	 ldr r2, [r0, #0x8]; \
	//	 ldr r3, [r0, #0xC]; \
	//	 ldr r4, [r0, #0x10]; \
	//	 ldr r5, [r0, #0x14]; \
	//	 ldr r6, [r0, #0x18]; \
	//	 ldr r7, [r0, #0x1C]; \
	//	 pop {r0}; \
	//	 pop {pc};"
	//	:\
	//	: "r"(x_reg) \
	//	:
	//);

	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"add r0, #1\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(ctx->uc_mcontext.arm_pc) \
	//	: "r0", "sp"
	//);

	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(ctx->uc_mcontext.arm_lr) \
	//	: "r0", "sp"
	//);

	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(x_reg[7]) \
	//	: "r0", "sp"
	//);

	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(x_reg[6]) \
	//	: "r0", "sp"
	//);

	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(x_reg[5]) \
	//	: "r0", "sp"
	//);

	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(x_reg[4]) \
	//	: "r0", "sp"
	//);
	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(x_reg[3]) \
	//	: "r0", "sp"
	//);
	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(x_reg[2]) \
	//	: "r0", "sp"
	//);
	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(x_reg[1]) \
	//	: "r0", "sp"
	//);
	//__asm __volatile
	//(
	//	"movs r0, %0\n\t" \
	//	"push {r0}\n\t" \
	//	: \
	//	: "r"(x_reg[0]) \
	//	: "r0", "sp"
	//);

	//__asm __volatile
	//(
	//	"pop {r0}\n\t" \
	//	"pop {r1}\n\t" \
	//	"pop {r2}\n\t" \
	//	"pop {r3}\n\t" \
	//	"pop {r4}\n\t" \
	//	"pop {r5}\n\t" \
	//	"pop {r6}\n\t" \
	//	"pop {r7}\n\t" \
	//	"pop {lr}\n\t" \

	//	"pop {pc}\n\t" \
	//);


}

static void install_segv_handler()
{
	struct sigaction sa = { 0 };
	sa.sa_sigaction = &_segv_handler;
	sa.sa_flags = SA_SIGINFO;
	struct sigaction osa = { 0 };
	sigaction(SIGSEGV, &sa, &osa);
}

static int xopen(const char* name)
{
	if (strchr(name, '/') != NULL)
	{
		int fd = TEMP_FAILURE_RETRY(open(name, O_RDONLY | O_CLOEXEC));
		if (fd != -1)
		{
			return fd;
		}
	}
	return RET_ERROR;
}

static void init_plk(const char* filename)
{
	xpltInfo = (PlkInfo*)malloc(BUF_SIZE);
	memset(xpltInfo, 0, BUF_SIZE);
	xgotInfo = (PlkInfo*)malloc(BUF_SIZE);
	memset(xgotInfo, 0, BUF_SIZE);
	xrodataInfo = (PlkInfo*)malloc(BUF_SIZE);
	memset(xrodataInfo, 0, BUF_SIZE);
	xbssInfo = (PlkInfo*)malloc(BUF_SIZE);
	memset(xbssInfo, 0, BUF_SIZE);

	int fd = 0;
	if ((fd = xopen(filename)) < 0)
	{
		LOGE("[-] xopen(%s) failed\n", filename);
		return;
	}

	struct stat st;
	if (fstat(fd, &st) == -1) {
		LOGE("[-] fstat error when init_plk\n", filename);
		close(fd);
		return;
	}

	char* plkBuf = (char*)mmap(NULL, st.st_size, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (plkBuf == NULL)
	{
		LOGE("[-] error in init_plk when mmap\n");
		close(fd);
		return;
	}
	cJSON* plkJson = cJSON_Parse(plkBuf);
	cJSON* pltArray = cJSON_GetObjectItem(plkJson, "plt");
	cJSON* gotArray = cJSON_GetObjectItem(plkJson, "got");
	cJSON* rodataArray = cJSON_GetObjectItem(plkJson, "rodata");
	cJSON* bssArray = cJSON_GetObjectItem(plkJson, "bss");

	int idx;
	for (idx = 0; idx < cJSON_GetArraySize(pltArray); ++idx)
	{
		cJSON* plkItem = cJSON_GetArrayItem(pltArray, idx);
		xpltInfo[idx].offset = cJSON_GetObjectItemCaseSensitive(plkItem, "off")->valueint;
		xpltInfo[idx].value = cJSON_GetObjectItemCaseSensitive(plkItem, "foo")->valuestring;
	}
	LOGD("[*] x_plt_size=%d\n", idx);

	for (idx = 0; idx < cJSON_GetArraySize(gotArray); ++idx)
	{
		cJSON* gotItem = cJSON_GetArrayItem(gotArray, idx);
		xgotInfo[idx].offset = cJSON_GetObjectItemCaseSensitive(gotItem, "off")->valueint;
		xgotInfo[idx].value = cJSON_GetObjectItemCaseSensitive(gotItem, "foo")->valuestring;
	}
	LOGD("[*] x_got_size=%d\n", idx);

	for (idx = 0; idx < cJSON_GetArraySize(rodataArray); ++idx)
	{
		cJSON* rodataItem = cJSON_GetArrayItem(rodataArray, idx);
		xrodataInfo[idx].offset = cJSON_GetObjectItemCaseSensitive(rodataItem, "off")->valueint;
		xrodataInfo[idx].value = cJSON_GetObjectItemCaseSensitive(rodataItem, "foo")->valuestring;
	}
	LOGD("[*] x_rodata_size=%d\n", idx);

	for (idx = 0; idx < cJSON_GetArraySize(bssArray); ++idx)
	{
		cJSON* bssItem = cJSON_GetArrayItem(bssArray, idx);
		xbssInfo[idx].offset = cJSON_GetObjectItemCaseSensitive(bssItem, "off")->valueint;
		xbssInfo[idx].value = cJSON_GetObjectItemCaseSensitive(bssItem, "foo")->valuestring;	// value in xbss item means offset to .bss segment
	}
	g_bss_base = malloc(BUF_SIZE);
	memset(g_bss_base, 0, BUF_SIZE);
	LOGD("[*] x_bss_size=%d\n", idx);

	munmap(plkBuf, st.st_size);
	close(fd);
}

void* xdlopen(const char* filename, const char* plkfile, int flags)
{
	int fd = 0;
	void* ret = NULL;
	unsigned char* xbuf = NULL;
	if ((fd = xopen(filename)) < 0)
	{
		LOGE("[-] xopen(%s) failed\n", filename);
		return NULL;
	}

	if ((flags & ~(XRTLD_NOW | XRTLD_LAZY | XRTLD_LOCAL | XRTLD_GLOBAL | XRTLD_XBIN)) != 0)
	{
		LOGE("[-] invalid flags to xdlopen: %x\n", flags);
		return NULL;
	}
	if ((flags & XRTLD_XBIN) != 0)
	{
		// load by .bin file and .plk file
		init_plk(plkfile);

		int xlen = lseek(fd, 0L, SEEK_END);
		if (xlen < 0)
		{
			LOGE("[-] lseek error in xdlopen");
			return NULL;
		}

		int xplen = xlen;
		if (xplen < 0xA000)
			xplen = 0xA000;

		lseek(fd, 0L, SEEK_SET);
		xbuf = (unsigned char*)((int)mmap(NULL, xplen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + PAGE_SIZE);

		LOGD("fct size: 0x%8x\n", xlen % PAGE_SIZE == 0 ? xlen : xlen + PAGE_SIZE - xlen % PAGE_SIZE);
		mprotect(xbuf, xlen % PAGE_SIZE == 0 ? xlen : xlen + PAGE_SIZE - xlen % PAGE_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE);
		//LOGD("fct size: %d\n", xlen % PAGE_SIZE == 0 ? xlen : xlen - xlen % PAGE_SIZE);
		//mprotect(xbuf, xlen % PAGE_SIZE == 0 ? xlen : xlen - xlen % PAGE_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE);

		int total_read = 0;
		int count = 0;
		while (total_read < xlen)
		{
			count = read(fd, xbuf, xlen - total_read);
			if (count < 0)
			{
				LOGE("[-] read xbin error in xdlopen");
				return NULL;
			}
			total_read += count;
		}

		// a. ----->  ...a1...  ->  .....a11 -> .......
		//               |             |

		// mmap 足够大的空间，并将rodata对应的偏移处置为不可读，xlinker在调用时会主动捕获这种不可读引起的异常，修复context后返回

		// Fix PLT： 代码从第二页开始加载，因此访问PLT时偏移位于第一页，第一页属性为PROT_NONE；malloc buf, 主动dlsym，置入正确的地址
		// Fix GOT: 目前GOT表中只额外修复__stack_chk_guard_ptr与__sF，malloc buf，__stack_chk_guard_ptr为任意值，__sF=stderr-0xA8
		// Fix rodata: malloc buf， 置入原始内容
		// Fix bss: malloc buf，置为0

		// offset 1E6C in test case is where to modify j_puts
		//void* imp_puts = dlsym(RTLD_DEFAULT, "puts");
		//LOGD("[*] Fix libc.puts=0x%08X\n", imp_puts);
		//unsigned char load_pc[8] = { 0x04, 0xF0, 0x1F, 0xE5 };	// LDR PC, [PC, #-4]
		//memcpy(load_pc + 4, &imp_puts, 4);
		//memcpy(xbuf + 0x1E6C, load_pc, 8);

		// Deprecated: nop canary, use regix to remove canary
		unsigned char nop_ins[16] = { 0x46, 0x00, 0x46, 0x00, 0x46, 0x00, 0x46, 0x00, 0x46, 0x00, 0x46, 0x00, 0x46, 0x00, 0x46, 0x00 };
		//memcpy(xbuf + 0x69E, nop_ins, 10);
		//memcpy(xbuf + 0x6EA, nop_ins, 14);

		memcpy(xbuf + 0x704, nop_ins, 8);
		unsigned char temp_ins[4] = { 0x24, 0xC6, 0x28 ,0x2E };
		memcpy(xbuf + 0x6B0, temp_ins, 1); // 修改跳转逻辑，测试plt与rodata修复效果

		// FIXME: If code and rodata in the same page?
		memcpy(xbuf + 0x7B8, temp_ins + 1, 2);	// 此处为测试数据，原rodata偏移为18C6，测试bin文件大小超过一页，因此部分数据处于同一页，这里强行改成28C6
		memcpy(xbuf + 0x281, temp_ins + 3, 1);

		//x_data_map.insert(std::pair<int, int>((int)xbuf + 0x1FD8, (int)xrel_str));
		//x_rodata_off = (int)xbuf + 0x712 + 0x28C6;


		xdyninfo* xi = (xdyninfo*)malloc(sizeof(xdyninfo) + 1);
		memset(xi, 0, sizeof(xdyninfo));

		xi->buffer = xbuf;
		g_xi = xi;
		return xi;
	}
	else
	{
		// normal dlopen
	}

	return ret;
}

void* xdlsym(void* handle, const char* symbol)
{

	xdyninfo* xi = (xdyninfo*)handle;
	if (xi == NULL)
	{
		LOGE("[-] xdlsym error: handle is NULL\n");
		return NULL;
	}

	if (strcmp(symbol, "main") == 0)
	{
		// FIXME: test main addr
		return (void*)((int)(xi->buffer) + 0x698);
	}
	return NULL;
}

int xdlclose(void* handle)
{
	return RET_OK;
}

int xexec(void* handle, void* addr)
{
	bool bxdyn = false;
	if (handle == NULL)
	{
		LOGE("[-] xexec failed, handle is NULL.\n");
		return RET_ERROR;
	}

	if (((char*)handle)[EI_MAG0] == ELFMAG0)
	{
		bxdyn = false;
	}
	else if (((char*)handle)[EI_MAG0] == XELFMAG0)
	{
		bxdyn = true;
	}
	if (addr == NULL)
	{
		// exec main in handle
		if (bxdyn)
		{
		}
		else
		{
			// normal ELF file, just find main
		}
	}
	else
	{
	}
	return RET_OK;
}

typedef int (*FUNC_MAIN)(int argc, char** argv);

int main(int argc, char** argv)
{
	if (argc != 2 && argc != 3)
	{
		LOGW("USAGE: xlinker <path_to_exec_file>\n");
		LOGW("  -x <path_to_rel_file>, use X mode linker\n");
		LOGW("--------------------------------------------------------------------\n");
		LOGW("EXAMPLE(x_mode): xlinker /data/local/tmp/test.bin /data/loca/tmp/test.plk\n");
		LOGW("EXAMPLE(normal): xlinker /data/local/tmp/test\n");
		// LOGW("               Default Symbol Name is \"main\", and Polymorphism is Not Support YET\n");
		return RET_ERROR;
	}

	install_segv_handler();

	void* xhandle = NULL;
	if (argc == 3)
		xhandle = xdlopen(argv[1], argv[2], XRTLD_XBIN);
	else
		xhandle = xdlopen(argv[1], NULL, XRTLD_XBIN);

	if (xhandle == NULL)
	{
		LOGE("[-] xhandle parse failed\n");
		return RET_ERROR;
	}

	LOGD("[+] XLINKER: xdlopen handle=%p\n", xhandle);

	FUNC_MAIN func_main = (FUNC_MAIN)((int)xdlsym(xhandle, "main") + 1);

	LOGD("[+] XLINKER: main_func=%p\n", func_main);

	func_main(1, argv + 1);

	return RET_OK;
}