#pragma once

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" 
{
#endif

#define RET_OK 0
#define RET_ERROR -1

#define DYN_PRELINK_SUFFIX ".plk"

	struct xdyninfo
	{
		char magic[4];
		unsigned char* buffer;
	};

	void* xdlopen(const char* filename, const char* plkfile, int flags);    // dlopen normal so files | Load shelled "bin" file, link-rel with ".plk" file
	void* xdlsym(void* handle, const char* symbol); // dlsym normal symbol in so files | find symbol in bin file, process splited decrypt
	int xdlclose(void* handle);
	const char* xdlerror(void);

	int xexec(void* handle, void* addr = NULL);

	struct PlkInfo
	{
		int offset;
		char* value;
	};

	enum {
		x_stub___libc_init = 0xdead0000,
		x_stub___cxa_atexit = 0xdead0001,
		x_stub___aeabi_memclr4 = 0xdead0002,
		x_stub_sprintf,
		x_stub_strcpy,
		x_stub__feof,
		x_stub_fgets,
		x_stub_strlen,
		x_stub_strncasecmp,
		x_stub_fwrite,
		x_stub___aeabi_memcpy4,
		x_stub_strncpy,
		x_stub___stack_chk_fail,
		x_stub_fopen,
		x_stub_fclose,
		x_stub_fprintf,
		x_stub_fseek,
		x_stub_ftell,
		x_stub___aeabi_memclr,
		x_stub_strcmp,
		x_stub_strcat,
		x_stub_fgetc,
		x_stub_strchr,
		x_stub_remove,
		x_stub_fputs,
		x_stub_printf,
		x_stub_puts,
		x_stub___gnu_Unwind_Find_exidx,
		x_stub_abort,
		x_stub_memcpy,
		x_stub___cxa_begin_cleanup,
		x_stub___cxa_type_match,
	};

	enum {
		XRTLD_NOW = 0,
		XRTLD_LAZY = 1,

		XRTLD_LOCAL = 0,
		XRTLD_GLOBAL = 2,
	};

//#define PAGE_SHIFT 12
//#define PAGE_SIZE (1UL << PAGE_SHIFT)
//#define PAGE_MASK (~(PAGE_SIZE-1))

#define REG_MAX 8

#define XRTLD_XBIN  4   // use xbin mode by pattern '-x'

#define XRTLD_DEFAULT  ((void*) 0xffffffff)
#define XRTLD_NEXT     ((void*) 0xfffffffe)




#ifdef __cplusplus
}
#endif
