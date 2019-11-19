# XLINKER

## 0x00 简介
最近在思考“如何在划水的同时让自己觉得不是在划水”，再加上一直对无源码的so加固方案有些兴趣，就找了自定义linker实现加固的方向在慢慢琢磨。
然而想着想着思路慢慢歪了，就有了这个四不像的玩意，于是就想着把这个思路分享给大家。当然目前只是一个demo版本，大部分工作只是完成了一个可以直接运行text段指令的自定义linker，距离真正意义上的加固还有很大的距离。

目前实现了如下的功能
- 将ELF转成只含有text段的bin文件，plt, got, rodata, bss等信息用另一个plk(prelink)文件保存下来
- 自定义linker加载bin文件，mmap 足够大的PROT_NONE空间，把text段读到这块空间，text段所在的页改成可执行
- 捕获访问plt/got/bss/rodata时抛出的segv异常，结合plk文件修复上下文

## 0x01 原理
xlinker的实现分为parser和loader两部分。
parser用以解析正常ELF文件，提取出其中的代码段，保存为.bin文件，并将解析获得的plt, got, rodata, bss等信息用json的形式保存下来，后简称plk；
loader即自定义的linker，加载bin，结合plk完成一系列的修复操作。
由于parser部分的代码还有不少坑需要填，这里主要讲loader这一块。

### 0x010 加载
首先以PROT_NONE mmap足够大的页空间，从第二页开始将只含有指令数据的bin文件加载进来，并赋予bin文件所在的页以可读可写可执行的属性。这样
```
int xlen = lseek(fd, 0L, SEEK_END);
if (xlen < 0)
{
	LOGE("[-] lseek error in xdlopen");
	return NULL;
}

int xplen = xlen;
if (xplen < 0xA000)
	xplen = 0xA000;	// 这里为了偷懒，写死了0xA000大小的空间，可以适当增大，或通过解析原ELF得出一个合适的值

lseek(fd, 0L, SEEK_SET);
xbuf = (unsigned char*)((int)mmap(NULL, xplen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) + PAGE_SIZE);

LOGD("fct size: 0x%8x\n", xlen % PAGE_SIZE == 0 ? xlen : xlen + PAGE_SIZE - xlen % PAGE_SIZE);
mprotect(xbuf, xlen % PAGE_SIZE == 0 ? xlen : xlen + PAGE_SIZE - xlen % PAGE_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE);
```

接下里解析plk文件，获取数据以及重定位相关的信息，plk文件形如
```
{
    "plt": [
        {
            "off": -384,
            "foo": "_libc_init"
        },
		....
		,
        {
            "off": -36,
            "foo": "memcpy"
        },
        {
            "off": -24,
            "foo": "__cxa_begin_cleanup"
        },
        {
            "off": -12,
            "foo": "__cxa_type_match"
        }
    ],
    "got": [
        {
            "off": 13352,
            "foo": "__stack_chk_guard_ptr"
        },
        {
            "off": 13356,
            "foo": "__sF"
        }
    ],
    "rodata": [
        {
            "off": 12232,
            "foo": "[%s]"
        },
        {
            "off": 12248,
            "foo": "[+] dm patch success"
        }
    ],
    "bss": [
        {
            "off": 13528,
            "foo": "0"
        }
    ]
}
```
其中off表示距离代码加载基址的偏移，foo的含义视类型而定。plt项中foo表示符号名；got中表示全局变量名，由于plt在实现上先于got修复，这里为了实现方便（偷懒）只对canary指针和标准io流指针做了记录；rodata中foo表示常量的内容，这里未对字符串以外的内容做处理，需要继续完善；bss中foo代表变量距离bss段首地址的偏移。
将上述内容保存在内存中，修复因PROT_NONE引起的段错误时会用到。

### 0x010 修复
首先需要设定segv_handler。
```
struct sigaction sa = { 0 };
sa.sa_sigaction = &_segv_handler;
sa.sa_flags = SA_SIGINFO;
struct sigaction osa = { 0 };
sigaction(SIGSEGV, &sa, &osa);

```
由于sa_flags = SA_SIGINFO，handler声明形如`_segv_handler(int signal_number, siginfo_t* si, void* context)`，这里主要的思路就是主动去修改context中寄存器因为PROT_NONE而无法访问的内存地址的值，再return，利用内核jump会出错时的位置重新执行，重新执行时的上下文即为参数中context。
在摸索过程中一开始并没有意识到这一点，尝试用内联汇编修改寄存器以后主动pop pc跳回目标位置，但由于sp难以恢复到出错时的值，所以最后没有采用。这里一并分享给大家，可以主动恢复除了sp以外的寄存器。
```
__asm__
(
	"mov r0, %0; \
	 ldr r2, [r0, #0x0]; \
	 ldr r1, [r0, #0x20]; \
	 mov r8, r1; \
	 ldr r1, [r0, #0x24]; \
	 mov r9, r1; \
	 ldr r1, [r0, #0x28]; \
	 mov r10, r1; \
	 ldr r1, [r0, #0x2C]; \
	 mov r11, r1; \
	 ldr r1, [r0, #0x30]; \
	 mov r12, r1; \
	 ldr r1, [r0, #0x34]; \
	 mov r13, r1; \
	 ldr r1, [r0, #0x38]; \
	 mov r14, r1; \
	 ldr r1, [r0, #0x3C]; \
	 mov r3, #1; \
	 orr r1, r3; \
	 push {r1}; \
	 push {r2}; \
	 ldr r1, [r0, #0x4]; \
	 ldr r2, [r0, #0x8]; \
	 ldr r3, [r0, #0xC]; \
	 ldr r4, [r0, #0x10]; \
	 ldr r5, [r0, #0x14]; \
	 ldr r6, [r0, #0x18]; \
	 ldr r7, [r0, #0x1C]; \
	 pop {r0}; \
	 pop {pc};"
	:\
	: "r"(x_reg) \
	:
);

```
而在实际实现中，由于只需修改context寄存器中存在异常的值，因此代码也比较简单，遍历一下解析的plk信息，遍历各个寄存器即可。
修复plt的代码如下：
```
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
```
xpltInfo中offset即为json中的off，value为foo。ctx+0x20的位置为r0的偏移，依次递增，0x60的位置为cpsr。
又由于调用plt桩的代码会用到形如add pc, r12, pc的指令，不能像bx,ldr一样有切换arm/thumb的效果。

这里需要根据dlsym获取的地址最低位判断是arm还是thumb，并强制修改CPSR中的T位。

在修复got段的全局变量时，只对\__stack_chk_guard_ptr与__sF做了记录，因此在代码里也写死处理了，需要后续完善。
```
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
```


got,rodata,bss的修复代码也类似，这里不再赘述，具体可见源码。

## 0x02 待续
### 0x020 开源地址
[https://github.com/Umiade/xlinker](https://github.com/Umiade/xlinker)
parser代码目前有不少坑要填，后面再传了（
### 0x021 运行demo
执行loader目录中的build脚本，将编译出来的xlinker可执行文件、test/dm.bin与test/dm.plk push到手机，如/data/local/tmp目录，
执行如下命令：
```
./xlinker /data/local/tmp/dm_bin /data/local/tmp/dm.plk
```


### 0x022 存在的坑
1. 目前仅仅实现了对bin文件的dlopen；
2. 未实现自定义的dlsym，demo代码的main函数偏移是写死的；
3. 对于rodata，存在由于文件过小，有部分内容与text段尾部的代码处于同一页的情况，demo中通过直接修改二进制的形式将访问rodata的偏移量增大了一个页的大小；
4. 琢磨的时候代码是想到哪写到哪，所以可能会有比较“神秘”的声明和注释，无视即可；
5. 由于指令和数据的分离，可以在加载、修复时加入加解密、压缩等操作，勉强当成一个简单的加固工具来用，但这种实现是否存在性能上的问题还有待验证。

....

