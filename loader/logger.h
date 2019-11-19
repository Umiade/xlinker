#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_DEBUG
#define LOG_TAG "X_LINKER"

#ifdef LOG_DEBUG
#define LOGI(fmt, args...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, fmt, ##args);
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args);
#define LOGE(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##args);
#define LOGW(fmt, args...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, fmt, ##args);
#define LOGF(fmt, args...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, fmt, ##args);

#define printBuffer(buf, len) printBuf((unsigned char *)buf, (int)len)

static void printBuf(unsigned char* buf, int len)
{
	char b[1024] = { 0 };
	int i = 0;
	for (i = 0; i < len; i++)
	{
		sprintf(b + (i % 100) * 3, "%02X ", buf[i]);
		if (((i + 1) % 100) == 0)
		{
			LOGD("%s", b);
			memset(b, 0, sizeof(b));
		}
	}
	if ((i % 100) != 0)
	{
		LOGD("%s", b);
	}
	LOGD("\n");
}

#else
#define printBuffer(buf, len)
#define LOGI(fmt, args...)
#define LOGD(fmt, args...)
#define LOGE(fmt, args...)
#define LOGW(fmt, args...)
#define LOGF(fmt, args...)
#endif
