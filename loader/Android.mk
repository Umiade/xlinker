LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie 
LOCAL_MODULE := xlinker
LOCAL_SRC_FILES := cJSON.c cJSON_Utils.c xlinker.cpp
LOCAL_LDLIBS += -llog
include $(BUILD_EXECUTABLE)
