LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := got_hook
LOCAL_SRC_FILES := got_hook.cpp
LOCAL_LDLIBS := -llog 
LOCAL_DISABLE_FORMAT_STRING_CHECKS := true

include $(BUILD_SHARED_LIBRARY)
