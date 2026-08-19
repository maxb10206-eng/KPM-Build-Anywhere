# Makefile for Kernel Patch Module (KPM) build system

ifeq ($(OS), Windows_NT)
    PLATFORM := windows-x86_64
else
    PLATFORM := linux-x86_64
endif

ifndef TARGET_COMPILE
    NDK_PATH := $(shell echo $(NDK_PATH))
    export TARGET_COMPILE=$(NDK_PATH)/toolchains/llvm/prebuilt/$(PLATFORM)/bin/
endif

ifndef KP_DIR
    KP_DIR := ../KernelPatch-0.11.3
endif

ifndef KERNEL_DIR
    KERNEL_DIR := ../android_kernel_modules_and_devicetree_oneplus_sm8450-oneplus-sm8450_b_16.0_oneplus_10_pro
endif

CC = $(TARGET_COMPILE)aarch64-linux-android31-clang
LD = $(TARGET_COMPILE)ld.lld
AS = $(TARGET_COMPILE)llvm-as
OBJCOPY = $(TARGET_COMPILE)llvm-objcopy
STRIP = $(TARGET_COMPILE)llvm-strip

KP_INCLUDE_DIRS := \
    . \
    include \
    patch/include \
    linux/include \
    linux/arch/arm64/include \
    linux/tools/arch/arm64/include

CAMERA_INCLUDE_DIRS := \
    $(KERNEL_DIR)/vendor/qcom/opensource/camera-kernel/include/uapi \
    $(KERNEL_DIR)/vendor/qcom/opensource/camera-kernel/drivers

KP_INCLUDE_FLAGS := $(foreach dir,$(KP_INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))
CAMERA_INCLUDE_FLAGS := $(foreach dir,$(CAMERA_INCLUDE_DIRS),-I$(dir))

CFLAGS = \
    $(KP_INCLUDE_FLAGS) \
    $(CAMERA_INCLUDE_FLAGS) \
    -Wall \
    -Ofast \
    -fno-PIC \
    -fno-asynchronous-unwind-tables \
    -fno-stack-protector \
    -fno-unwind-tables \
    -fno-semantic-interposition \
    -U_FORTIFY_SOURCE \
    -fno-common \
    -fvisibility=hidden

LDFLAGS += -s

objs := hello.o

all: hello.kpm

hello.kpm: $(objs)
	$(CC) $(LDFLAGS) -r -o $@ $^
	$(STRIP) -g --strip-unneeded --strip-debug \
		--remove-section=.comment \
		--remove-section=.note.GNU-stack $@

%.o: %.c
	$(CC) $(CFLAGS) -Thello.lds -c -O2 -o $@ $<

.PHONY: clean
ifeq ($(OS), Windows_NT)
clean:
	del /Q *.o *.kpm
else
clean:
	rm -rf *.o *.kpm
endif
