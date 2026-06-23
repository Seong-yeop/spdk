#  SPDX-License-Identifier: BSD-3-Clause

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 1
SO_MINOR := 0

LIBNAME = sock_iip
C_SRCS = iip.c

CFLAGS += $(ENV_CFLAGS)
CFLAGS += -Wno-unused-function

ifeq ($(IIP_SOCK_TRACE_LOG),y)
CFLAGS += -DIIP_SOCK_ENABLE_TRACE_LOG
endif

ifeq ($(IIP_SOCK_DEBUG_LOG),y)
CFLAGS += -DIIP_SOCK_ENABLE_DEBUG_LOG
endif

SPDK_MAP_FILE = $(SPDK_ROOT_DIR)/mk/spdk_blank.map

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
