#
# Copyright (C) 2014 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=netmap
PKG_VERSION:=1
PKG_RELEASE:=$(PKG_SOURCE_VERSION)

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_URL:=/home/giuseppe/Compile/netmap-git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=ab0a4789d1277a5263b33de5969f58c8305986a8
PKG_MAINTAINER:=Giuseppe Lettieri <g.lettieri@iet.unipi.it>

include $(INCLUDE_DIR)/package.mk

define KernelPackage/netmap
  TITLE:=Netmap
  SECTION:=kernel
  SUBMENU:=Other modules
  FILES:=$(PKG_BUILD_DIR)/LINUX/netmap_lin.ko
  AUTOLOAD:=$(call AutoLoad,80,netmap_lin)
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Configure
	( \
	    cd $(PKG_BUILD_DIR)/LINUX; \
	    ./configure \
	        --kernel-dir=$(LINUX_DIR) \
	        --kernel-opts=" \
		    CROSS_COMPILE=$(TARGET_CROSS) \
		    ARCH=$(LINUX_KARCH) \
		    PATH=$(TARGET_PATH) \
	        " \
		--cc="$(TARGET_CC) $(TARGET_CFLAGS)" \
		--ld="$(TARGET_CC) $(TARGET_LDFLAGS)" \
		--prefix=/usr \
	)
endef

define Build/Compile
	( \
	    cd $(PKG_BUILD_DIR)/LINUX; \
	    make; \
	    make apps; \
	)
endef

define Build/Install
	( \
	    cd $(PKG_BUILD_DIR)/LINUX; \
	    make install-apps DESTDIR=$(1); \
	)
endef

$(eval $(call KernelPackage,netmap))
