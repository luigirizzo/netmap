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
PKG_SOURCE_VERSION:=1ac2b984c13489c893ca7448d1e024b67526afbf
PKG_MAINTAINER:=Giuseppe Lettieri <g.lettieri@iet.unipi.it>

include $(INCLUDE_DIR)/package.mk

define KernelPackage/netmap
  TITLE:=Netmap
  SECTION:=kernel
  SUBMENU:=Other modules
  FILES:=$(PKG_BUILD_DIR)/LINUX/netmap.ko
  AUTOLOAD:=$(call AutoLoad,80,netmap)
endef

define KernelPackage/r8169-netmap
  TITLE:=Netmap enabled r8169 driver
  SECTION:=kernel
  SUBMENU:=Other modules
  DEPENDS:= +kmod-netmap
  FILES=$(wildcard $(PKG_BUILD_DIR)/LINUX/r8169-netmap.ko)
endef

define KernelPackage/e1000-netmap
  TITLE:=Netmap enabled e1000 driver
  SECTION:=kernel
  SUBMENU:=Other modules
  DEPENDS:= +kmod-netmap
  FILES=$(wildcard $(PKG_BUILD_DIR)/LINUX/e1000/e1000-netmap.ko)
endef

define KernelPackage/e1000e-netmap
  TITLE:=Netmap enabled e1000e driver
  SECTION:=kernel
  SUBMENU:=Other modules
  DEPENDS:= +kmod-netmap +kmod-ptp
  FILES=$(wildcard $(PKG_BUILD_DIR)/LINUX/e1000e/e1000e-netmap.ko)
endef

define KernelPackage/igb-netmap
  TITLE:=Netmap enabled igb driver
  SECTION:=kernel
  SUBMENU:=Other modules
  DEPENDS:= +kmod-netmap +kmod-i2c-algo-bit +kmod-i2c-core +kmod-ptp
  FILES=$(wildcard $(PKG_BUILD_DIR)/LINUX/igb/igb-netmap.ko)
endef

# mdio is missing
#define KernelPackage/ixgbe-netmap
#  TITLE:=Netmap enabled ixgbe driver
#  SECTION:=kernel
#  SUBMENU:=Other modules
#  DEPENDS:= +kmod-netmap +kmod-ptp +kmod-mdio
#  FILES=$(wildcard $(PKG_BUILD_DIR)/LINUX/ixgbe/ixgbe-netmap.ko)
#endef

define KernelPackage/forcedeth-netmap
  TITLE:=Netmap enabled forcedeth driver
  SECTION:=kernel
  SUBMENU:=Other modules
  DEPENDS:= +kmod-netmap
  FILES=$(wildcard $(PKG_BUILD_DIR)/LINUX/forcedeth-netmap.ko)
endef

define Package/netmap-utils
  TITLE:=Netmap utils (pkt-gen, vale-ctl, bridge)
  DEPENDS:= +kmod-netmap
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:= +libpthreads +librt
endef

include $(INCLUDE_DIR)/kernel-defaults.mk

define Build/Configure
	( \
	    cd $(PKG_BUILD_DIR)/LINUX; \
	    CONFIG_R8169=m \
	    CONFIG_E1000=m \
	    CONFIG_E1000E=m \
	    CONFIG_IGB=m \
	    CONFIG_IXGBE=m \
	    CONFIG_FORCEDETH=m \
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
		--driver-suffix=-netmap \
	)
endef

define Build/Compile
	( \
	    cd $(PKG_BUILD_DIR)/LINUX; \
	    make; \
	    make apps; \
	)
endef

define Package/netmap-utils/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/examples/pkt-gen $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/examples/vale-ctl $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/examples/bridge $(1)/usr/bin
endef

$(eval $(call KernelPackage,netmap))
$(eval $(call KernelPackage,r8169-netmap))
$(eval $(call KernelPackage,e1000-netmap))
$(eval $(call KernelPackage,e1000e-netmap))
$(eval $(call KernelPackage,igb-netmap))
#$(eval $(call KernelPackage,ixgbe-netmap))
$(eval $(call KernelPackage,forcedeth-netmap))
$(eval $(call BuildPackage,netmap-utils))
