include $(TOPDIR)/rules.mk

PKG_NAME:=l2access
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/unitednf/l2access.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=HEAD
PKG_SOURCE_DATE:=2026-03-12
PKG_BUILD_DEPENDS:=rust/host

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/../feeds/packages/lang/rust/rust-package.mk

define Package/l2access
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Secure L2-tunnelled IP connectivity
  DEPENDS:=+libip4tc +libip6tc +ip-full
endef

define Package/l2access/description
  Secure, zero-configuration L2-tunnelled IP connectivity over local networks.
  Provides a fast userspace tunneling app utilizing ChaCha20Poly1305.
endef

define Package/l2access/conffiles
/etc/config/l2access
endef

define Package/l2access/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/l2access $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/l2access.config $(1)/etc/config/l2access
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/l2access.init $(1)/etc/init.d/l2access
endef

define Package/l2access/prerm
#!/bin/sh
if [ -x /etc/init.d/l2access ]; then
	/etc/init.d/l2access stop || true
	/etc/init.d/l2access cleanup || true
	/etc/init.d/l2access disable || true
fi
exit 0
endef

# Let the rust-package.mk module handle the Cargo build wrapper
$(eval $(call BuildPackage,l2access))
