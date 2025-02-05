# Modify TA root Makefile
TARGET_DIR := $(notdir $(shell pwd))

.PHONY: all
all:
	$(MAKE) -C ta \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) \
		O=$(O)/ta/$(TARGET_DIR)
	$(MAKE) -C ta_hello_world \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) \
		O=$(O)/ta_hello_world/$(TARGET_DIR)
	$(MAKE) -C ta_increment \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) \
		O=$(O)/ta_increment/$(TARGET_DIR)
	$(MAKE) -C host \
		CROSS_COMPILE=$(CROSS_COMPILE) \
		OPTEE_CLIENT_EXPORT=$(OPTEE_CLIENT_EXPORT) \
		O=$(O)/ca/$(TARGET_DIR) \
		--no-builtin-variables

.PHONY: clean
clean:
	$(MAKE) -C ta \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) \
		O=$(O)/ta/$(TARGET_DIR) \
		clean
	$(MAKE) -C ta_hello_world \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) \
		O=$(O)/ta_hello_world/$(TARGET_DIR) \
		clean
	$(MAKE) -C ta_increment \
		TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR) \
		O=$(O)/ta_increment/$(TARGET_DIR) \
		clean
	$(MAKE) -C host \
		OPTEE_CLIENT_EXPORT=$(OPTEE_CLIENT_EXPORT) \
		O=$(O)/ca/$(TARGET_DIR) \
		clean
	rm -rf $(O)/ca/$(TARGET_DIR)
