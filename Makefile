ARCHS = armv7 arm64
THEOS_DEVICE_IP = 192.168.1.4
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = CheckSandbox0Day

CheckSandbox0Day_FILES = Tweak.x
CheckSandbox0Day_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
