# ****************************************************************************
#    Ledger App Boilerplate
#    (c) 2020 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

APPNAME      = "BTEC"
APPVERSION_M = 1
APPVERSION_N = 0
APPVERSION_P = 0
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = btec

APP_LOAD_PARAMS += --curve secp256k1
APP_LOAD_PARAMS += --path "44'/60'" --path "12381/3600" --curve bls12381g1

ifeq ($(TARGET_NAME),TARGET_NANOS)
    ICONNAME=icons/nanos_app_btec.gif
else ifeq ($(TARGET_NAME),TARGET_STAX)
    ICONNAME=icons/stax_app_btec_32px.gif
else
    ICONNAME=icons/nanox_app_btec.gif
endif

ENABLE_BLUETOOTH = 0

# Enabling DEBUG flag will enable PRINTF and disable optimizations
DEBUG ?= 0

ENABLE_NBGL_QRCODE   = 1
ENABLE_NBGL_KEYBOARD = 0
ENABLE_NBGL_KEYPAD   = 0

DEFINES += HAVE_BLS

APP_SOURCE_PATH += src

#CUSTOM_APP_FLAGS = 0x000 # Set custom flags here, see appflags.h in SDK for flags definition
#DISABLE_STANDARD_APP_FILES = 1
#DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1 # To allow custom size declaration

#DISABLE_STANDARD_APP_DEFINES = 1 # Will set all the following disablers
#DISABLE_STANDARD_SNPRINTF = 1
#DISABLE_STANDARD_USB = 1
#DISABLE_STANDARD_WEBUSB = 1
#DISABLE_STANDARD_BAGL_UX_FLOW = 1

include $(BOLOS_SDK)/Makefile.standard_app
