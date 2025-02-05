/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_test.h>

#define TA_UUID				TA_TEST_UUID

#define TA_FLAGS			TA_FLAG_EXEC_DDR
#define TA_STACK_SIZE			(2 * 1024)
#define TA_DATA_SIZE			(32 * 1024)
#define TA_VERSION	"1.0"
#define TA_DESCRIPTION	"Example of OP-TEE Hello World Trusted Application"
#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "org.linaro.optee.examples.hello_world.property1", \
	USER_TA_PROP_TYPE_STRING, \
        "Some string" }, \
    { "org.linaro.optee.examples.hello_world.property2", \
	USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif /* USER_TA_HEADER_DEFINES_H */
