/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <ta_test.h>
#include <ta_hello_world.h>
#include <ta_increment.h>

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;

	TEEC_Session sess;
	TEEC_Session sess_hello_world;
	TEEC_Session sess_increment;

	TEEC_Operation op;
	TEEC_Operation op_hello_world;
	TEEC_Operation op_increment;

	TEEC_UUID uuid = TA_TEST_UUID;
	TEEC_UUID uuid_hello_world = HELLO_WORLD_UUID;
	TEEC_UUID uuid_increment = INCREMENT_UUID;
	
	uint32_t err_origin;

	//////////////////////////
	// Initialize a context //
	//////////////////////////
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	///////////////////
	// Open sessions //
	///////////////////

	// (base) Open a session to the TA
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	else
		printf("Opened session to TA\n");
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 42;
	// (hello world) Open a session to the TA
	res = TEEC_OpenSession(&ctx, &sess_hello_world, &uuid_hello_world,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS){
printf("(hello world) failed to Open session to TA\n");
		errx(1, "(hello world) TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	}
	else
printf("(hello world) Opened session to TA\n");

	// (increment) Open a session to the TA
	res = TEEC_OpenSession(&ctx, &sess_increment, &uuid_increment,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS){
printf("(increment) failed to Open session to TA\n");
		errx(1, "(increment) TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	}
	else
printf("(increment) Opened session to TA\n");
	memset(&op_increment, 0, sizeof(op));

	op_increment.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op_increment.params[0].value.a = 111;

	////////////////////
	// Invoke Command //
	////////////////////

	// (base) Invoke command to the TA
	printf("Invoking TA to increment %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_TEST_CMD_INC_VALUE, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("TA incremented value to %d\n", op.params[0].value.a);
	// (hello world) Invoke command to the TA
	printf("(hello world) Invoking TA to say hello world\n");
	res = TEEC_InvokeCommand(&sess_hello_world, HELLO_WORLD_CMD_SAY_HELLO, NULL,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "(hello world) TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("(hello world) TA said hello world\n");
	// (increment) Invoke command to the TA
	printf("(increment) Invoking TA to increment %d\n", op_increment.params[0].value.a);
	res = TEEC_InvokeCommand(&sess_increment, INCREMENT_CMD_INC_VALUE, &op_increment,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "(increment) TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	printf("(increment) TA incremented value to %d\n", op_increment.params[0].value.a);


	////////////////////
	// Close sessions //
	////////////////////

	TEEC_CloseSession(&sess);
	TEEC_CloseSession(&sess_hello_world);
	TEEC_CloseSession(&sess_increment);

	//////////////////////////
	// Finalize the context //
	//////////////////////////

	TEEC_FinalizeContext(&ctx);
printf("Completed Successfully\n");
	return 0;
}
