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

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEST_UUID;
	uint32_t err_origin;

printf("II\n");
	//////////////////////////
	// Initialize a context //
	//////////////////////////
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
printf("II\n");

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
printf("I\n");

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
printf("I\n");


	////////////////////
	// Close sessions //
	////////////////////

	TEEC_CloseSession(&sess);
printf("I\n");	

	//////////////////////////
	// Finalize the context //
	//////////////////////////

	TEEC_FinalizeContext(&ctx);
printf("I\n");
	return 0;
}
