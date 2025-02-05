/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */
#ifndef TA_HELLO_WORLD_H
#define TA_HELLO_WORLD_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */

#define HELLO_WORLD_UUID \
	{ 0x93d762de, 0x4610, 0x4eec, \
    	{ 0xb0, 0x0c, 0xc3, 0x2d, 0x06, 0x5c, 0xf0, 0x85 } }
/* The function IDs implemented in this TA */
#define HELLO_WORLD_CMD_SAY_HELLO	1

#endif /*TA_HELLO_WORLD_H*/
