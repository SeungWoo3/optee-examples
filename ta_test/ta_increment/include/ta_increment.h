/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */
#ifndef TA_INCREMENT_H
#define TA_INCREMENT_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define INCREMENT_UUID \
	{ 0x8e699853, 0x8728, 0x4c9e, \
	    { 0x82, 0x13, 0x41, 0x12, 0xf7, 0x37, 0x09, 0x3f } }
/* The function IDs implemented in this TA */
#define INCREMENT_CMD_INC_VALUE		0
#define INCREMENT_CMD_DEC_VALUE		1

#endif /*TA_INCREMENT_H*/
