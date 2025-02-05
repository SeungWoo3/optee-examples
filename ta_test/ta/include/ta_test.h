/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */
#ifndef TA_TEST_H
#define TA_TEST_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_TEST_UUID \
	{ 0xdff685a8, 0x9a43, 0x47c4, \
		{ 0xba, 0xa9, 0x83, 0x37, 0xd2, 0x6b, 0x08, 0x0c} }
/* The function IDs implemented in this TA */
#define TA_TEST_CMD_INC_VALUE		0
#define TA_TEST_CMD_DEC_VALUE		1

#endif /*TA_TEST_H*/
