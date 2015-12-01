/* Copyright (C) 2015 Steve Kim (ssekim at gmail.com), MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "ets_sys.h"
#include "user_interface.h"
#include "driver/uart.h"

#include "netif/etharp.h"

#include "menu-functions.h"
#include "misc-functions.h"

char g_szDebug[256] = {0,};

void *meminmem(const void *b1, const void *b2, size_t len1, size_t len2)
{
	char *sp = (char *) b1;
	char *pp = (char *) b2;

	char *eos   = sp + len1 - len2;

	if(!(b1 && b2 && len1 && len2))
		return NULL;

	while (sp <= eos)
	{
		if (*sp == *pp)
			if (memcmp(sp, pp, len2) == 0)
				return sp;
		sp++;
	}

	return NULL;
}


void print_hex_line(uint8 *payload, int32 len, int32 offset)
{
	int32 i;
	int32 gap;
	uint8 *ch;

	ets_uart_printf("%08x   ", (uint32)(payload));

	ch = payload;
	for(i = 0; i < len; i++)
	{
		ets_uart_printf("%02x ", *ch);

		ch++;
		if ( i == 7 )			ets_uart_printf(" ");
	}
	if ( len < 8 )		ets_uart_printf(" ");

	if ( len < 16 )
	{
		gap = 16 - len;
		for(i = 0; i < gap; i++)
			ets_uart_printf("   ");
	}
	ets_uart_printf("   ");

	ch = payload;
	for(i = 0; i < len; i++)
	{
		if ( isprint(*ch) )		ets_uart_printf("%c", *ch);
		else					ets_uart_printf(".");
		ch++;
	}

	ets_uart_printf("\r\n");
	return;
}

void wdump(uint8 *payload, int32 len)
{
	int32 len_rem = len;
	int32 line_width = 16;
	int32 line_len;
	int32 offset = 0;
	uint8 *ch = payload;

	if ( len <= 0 )
	{
		return;
	}

	if ( len <= line_width )
	{
		print_hex_line(ch, len, offset);
		return;
	}

	for(;;)
	{
		line_len = line_width % len_rem;
		print_hex_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if ( len_rem <= line_width )
		{
			print_hex_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void dump_ethernet_raw_packet(uint8 bInput, char* szMessage, uint8 *payload, int32 len)
{
	extern int g_modePacketDump;
	extern int g_modePacketInfo;
	extern uint8_t g_macFilterUse;
	extern uint8_t g_macFilter1[6];
	extern uint8_t g_macFilter2[6];

	if ( g_macFilterUse )
	{
		if ( memcmp(payload, g_macFilter1, 6)==0 && memcmp(payload+6, g_macFilter1, 6)==0 && memcmp(payload+6, g_macFilter2, 6)==0 && memcmp(payload+6, g_macFilter2, 6)==0 )
		{
			return;
		}
	}

	if ( g_modePacketDump==1 )
	{
		ets_uart_printf(szMessage);
		ets_uart_printf(" (%d)\r\n", len);
		wdump(payload, len);
	}

	if ( g_modePacketInfo==1 )
	{
		void packet_handler(uint32_t packet_length, const uint8_t *packet);
		packet_handler(len, payload);
	}
}


void ethernet_raw_packet_tx(uint8_t* source_packet, uint16_t len_packet, uint16_t ref)
{
	struct pbuf *p = 0;
	p = pbuf_alloc(PBUF_RAW, SIZEOF_ETHARP_PACKET, PBUF_RAM);
	if (p == NULL) {
		ets_uart_printf("ethernet_raw_packet_tx alloc error \r\n");
		return;
	}

	memcpy((uint8_t*)(p->payload), (uint8_t*)source_packet, len_packet);

	p->tot_len = len_packet;
	p->len = len_packet;
	p->ref = ref;

	//dump_ethernet_raw_packet(0, "Ethernet Output(user packet)", p->payload, p->tot_len);
	netif_default->linkoutput(netif_default, p);

	pbuf_free(p);
}

