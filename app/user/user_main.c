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

#include "driver/spi.h"
#include "driver/gpio16.h"

#include "menu-functions.h"
#include "misc-functions.h"


os_event_t uart_recvTaskQueue[uart_recvTaskQueueLen];

int g_modePacketDump = 1;
int g_modePacketInfo = 1;
uint8_t g_macFilterUse = 0;
uint8_t g_macFilter1[6] = { 0x00, 0x08, 0xdc, 0x1e, 0xde, 0x3d };
uint8_t g_macFilter2[6] = { 0x18, 0xfe, 0x34, 0xf4, 0xd4, 0x76 };

void usage_output()
{
	ets_uart_printf("//////////////////////////////////////////////////////////////// \r\n");
	ets_uart_printf("1 : WiFi Link Up (AP mode) \r\n");
	ets_uart_printf("2 : WiFi Link Up (STA mode) \r\n");
	ets_uart_printf("3 : WiFi Link Down \r\n");
	ets_uart_printf("4 : Display Packet Dump %s \r\n", (g_modePacketDump==0)?"On":"Off" );
	ets_uart_printf("5 : Display Packet Information %s \r\n", (g_modePacketInfo==0)?"On":"Off" );
	ets_uart_printf("6 : MAC Filter %s \r\n", (g_macFilterUse==0)?"Enable":"Disable" );

	ets_uart_printf("a : Send Packet : ARP \r\n");
	ets_uart_printf("b : Send Packet : UDP \r\n");
	ets_uart_printf("c : Send Packet : Dummy \r\n");

	ets_uart_printf("//////////////////////////////////////////////////////////////// \r\n");
}

void init_done(void)
{
	wifi_station_set_auto_connect(false);
	wifi_station_disconnect();

	usage_output();

	void uart_recvTask(os_event_t *events);
	system_os_task(uart_recvTask, uart_recvTaskPrio, uart_recvTaskQueue, uart_recvTaskQueueLen);;
}


void uart_recvTask(os_event_t *events)
{
	static uint8_t atHead[2];
	static uint8_t *pCmdLine;
	uint8_t uart_getmenu;

	while(READ_PERI_REG(UART_STATUS(UART0)) & (UART_RXFIFO_CNT << UART_RXFIFO_CNT_S))
	{
		WRITE_PERI_REG(0X60000914, 0x73);
		uart_getmenu = READ_PERI_REG(UART_FIFO(UART0)) & 0xFF;

		switch (uart_getmenu)
		{
		case '1':
			menu_linkup_apmode();
			break;
		case '2':
			menu_linkup_stamode();
			break;
		case '3':
			menu_linkdown();
			break;
		case '4':
			g_modePacketDump++;
			if ( g_modePacketDump==2 )	g_modePacketDump = 0;
			break;
		case '5':
			g_modePacketInfo++;
			if ( g_modePacketInfo==2 )	g_modePacketInfo = 0;
			break;
		case '6':
			g_macFilterUse++;
			if ( g_macFilterUse==2 )		g_macFilterUse = 0;
			break;

		case 'a':
			menu_sendpacket_arp();
			break;
		case 'b':
			menu_sendpacket_udp();
			break;
		case 'c':
			menu_sendpacket_dummy();
			break;

		default:
			break;
		}

		usage_output();
	}

	if(UART_RXFIFO_FULL_INT_ST == (READ_PERI_REG(UART_INT_ST(UART0)) & UART_RXFIFO_FULL_INT_ST))
		WRITE_PERI_REG(UART_INT_CLR(UART0), UART_RXFIFO_FULL_INT_CLR);
	else if(UART_RXFIFO_TOUT_INT_ST == (READ_PERI_REG(UART_INT_ST(UART0)) & UART_RXFIFO_TOUT_INT_ST))
		WRITE_PERI_REG(UART_INT_CLR(UART0), UART_RXFIFO_TOUT_INT_CLR);

	ETS_UART_INTR_ENABLE();
}

void ICACHE_FLASH_ATTR user_init(void)
{
	// Configure the UART
	uart_init(BIT_RATE_115200, BIT_RATE_115200);
	system_init_done_cb(init_done);
}
