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

#include "menu-functions.h"
#include "misc-functions.h"

void menu_linkdown()
{
	wifi_station_disconnect();
	wifi_station_dhcpc_stop();

	wifi_softap_dhcps_stop();
}

void menu_linkup_stamode()
{
	menu_linkdown();

	wifi_set_opmode(STATION_MODE);

	// Set WiFi
	struct station_config stconfig;
	if(wifi_station_get_config(&stconfig))
	{
		os_memset(stconfig.ssid, 0, sizeof(stconfig.ssid));
		os_memset(stconfig.password, 0, sizeof(stconfig.password));
		os_sprintf(stconfig.ssid, "%s", "myAP");
		os_sprintf(stconfig.password, "%s", "12345678");
		if(!wifi_station_set_config(&stconfig))
		{
		}
	}

	// Set IP
	struct ip_info info;
	info.ip.addr = ipaddr_addr("192.168.12.11");
	info.netmask.addr = ipaddr_addr("255.255.255.0");
	info.gw.addr = ipaddr_addr("192.168.12.1");
	wifi_set_ip_info(STATION_IF, &info);

	wifi_station_connect();
	wifi_station_set_auto_connect(1);

	struct station_config stationConfig;
	if(wifi_station_get_config(&stationConfig)) ets_uart_printf("STA config: SSID: %s, PASSWORD: %s\r\n", stationConfig.ssid, stationConfig.password);

	uint8 mac[6];
	wifi_get_macaddr(0, mac);
	ets_uart_printf("MAC : "MACSTR" \r\n", MAC2STR(mac));

	struct ip_info pTempIp;
    wifi_get_ip_info(0x00, &pTempIp);
    ets_uart_printf("%d.%d.%d.%d  %d.%d.%d.%d  %d.%d.%d.%d  \r\n", IP2STR(&pTempIp.ip), IP2STR(&pTempIp.netmask), IP2STR(&pTempIp.gw));
}

void menu_linkup_apmode()
{
	menu_linkdown();

	wifi_set_opmode(SOFTAP_MODE);

	struct softap_config apconfig;
	if(wifi_softap_get_config(&apconfig))
	{
		wifi_softap_dhcps_stop();
		os_memset(apconfig.ssid, 0, sizeof(apconfig.ssid));
		os_memset(apconfig.password, 0, sizeof(apconfig.password));
		apconfig.ssid_len = os_sprintf(apconfig.ssid, "ESP8266-AP");
		os_sprintf(apconfig.password, "%s", "12345678");

		apconfig.authmode = AUTH_OPEN;

		apconfig.ssid_hidden = 0;
		apconfig.channel = 7;
		apconfig.max_connection = 4;
		if(!wifi_softap_set_config(&apconfig))
		{
		}

		struct ip_info ipinfo;
		wifi_get_ip_info(SOFTAP_IF, &ipinfo);
		IP4_ADDR(&ipinfo.ip, 192, 168, 4, 1);
		IP4_ADDR(&ipinfo.gw, 192, 168, 4, 1);
		IP4_ADDR(&ipinfo.netmask, 255, 255, 255, 0);

		wifi_set_ip_info(SOFTAP_IF, &ipinfo);
		wifi_softap_dhcps_start();
	}

	struct softap_config apConfig;
	if(wifi_softap_get_config(&apConfig)) 		ets_uart_printf("AP config: SSID: %s, PASSWORD: %s\r\n", apConfig.ssid, apConfig.password);

	uint8 mac[6];
	wifi_get_macaddr(0, mac);
	ets_uart_printf("MAC : "MACSTR" \r\n", MAC2STR(mac));

	struct ip_info pTempIp;
    wifi_get_ip_info(0x00, &pTempIp);
    ets_uart_printf("%d.%d.%d.%d  %d.%d.%d.%d  %d.%d.%d.%d  \r\n", IP2STR(&pTempIp.ip), IP2STR(&pTempIp.netmask), IP2STR(&pTempIp.gw));
}

void menu_sendpacket_arp()
{
	uint8_t buff_temp[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Des Mac
		0x18, 0xfe, 0x34, 0xf4, 0xd4, 0x76, // Src Mac
		0x08, 0x06, // EtherType ARP
		0x00, 0x01, // Ethernet
		0x08, 0x00, // IP
		0x06, // Header Size
		0x04, // Protocol Size
		0x00, 0x01, // OPCode Request
		0x18, 0xfe, 0x34, 0xf4, 0xd4, 0x76, // Sender Mac
		0xc0, 0xa8, 0x0c, 0x0b, // Sender IP
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target Mac
		0xc0, 0xa8, 0xc0, 0xc0 // Target IP
	};

	ethernet_raw_packet_tx(buff_temp, sizeof(buff_temp), 1);
}


void menu_sendpacket_udp()
{
	uint8_t buff_temp[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Des Mac
		0x18, 0xfe, 0x34, 0xf4, 0xd4, 0x76, // Src Mac
		0x08, 0x00, // EtherType IP
		0x45, 0x00, // V4, Header Length 20, ...
		0x00, 0x21, // Total Length 33
		0x00, 0x0d, 0x40, 0x00, 0xff, // Identification, Flags, Fragment offset, TTL
		0x11, // UDP
		0x00, 0x00, // Header Checksum
		0xc0, 0xa8, 0x0c, 0x03, // Src IP
		0xc0, 0xa8, 0x0c, 0xff, // Des IP
		0x17, 0x70, // Src Port
		0x17, 0x70, // Des Port
		0x00, 0x0d, // Length 13
		0x00, 0x00, // Checksum
		0x33, 0x33, 0x33, 0x33, 0x33 // Data "33333"
	};

	ethernet_raw_packet_tx(buff_temp, sizeof(buff_temp), 1);
}

void menu_sendpacket_dummy()
{
	// dummy data
	uint8_t buff_temp[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Des Mac
		0x18, 0xfe, 0x34, 0xf4, 0xd4, 0x76, // Src Mac
		0xcd, 0xcd, // EtherType
		0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd // Garbage
	};

	ethernet_raw_packet_tx(buff_temp, sizeof(buff_temp), 1);
}
