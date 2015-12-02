# ethernet_packet_handling_using_esp8266

I wanted to implement a ethernet interface in ESP8266 module.

Just in time, Espressif released open-source-lwIP as below.
http://bbs.espressif.com/viewtopic.php?f=46&t=951

So, for just test reason, I implemented ethernet packet handling code using ESP8266 as above.

With this test, I'm sure that many projects with ESP8266 and ethernet are possible.
 - Ethernet to WiFi (Ethernet to 802.11 converter)
 - Dual NIC Application(WiFi and Ethernet)

And, I think that W5500 is a best choice for the ESP8266's ethernet interface.
https://github.com/Wiznet/ioLibrary_Driver

Please refer to my test result as below and source codes.

![](https://cloud.githubusercontent.com/assets/2126804/11518711/27320216-98d7-11e5-8d0a-f2c710bf85e3.JPG)
![](https://cloud.githubusercontent.com/assets/2126804/11518713/299d6d4c-98d7-11e5-81a6-e8161732afd6.JPG)
![](https://cloud.githubusercontent.com/assets/2126804/11518715/2d9be6bc-98d7-11e5-8885-df56d3a6a256.JPG)
![](https://cloud.githubusercontent.com/assets/2126804/11518718/3006fb6c-98d7-11e5-978e-9f541f2d5527.JPG)
![](https://cloud.githubusercontent.com/assets/2126804/11518719/3191c8b8-98d7-11e5-8bd6-e659c509527f.JPG)
![](https://cloud.githubusercontent.com/assets/2126804/11518720/33082bd8-98d7-11e5-8cc7-d706fdbb6d33.JPG)

