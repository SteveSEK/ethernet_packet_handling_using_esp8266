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

![](https://cloud.githubusercontent.com/assets/2126804/11498987/51dbc7b6-9866-11e5-8145-ca566a951860.JPG)

![](https://cloud.githubusercontent.com/assets/2126804/11499061/ccaf9120-9866-11e5-8a3d-7226e9a51b6c.JPG)

![](https://cloud.githubusercontent.com/assets/2126804/11499064/cec65872-9866-11e5-900d-5b93ad05257f.JPG)

![](https://cloud.githubusercontent.com/assets/2126804/11499065/d092256e-9866-11e5-9440-7fb8fbc06219.JPG)

![](https://cloud.githubusercontent.com/assets/2126804/11499068/d3c0b20a-9866-11e5-8494-b1e841d4b62e.JPG)

![](https://cloud.githubusercontent.com/assets/2126804/11499069/d52dc006-9866-11e5-99c3-17a5e93aab5a.JPG)
