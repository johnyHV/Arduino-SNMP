/**
 * Agentuino SNMP Agent Library Prototyping...
 *
 * Copyright 2010 Eric C. Gionet <lavco_eg@hotmail.com>
 *
 * @Edit: M. Pivovarsky <miroslav.pivovarsky@gmail.com>
 *
 */

#include "Streaming.h"         // Include the Streaming library
#include <Ethernet.h>          // Include the Ethernet library
#include <SPI.h>
#include "Agentuino.h"
#include "Flash.h"
#include "MIB.h"
#include "Variable.h"

IPAddress address;

static byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xEF};
static byte ip[] = {192, 168, 2, 64};
static byte gateway[] = {192, 168, 2, 1};
static byte subnet[] = {255, 255, 255, 0};

static byte RemoteIP[4] = {192, 168, 2, 60}; // The IP address of the host that will receive the trap

void setup() {
    Serial.begin(9600);
    Serial.println("CPU Start");

    pinMode(6, INPUT);

    Ethernet.begin(mac);
    //Ethernet.begin(mac,ip,gateway,subnet);

    IPAddress address = Ethernet.localIP();
    for (uint8_t i=0;i<=4;i++) {
        my_IP_address[i] = address[i];
        Serial.print(my_IP_address[i]);
        Serial.print(".");
    }
    Serial.println("");
    
    api_status = Agentuino.begin();
    
    if (api_status == SNMP_API_STAT_SUCCESS) {

        Agentuino.onPduReceive(pduReceived);

        delay(10);

        Serial << F("SNMP Agent Initalized...") << endl;

        return;
    }

    delay(10);

    Serial << F("SNMP Agent Initalization Problem...") << status << endl;
}

void loop() {
    // listen/handle for incoming SNMP requests
    Agentuino.listen();

    // Is pin 6 HIGH, send trap
    if (digitalRead(6) == 0) {
        Serial.println("Send TRAP");
        //Agentuino.Trap("test", RemoteIP, locUpTime, "1.3.6.1.4.1.28032.1.1.1", "1.3.6.1.2.1.1.1.0"); // You need to specify a message, the remote host and the locUpTime
        //Agentuino.Trap("Arduino SNMP trap", RemoteIP, locUpTime, "1.3.6.1.4.1.28032.1.1.1");
        Agentuino.Trap("Arduino SNMP trap", RemoteIP, locUpTime, "1.3.6.1.4.1.36061.0", "1.3.6.1.4.1.36061.3.1.1.1");
        delay(1000);
        locUpTime = locUpTime + 100;
    }

    // sysUpTime - The time (in hundredths of a second) since
    // the network management portion of the system was last
    // re-initialized.
    if (millis() - prevMillis > 1000) {

        // increment previous milliseconds
        prevMillis += 1000;

        // increment up-time counter
        locUpTime += 100;
    }
}

