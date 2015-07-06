#ifndef _VARIABLE_H_
#define _VARIABLE_H_

#include <Arduino.h>

// RFC1213 local values
const char locDescr[]              = "Agentuino, a light-weight SNMP Agent.";   // read-only (static)
const char locObjectID[]           = "1.3.6.1.3.2009.0";                        // read-only (static)
extern uint32_t locUpTime;                                                      // read-only (static)
extern char locContact[20];                                                     // should be stored/read from EEPROM - read/write (not done for simplicity)
extern char locName[20];                                                        // should be stored/read from EEPROM - read/write (not done for simplicity)
extern char locLocation[20];                                                    // should be stored/read from EEPROM - read/write (not done for simplicity)
extern int32_t locServices;   
extern byte my_IP_address[4];                                                   // arduino IP address

#endif
