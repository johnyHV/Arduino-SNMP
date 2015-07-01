#include "Variable.h"

uint32_t locUpTime                 = 0;                                        // read-only (static)
char locContact[20]         = "Miroslav Pivovarsky";                    // should be stored/read from EEPROM - read/write (not done for simplicity)
char locName[20]            = "Agentuino";                              // should be stored/read from EEPROM - read/write (not done for simplicity)
char locLocation[20]        = "Zilina, Slovak";                         // should be stored/read from EEPROM - read/write (not done for simplicity)
int32_t locServices         = 7;    

