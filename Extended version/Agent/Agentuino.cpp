/*
  Agentuino.cpp - An Arduino library for a lightweight SNMP Agent.
  Copyright (C) 2010 Eric C. Gionet <lavco_eg@hotmail.com>
  All rights reserved.

  @Edit: M. Pivovarsky <miroslav.pivovarsky@gmail.com>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

//
// sketch_aug23a
//

#include "Agentuino.h"
#include "EthernetUdp.h"
#include "MemoryFree.h"

EthernetUDP Udp;

SNMP_API_STAT_CODES AgentuinoClass::begin() {
    // set community names
    _getCommName = "public";
    _setCommName = "private";
    //
    // set community name set/get sizes
    _setSize = strlen(_setCommName);
    _getSize = strlen(_getCommName);
    //
    // init UDP socket
    Udp.begin(SNMP_DEFAULT_PORT);
    //
    return SNMP_API_STAT_SUCCESS;
}

SNMP_API_STAT_CODES AgentuinoClass::begin(char *getCommName, char *setCommName, uint16_t port) {
    // set community name set/get sizes
    _setSize = strlen(setCommName);
    _getSize = strlen(getCommName);
    //
    // validate get/set community name sizes
    if (_setSize > SNMP_MAX_NAME_LEN + 1 || _getSize > SNMP_MAX_NAME_LEN + 1) {
        return SNMP_API_STAT_NAME_TOO_BIG;
    }
    //
    // set community names
    _getCommName = getCommName;
    _setCommName = setCommName;
    //
    // validate session port number
    if (port == NULL || port == 0) port = SNMP_DEFAULT_PORT;
    //
    // init UDP socket
    Udp.begin(port);

    return SNMP_API_STAT_SUCCESS;
}

void AgentuinoClass::listen(void) {
    // if bytes are available in receive buffer
    // and pointer to a function (delegate function)
    // isn't null, trigger the function
    Udp.parsePacket();
    if (Udp.available() && _callback != NULL) (*_callback)();
}

SNMP_API_STAT_CODES AgentuinoClass::requestPdu(SNMP_PDU *pdu) {
    char *community;
    // sequence length
    byte seqLen;
    // version
    byte verLen, verEnd;
    // community string
    byte comLen, comEnd;
    // pdu
    byte pduTyp, pduLen;
    byte ridLen, ridEnd;
    byte errLen, errEnd;
    byte eriLen, eriEnd;
    byte vblTyp, vblLen;
    byte vbiTyp, vbiLen;
    byte obiLen, obiEnd;
    byte valTyp, valLen, valEnd;
    byte i;
    //
    // set packet packet size (skip UDP header)
    _packetSize = Udp.available();
    //
    // reset packet array
    memset(_packet, 0, SNMP_MAX_PACKET_LEN);
    //
    // validate packet
    if (_packetSize != 0 && _packetSize > SNMP_MAX_PACKET_LEN) {
        //
        //SNMP_FREE(_packet);

        return SNMP_API_STAT_PACKET_TOO_BIG;
    }
    //
    // get UDP packet
    //Udp.parsePacket();
    Udp.read(_packet, _packetSize);
    // 	Udp.readPacket(_packet, _packetSize, _dstIp, &_dstPort);
    //
    // packet check 1
    if (_packet[0] != 0x30) {
        //
        //SNMP_FREE(_packet);

        return SNMP_API_STAT_PACKET_INVALID;
    }
    //
    // sequence length
    seqLen = _packet[1];
    // version
    verLen = _packet[3];
    verEnd = 3 + verLen;
    // community string
    comLen = _packet[verEnd + 2];
    comEnd = verEnd + 2 + comLen;
    // pdu
    pduTyp = _packet[comEnd + 1];
    pduLen = _packet[comEnd + 2];
    ridLen = _packet[comEnd + 4];
    ridEnd = comEnd + 4 + ridLen;
    errLen = _packet[ridEnd + 2];
    errEnd = ridEnd + 2 + errLen;
    eriLen = _packet[errEnd + 2];
    eriEnd = errEnd + 2 + eriLen;
    vblTyp = _packet[eriEnd + 1];
    vblLen = _packet[eriEnd + 2];
    vbiTyp = _packet[eriEnd + 3];
    vbiLen = _packet[eriEnd + 4];
    obiLen = _packet[eriEnd + 6];
    obiEnd = eriEnd + obiLen + 6;
    valTyp = _packet[obiEnd + 1];
    valLen = _packet[obiEnd + 2];
    valEnd = obiEnd + 2 + valLen;
    //
    // extract version
    pdu->version = 0;
    for (i = 0; i < verLen; i++) {
        pdu->version = (pdu->version << 8) | _packet[5 + i];
    }
    //
    // validate version
    //
    // pdu-type
    pdu->type = (SNMP_PDU_TYPES) pduTyp;
    _dstType = pdu->type;
    //
    // validate community size
    if (comLen > SNMP_MAX_NAME_LEN) {
        // set pdu error
        pdu->error = SNMP_ERR_TOO_BIG;
        //
        return SNMP_API_STAT_NAME_TOO_BIG;
    }
    //
    //
    // validate community name
    if (pdu->type == SNMP_PDU_SET && comLen == _setSize) {
        //
        for (i = 0; i < _setSize; i++) {
            if (_packet[verEnd + 3 + i] != (byte) _setCommName[i]) {
                // set pdu error
                pdu->error = SNMP_ERR_NO_SUCH_NAME;
                //
                return SNMP_API_STAT_NO_SUCH_NAME;
            }
        }
    } else if (pdu->type == SNMP_PDU_GET && comLen == _getSize) {
        //
        for (i = 0; i < _getSize; i++) {
            if (_packet[verEnd + 3 + i] != (byte) _getCommName[i]) {
                // set pdu error
                pdu->error = SNMP_ERR_NO_SUCH_NAME;
                //
                return SNMP_API_STAT_NO_SUCH_NAME;
            }
        }
    } else {
        // set pdu error
        pdu->error = SNMP_ERR_NO_SUCH_NAME;
        //
        return SNMP_API_STAT_NO_SUCH_NAME;
    }
    //
    //
    // extract reqiest-id 0x00 0x00 0x00 0x01 (4-byte int aka int32)
    pdu->requestId = 0;
    for (i = 0; i < ridLen; i++) {
        pdu->requestId = (pdu->requestId << 8) | _packet[comEnd + 5 + i];
    }
    //
    // extract error
    pdu->error = SNMP_ERR_NO_ERROR;
    int32_t err = 0;
    for (i = 0; i < errLen; i++) {
        err = (err << 8) | _packet[ridEnd + 3 + i];
    }
    pdu->error = (SNMP_ERR_CODES) err;
    //
    // extract error-index
    pdu->errorIndex = 0;
    for (i = 0; i < eriLen; i++) {
        pdu->errorIndex = (pdu->errorIndex << 8) | _packet[errEnd + 3 + i];
    }
    //
    //
    // validate object-identifier size
    if (obiLen > SNMP_MAX_OID_LEN) {
        // set pdu error
        pdu->error = SNMP_ERR_TOO_BIG;

        return SNMP_API_STAT_OID_TOO_BIG;
    }
    //
    // extract and contruct object-identifier
    memset(pdu->OID.data, 0, SNMP_MAX_OID_LEN);
    pdu->OID.size = obiLen;
    for (i = 0; i < obiLen; i++) {
        pdu->OID.data[i] = _packet[eriEnd + 7 + i];
    }
    //
    // value-type
    pdu->VALUE.syntax = (SNMP_SYNTAXES) valTyp;
    //
    // validate value size
    if (obiLen > SNMP_MAX_VALUE_LEN) {
        // set pdu error
        pdu->error = SNMP_ERR_TOO_BIG;

        return SNMP_API_STAT_VALUE_TOO_BIG;
    }
    //
    // value-size
    pdu->VALUE.size = valLen;
    //
    // extract value
    memset(pdu->VALUE.data, 0, SNMP_MAX_VALUE_LEN);
    for (i = 0; i < valLen; i++) {
        pdu->VALUE.data[i] = _packet[obiEnd + 3 + i];
    }
    //
    return SNMP_API_STAT_SUCCESS;
}

SNMP_API_STAT_CODES AgentuinoClass::responsePdu(SNMP_PDU *pdu) {
    int32_u u;
    byte i;
    //
    // Length of entire SNMP packet
    _packetPos = 0; // 23
    _packetSize = 25 + sizeof (pdu->requestId) + sizeof (pdu->error) + sizeof (pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size;
    //
    memset(_packet, 0, SNMP_MAX_PACKET_LEN);
    //
    if (_dstType == SNMP_PDU_SET) {
        _packetSize += _setSize;
    } else {
        _packetSize += _getSize;
    }
    //
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_SEQUENCE; // type
    _packet[_packetPos++] = (byte) _packetSize - 2; // length
    //
    // SNMP version
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_INT; // type
    _packet[_packetPos++] = 0x01; // length
    _packet[_packetPos++] = 0x00; // value
    //
    // SNMP community string
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_OCTETS; // type
    if (_dstType == SNMP_PDU_SET) {
        _packet[_packetPos++] = (byte) _setSize; // length
        for (i = 0; i < _setSize; i++) {
            _packet[_packetPos++] = (byte) _setCommName[i];
        }
    } else {
        _packet[_packetPos++] = (byte) _getSize; // length
        for (i = 0; i < _getSize; i++) {
            _packet[_packetPos++] = (byte) _getCommName[i];
        }
    }
    //
    // SNMP PDU
    _packet[_packetPos++] = (byte) pdu->type;
    _packet[_packetPos++] = (byte) (sizeof (pdu->requestId) + sizeof ((int32_t) pdu->error) + sizeof (pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size + 14);
    //
    // Request ID (size always 4 e.g. 4-byte int)
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_INT; // type
    _packet[_packetPos++] = (byte)sizeof (pdu->requestId);
    u.int32 = pdu->requestId;
    _packet[_packetPos++] = u.data[3];
    _packet[_packetPos++] = u.data[2];
    _packet[_packetPos++] = u.data[1];
    _packet[_packetPos++] = u.data[0];
    //
    // Error (size always 4 e.g. 4-byte int)
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_INT; // type
    _packet[_packetPos++] = (byte)sizeof ((int32_t) pdu->error);
    u.int32 = pdu->error;
    _packet[_packetPos++] = u.data[3];
    _packet[_packetPos++] = u.data[2];
    _packet[_packetPos++] = u.data[1];
    _packet[_packetPos++] = u.data[0];
    //
    // Error Index (size always 4 e.g. 4-byte int)
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_INT; // type
    _packet[_packetPos++] = (byte)sizeof (pdu->errorIndex);
    u.int32 = pdu->errorIndex;
    _packet[_packetPos++] = u.data[3];
    _packet[_packetPos++] = u.data[2];
    _packet[_packetPos++] = u.data[1];
    _packet[_packetPos++] = u.data[0];
    //
    // Varbind List
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_SEQUENCE; // type
    _packet[_packetPos++] = (byte) (pdu->OID.size + pdu->VALUE.size + 6); //4
    //
    // Varbind
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_SEQUENCE; // type
    _packet[_packetPos++] = (byte) (pdu->OID.size + pdu->VALUE.size + 4); //2
    //
    // ObjectIdentifier
    _packet[_packetPos++] = (byte) SNMP_SYNTAX_OID; // type
    _packet[_packetPos++] = (byte) (pdu->OID.size);
    for (i = 0; i < pdu->OID.size; i++) {
        _packet[_packetPos++] = pdu->OID.data[i];
    }
    //
    // Value
    _packet[_packetPos++] = (byte) pdu->VALUE.syntax; // type
    _packet[_packetPos++] = (byte) (pdu->VALUE.size);
    for (i = 0; i < pdu->VALUE.size; i++) {
        _packet[_packetPos++] = pdu->VALUE.data[i];
    }
    //
    Udp.beginPacket(Udp.remoteIP(), Udp.remotePort());
    Udp.write(_packet, _packetSize);
    Udp.endPacket();
    //	Udp.write(_packet, _packetSize, _dstIp, _dstPort);
    //
    return SNMP_API_STAT_SUCCESS;
}

void AgentuinoClass::onPduReceive(onPduReceiveCallback pduReceived) {
    _callback = pduReceived;
}

void AgentuinoClass::freePdu(SNMP_PDU *pdu) {
    //
    memset(pdu->OID.data, 0, SNMP_MAX_OID_LEN);
    memset(pdu->VALUE.data, 0, SNMP_MAX_VALUE_LEN);
    free((char *) pdu);
}

void AgentuinoClass::Trampa(char Mensaje[], byte RemIP[4], uint32_t Tiempo) {
    byte TipoyLongitud[2] = {48, 68 + strlen(Mensaje)}; // Here is defined the full packet size
    byte Version[3] = {2, 1, 0}; // Defined versión 1
    byte Comunidad[8] = {4, 6, 112, 117, 98, 108, 105, 99}; // Second byte from the left is the number of characters in the community name. Last four bytes = public in ASCII characters
    byte TipoSNMP[4] = {164, 130, 0, 53 + strlen(Mensaje)}; // Here is defined the size
    byte OID[11] = {6, 9, 43, 6, 1, 4, 1, 130, 153, 93, 0}; // Here is defined the enterprise OID
    byte IPdefinida[2] = {64, 4};
    byte TrapIP[4] = {158, 193, 86, 74}; // Here you can change the trap IP address
    byte TipoTrampa[3] = {2, 1, 6};
    byte extraOID[3] = {2, 1, 1};
    byte TipoTiempo[2] = {67, 4};
    byte VarBind[4] = {48, 130, 0, 20 + strlen(Mensaje)}; // Here is defined the size
    byte VarBind1[4] = {48, 130, 0, 16 + strlen(Mensaje)}; // Here is defined the size
    byte OID1[14] = {6, 12, 43, 6, 1, 4, 1, 130, 153, 93, 3, 1, 1, 1}; // Here is defined the trap OID. OID ktore sa posiela s spravou
    byte Value1[2] = {4, strlen(Mensaje)};

    // The next part is to change the locUpTime into bytes
    int i = 0, k = 1, temp;
    byte suma = 0;
    uint32_t quotient;
    quotient = Tiempo;
    byte hexadecimalNumber[4] = {0, 0, 0, 0};
    while (quotient != 0) {
        temp = quotient % 16;
        if (k == 1) {
            suma = temp;
            k = 2;
        } else {
            suma = suma + temp * 16;
            hexadecimalNumber[3 - i] = suma;
            i = i + 1;
            k = 1;
        }
        quotient = quotient / 16;
    }
    if (k == 2) {
        hexadecimalNumber[3 - i] = suma;
    }

    Udp.beginPacket(RemIP, 162); // Here is defined the UDP port 162 to send the trap
    Udp.write(TipoyLongitud, 2);
    Udp.write(Version, 3);
    Udp.write(Comunidad, 8); // public v ASCII pricom 2 bajt je velkost
    Udp.write(TipoSNMP, 4);
    Udp.write(OID, 11); // enterprise indetifikuje typ objektu ktory vegeneroval trap
    Udp.write(IPdefinida, 2);
    Udp.write(TrapIP, 4); // adresa hosta ktory vygeneroval trap
    Udp.write(TipoTrampa, 3);
    Udp.write(extraOID, 3);
    Udp.write(TipoTiempo, 2);
    Udp.write(hexadecimalNumber, 4);
    Udp.write(VarBind, 4);
    Udp.write(VarBind1, 4);
    Udp.write(OID1, 14);
    Udp.write(Value1, 2);
    Udp.write(Mensaje, strlen(Mensaje));
    Udp.endPacket();
}

// Create one global object
AgentuinoClass Agentuino;

// function for pduReceived() function
SNMP_API_STAT_CODES api_status;
SNMP_ERR_CODES status;
char oid[SNMP_MAX_OID_LEN];
uint32_t prevMillis = 0;
//uint32_t prevMillis= millis();

// function the perform at SNMP Requirements

void pduReceived() {
    SNMP_PDU pdu;

    Serial.println(locUpTime);
    //
#ifdef DEBUG
    Serial.print(F("UDP Packet Received Start.."));
    Serial.print(F(" RAM:"));
    Serial.print(freeMemory());
#endif
    //
    api_status = Agentuino.requestPdu(&pdu);
    //
    if (pdu.type == SNMP_PDU_GET || pdu.type == SNMP_PDU_GET_NEXT || pdu.type == SNMP_PDU_SET
            && pdu.error == SNMP_ERR_NO_ERROR && api_status == SNMP_API_STAT_SUCCESS) {
        //
        pdu.OID.toString(oid);
        //
        //Serial << "OID: " << oid << endl;
        //
        if (strcmp_P(oid, sysDescr) == 0) {
            // handle sysDescr (set/get) requests
            if (pdu.type == SNMP_PDU_SET) {
                // response packet from set-request - object is read-only
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = SNMP_ERR_READ_ONLY;
            } else {
                // response packet from get-request - locDescr
                status = pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locDescr);
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            }
            //
#ifdef DEBUG
            Serial.print(F("sysDescr..."));
            Serial.print(locDescr);
            Serial.print(F(" "));
            Serial.println(pdu.VALUE.size);
#endif
        } else if (strcmp_P(oid, sysUpTime) == 0) {
            // handle sysName (set/get) requests
            if (pdu.type == SNMP_PDU_SET) {
                // response packet from set-request - object is read-only
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = SNMP_ERR_READ_ONLY;
            } else {
                // response packet from get-request - locUpTime
                status = pdu.VALUE.encode(SNMP_SYNTAX_TIME_TICKS, locUpTime);
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            }
            //
#ifdef DEBUG
            Serial.print(F("sysUpTime..."));
            Serial.print(locUpTime);
            Serial.print(F(" "));
            Serial.println(pdu.VALUE.size);
#endif
        } else if (strcmp_P(oid, sysName) == 0) {
            // handle sysName (set/get) requests
            if (pdu.type == SNMP_PDU_SET) {
                // response packet from set-request - object is read/write
                status = pdu.VALUE.decode(locName, strlen(locName));
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            } else {
                // response packet from get-request - locName
                status = pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locName);
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            }
            //
#ifdef DEBUG
            Serial.print(F("sysName..."));
            Serial.print(locName);
            Serial.print(F(" "));
            Serial.println(pdu.VALUE.size);
#endif
        } else if (strcmp_P(oid, sysContact) == 0) {
            // handle sysContact (set/get) requests
            if (pdu.type == SNMP_PDU_SET) {
                // response packet from set-request - object is read/write
                status = pdu.VALUE.decode(locContact, strlen(locContact));
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            } else {
                // response packet from get-request - locContact
                status = pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locContact);
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            }
            //
#ifdef DEBUG
            Serial.print(F("sysContact..."));
            Serial.print(locContact);
            Serial.print(F(" "));
            Serial.println(pdu.VALUE.size);
#endif
        } else if (strcmp_P(oid, sysLocation) == 0) {
            // handle sysLocation (set/get) requests
            if (pdu.type == SNMP_PDU_SET) {
                // response packet from set-request - object is read/write
                status = pdu.VALUE.decode(locLocation, strlen(locLocation));
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            } else {
                // response packet from get-request - locLocation
                status = pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locLocation);
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            }
            //
#ifdef DEBUG
            Serial.print(F("sysLocation..."));
            Serial.print(locLocation);
            Serial.print(F(" "));
            Serial.println(pdu.VALUE.size);
#endif
        } else if (strcmp_P(oid, sysServices) == 0) {
            // handle sysServices (set/get) requests
            if (pdu.type == SNMP_PDU_SET) {
                // response packet from set-request - object is read-only
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = SNMP_ERR_READ_ONLY;
            } else {
                // response packet from get-request - locServices
                status = pdu.VALUE.encode(SNMP_SYNTAX_INT, locServices);
                pdu.type = SNMP_PDU_RESPONSE;
                pdu.error = status;
            }
            //
#ifdef DEBUG
            Serial.print(F("locServices..."));
            Serial.print(locServices);
            Serial.print(F(" "));
            Serial.println(pdu.VALUE.size);
#endif
        } else {
            // oid does not exist
            //
            // response packet - object not found
            pdu.type = SNMP_PDU_RESPONSE;
            pdu.error = SNMP_ERR_NO_SUCH_NAME;
        }
        //
        Agentuino.responsePdu(&pdu);
    }
    //
    Agentuino.freePdu(&pdu);
    //
    //Serial << "UDP Packet Received End.." << " RAM:" << freeMemory() << endl;
}
