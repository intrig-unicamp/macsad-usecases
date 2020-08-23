/* Copyright 2018 INTRIG/FEEC/UNICAMP (University of Campinas), Brazi      */
/*                                                                         */
/*Licensed under the Apache License, Version 2.0 (the "License");          */
/*you may not use this file except in compliance with the License.         */
/*You may obtain a copy of the License at                                  */
/*                                                                         */
/*    http://www.apache.org/licenses/LICENSE-2.0                           */
/*                                                                         */
/*Unless required by applicable law or agreed to in writing, software      */
/*distributed under the License is distributed on an "AS IS" BASIS,        */
/*WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. */
/*See the License for the specific language governing permissions and      */
/*limitations under the License.                                           */

//#include <core.p4>
//#include <v1model.p4>
//#include "include/standard_headers.p4"


const bit<16> ETHERTYPE_ARP  = 0x0806; 
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;

const bit<16> GTP_UDP_PORT     = 2152;
const bit<16>  UDP_PORT_VXLAN   = 4789;

const bit<32>  MAC_LEARN_RECEIVER = 1;
const bit<32> ARP_LEARN_RECEIVER = 1025;

const bit<48> OWN_MAC = 0x001122334455;
const bit<48> MACD = 0x001322334458;
const bit<48> BCAST_MAC = 0xFFFFFFFFFFFF;
const bit<32> GW_IP = 0x0A000001; // 10.0.0.1
const bit<32> IP = 0x0A01012A; // 10.1.1.42

const bit<48> VIRTUAL_EPG_MAC = 0x001122334488;
const bit<32> VIRTUAL_EPG_IP =  0x0A000302;
const bit<32> VIRTUAL_DCGW_IP = 0x0A000303;
const bit<48> VIRTUAL_DCGW_MAC= 0x001122334489;

const bit<4> MAX_PORT = 1;
const bit<32> NUM_PORTS = 512;

typedef bit<48> ByteCounter_t;
typedef bit<16> nhgp_t;
typedef bit<32> teid_t;


typedef bit<9> port_t;
const port_t port = 136;
const port_t CPU_PORT = 255;
