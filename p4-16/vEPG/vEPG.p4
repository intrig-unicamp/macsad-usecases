
/* Copyright 2019 INTRIG/FEEC/UNICAMP (University of Campinas), Brazil     */
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


#include <core.p4>
#include <v1model.p4>
#include "include/standard_headers.p4"

/*************************************************************************
*********************** C O N S T A N T S ********************************
*************************************************************************/

const bit<16> ETHERTYPE_IPV4         = 0x0800  ;
const bit<16> ETHERTYPE_ARP          = 0x0806  ; 
const bit<16> ETHERTYPE_VLAN         = 0x8100  ;

const bit<8>  IPPROTO_ICMP           = 0x01    ;
const bit<8>  IPPROTO_IPv4           = 0x04    ;
const bit<8>  IPPROTO_TCP            = 0x06    ;
const bit<8>  IPPROTO_UDP            = 0x11    ;

const bit<16> ARP_HTYPE_ETHERNET     = 0x0001  ;
const bit<16> ARP_PTYPE_IPV4         = 0x0800  ;
const bit<8>  ARP_HLEN_ETHERNET      = 6       ;
const bit<8>  ARP_PLEN_IPV4          = 4       ;
const bit<16> ARP_OPER_REQUEST       = 1       ;
const bit<16> ARP_OPER_REPLY         = 2       ;

const bit<8> ICMP_ECHO_REQUEST       = 8       ;
const bit<8> ICMP_ECHO_REPLY         = 0       ;

const bit<16> GTP_UDP_PORT           = 2152    ;
const bit<16>  UDP_PORT_VXLAN        = 4789    ;

const bit<32>  MAC_LEARN_RECEIVER    = 1       ;
const bit<32> ARP_LEARN_RECEIVER     = 1025    ;

const bit<48> OWN_MAC                = 0x001122334455  ;
const bit<48> BCAST_MAC              = 0xFFFFFFFFFFFF  ;
const bit<32> GW_IP                  = 0x0A000001      ; 
const bit<32> DCGW_IP_DL             = 0x0A000102      ;
const bit<32> DCGW_IP_UL             = 0x0A000103      ;

const bit<48> VIRTUAL_EPG_MAC        = 0x001122334488  ;
const bit<32> VIRTUAL_EPG_IP         = 0x0A000302      ;
const bit<48> VIRTUAL_DCGW_MAC       = 0x001122334489  ;

const bit<2>  METER_COLOR_GREEN      = 0               ;
const bit<2>  METER_COLOR_YELLOW     = 1               ;
const bit<2>  METER_COLOR_RED        = 2               ;

const bit<4> MAX_PORT                = 1               ;


/*************************************************************************
*********************** P A R S E R  *************************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

   @name(".start") state start {
        transition parse_ethernet;
    }

   @name("parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    @name("parse_arp") state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype, hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
            ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    @name("parse_arp_ipv4") state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.arp_metadata.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }

    @name("parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP  : parse_udp;
            IPPROTO_ICMP : parse_icmp;
            default      : accept;
        }
    }

     @name("parse_udp")state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            UDP_PORT_VXLAN : parse_vxlan;
            default        : accept;
        }
    }

    @name("parse_icmp") state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    @name("parse_vxlan") state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition parse_inner_ethernet;
    }

    @name("parse_inner_ethernet") state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_inner_ipv4;
            default 	   : accept;
        }
    }

    @name("parse_inner_ipv4") state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            IPPROTO_UDP  : parse_inner_udp;
            IPPROTO_TCP  : parse_inner_tcp;
            default      : accept;
        }
    }

    @name("parse_inner_udp") state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition select(hdr.inner_udp.dstPort) {
            GTP_UDP_PORT : parse_gtp;
            default      : accept;
        }
    }

   @name("parse_inner_tcp") state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        transition accept;
    }


   @name("parse_gtp") state parse_gtp {
        packet.extract(hdr.gtp);
        transition parse_inner1_ipv4;

    }

    @name("parse_inner1_ipv4") state parse_inner1_ipv4 {
        packet.extract(hdr.inner1_ipv4);
        transition select( hdr.inner1_ipv4.protocol) {
            IPPROTO_TCP  : parse_inner1_tcp;
            default      : accept;
        }

    }

    @name("parse_inner1_tcp") state parse_inner1_tcp {
        packet.extract(hdr.inner1_tcp);
        transition accept;
    }

}

/*********************************************************************************/
/**************  I N G R E S S   P R O C E S S I N G   ***************************/
/*********************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata ) {

/******************************** Drop ******************************************/

    @name(".drop") action drop() {

        mark_to_drop();
    }

    @name(".nop") action nop() {

    }

/************************ process mac learn  *************************************/

    @name(".mac_learn") action mac_learn() {

        digest(MAC_LEARN_RECEIVER, { hdr.ethernet.srcAddr, standard_metadata.ingress_port } );
  } 

    @name(".smac") table smac {
    key = {

        hdr.ethernet.srcAddr : lpm;
    }
    actions = {mac_learn; }
    size = 10;
    default_action = mac_learn;
    }

    @name(".dmac") table dmac {
    key = {
        hdr.ethernet.dstAddr : lpm;
    }
    actions = {nop; drop;}
    size = 10;
    default_action = drop;
    }


/**************************** GTP Decap ********************************************/


    @name(".gtp_decapsulate") action gtp_decapsulate() {


        meta.meta_ipv4.version                       = hdr.ipv4.version                         ;
        meta.meta_ipv4.ihl                           = hdr.ipv4.ihl                             ;
        meta.meta_ipv4.diffserv                      = hdr.ipv4.diffserv                        ;
        meta.meta_ipv4.totalLen                      = hdr.ipv4.totalLen                        ;
        meta.meta_ipv4.identification                = hdr.ipv4.identification                  ;
        meta.meta_ipv4.flags                         = hdr.ipv4.flags                           ;
        meta.meta_ipv4.fragOffset                    = hdr.ipv4.fragOffset                      ;
        meta.meta_ipv4.ttl                           = hdr.ipv4.ttl                             ;
        meta.meta_ipv4.protocol                      = hdr.ipv4.protocol                        ;
        meta.meta_ipv4.hdrChecksum                   = hdr.ipv4.hdrChecksum                     ;
        meta.meta_ipv4.srcAddr                       = hdr.ipv4.srcAddr                         ;
        meta.meta_ipv4.dstAddr                       = hdr.ipv4.dstAddr                         ;

        meta.meta_udp.srcPort                        = hdr.udp.srcPort                          ;
        meta.meta_udp.dstPort                        = hdr.udp.dstPort                          ;
        meta.meta_udp.plength                        = hdr.udp.plength                          ;
        meta.meta_udp.checksum                       = hdr.udp.checksum                         ;

        meta.meta_inner1_ipv4.version     	     = hdr.inner1_ipv4.version                  ;
        meta.meta_inner1_ipv4.ihl        	     = hdr.inner1_ipv4.ihl                      ;
        meta.meta_inner1_ipv4.diffserv   	     = hdr.inner1_ipv4.diffserv                 ;
        meta.meta_inner1_ipv4.totalLen    	     = hdr.inner1_ipv4.totalLen                 ;
        meta.meta_inner1_ipv4.identification         = hdr.inner1_ipv4.identification           ;
        meta.meta_inner1_ipv4.flags                  = hdr.inner1_ipv4.flags                    ;
        meta.meta_inner1_ipv4.fragOffset             = hdr.inner1_ipv4.fragOffset               ;
        meta.meta_inner1_ipv4.ttl                    = hdr.inner1_ipv4.ttl                      ;
        meta.meta_inner1_ipv4.protocol               = hdr.inner1_ipv4.protocol                 ;
        meta.meta_inner1_ipv4.hdrChecksum            = hdr.inner1_ipv4.hdrChecksum              ;
        meta.meta_inner1_ipv4.srcAddr                = hdr.inner1_ipv4.srcAddr                  ;
        meta.meta_inner1_ipv4.dstAddr                = hdr.inner1_ipv4.dstAddr                  ;

        meta.meta_inner1_tcp.srcPort                 = hdr.inner1_tcp.srcPort                   ;
        meta.meta_inner1_tcp.dstPort                 = hdr.inner1_tcp.dstPort                   ;
        meta.meta_inner1_tcp.seqNo                   = hdr.inner1_tcp.seqNo                     ;
        meta.meta_inner1_tcp.ackNo                   = hdr.inner1_tcp.ackNo                     ;
        meta.meta_inner1_tcp.dataOffset              = hdr.inner1_tcp.dataOffset                ;
        meta.meta_inner1_tcp.res                     = hdr.inner1_tcp.res                       ;
        meta.meta_inner1_tcp.flags                   = hdr.inner1_tcp.flags                     ;
        meta.meta_inner1_tcp.window                  = hdr.inner1_tcp.window                    ;
        meta.meta_inner1_tcp.checksum                = hdr.inner1_tcp.checksum                  ;
        meta.meta_inner1_tcp.urgentPtr               = hdr.inner1_tcp.urgentPtr                 ;

        meta.gtp_metadata.teid                       = hdr.gtp.teid                             ;

         /* removing header */

        hdr.inner1_tcp.setInvalid();
        hdr.inner1_ipv4.setInvalid();
        hdr.gtp.setInvalid();
        hdr.inner_udp.setInvalid();
        hdr.inner_ipv4.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.vxlan.setInvalid();
        hdr.udp.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.ethernet.setInvalid();

        /* adding header  */

        hdr.inn_tcp.setValid();
        hdr.inn_ipv4.setValid();
        hdr.ethernet1.setValid();
        hdr.vxlan_new.setValid();
        hdr.outer_udp.setValid();
        hdr.ipv4_outer.setValid();

        hdr.inn_tcp.srcPort              	    =  meta.meta_inner1_tcp.srcPort         ;
        hdr.inn_tcp.dstPort           		    =  meta.meta_inner1_tcp.dstPort         ;
        hdr.inn_tcp.seqNo              		    =  meta.meta_inner1_tcp.seqNo           ;
        hdr.inn_tcp.ackNo              		    =  meta.meta_inner1_tcp.ackNo           ;
        hdr.inn_tcp.dataOffset         		    =  meta.meta_inner1_tcp.dataOffset      ;
        hdr.inn_tcp.res               		    =  meta.meta_inner1_tcp.res             ;
        hdr.inn_tcp.flags             		    =  meta.meta_inner1_tcp.flags           ;
        hdr.inn_tcp.window              	    =  meta.meta_inner1_tcp.window          ;
        hdr.inn_tcp.checksum          		    =  meta.meta_inner1_tcp.checksum        ;
        hdr.inn_tcp.urgentPtr         		    =  meta.meta_inner1_tcp.urgentPtr       ;

        hdr.inn_ipv4.version       		    = meta.meta_inner1_ipv4.version         ;
        hdr.inn_ipv4.ihl            		    = meta.meta_inner1_ipv4.ihl             ;
        hdr.inn_ipv4.diffserv        	            = meta.meta_inner1_ipv4.diffserv        ;
        hdr.inn_ipv4.totalLen         		    = meta.meta_inner1_ipv4.totalLen        ;
        hdr.inn_ipv4.identification   		    = meta.meta_inner1_ipv4.identification  ;
        hdr.inn_ipv4.flags            		    = meta.meta_inner1_ipv4.flags           ;
        hdr.inn_ipv4.fragOffset       		    = meta.meta_inner1_ipv4.fragOffset      ;
        hdr.inn_ipv4.ttl              		    = meta.meta_inner1_ipv4.ttl             ;
        hdr.inn_ipv4.protocol         		    = IPPROTO_TCP                           ;
        hdr.inn_ipv4.hdrChecksum      		    = meta.meta_inner1_ipv4.hdrChecksum     ;
        hdr.inn_ipv4.srcAddr          		    = meta.meta_inner1_ipv4.srcAddr         ;
        hdr.inn_ipv4.dstAddr          	            = meta.meta_inner1_ipv4.dstAddr         ;

        hdr.ipv4_outer.version       		    = meta.meta_ipv4.version                ;
        hdr.ipv4_outer.ihl            		    = meta.meta_ipv4.ihl                    ;
        hdr.ipv4_outer.diffserv      	            = meta.meta_ipv4.diffserv               ;
        hdr.ipv4_outer.totalLen          	    = meta.meta_ipv4.totalLen - 36          ;
        hdr.ipv4_outer.identification 		    = meta.meta_ipv4.identification         ;
        hdr.ipv4_outer.flags          		    = meta.meta_ipv4.flags                  ;
        hdr.ipv4_outer.fragOffset     		    = meta.meta_ipv4.fragOffset             ;
        hdr.ipv4_outer.ttl             		    = meta.meta_ipv4.ttl                    ;
        hdr.ipv4_outer.protocol        		    = meta.meta_ipv4.protocol               ;
        hdr.ipv4_outer.hdrChecksum    		    = meta.meta_ipv4.hdrChecksum            ;
        hdr.ipv4_outer.srcAddr        		    = GW_IP                                 ;
        hdr.ipv4_outer.dstAddr       		    = DCGW_IP_UL                            ;

        hdr.outer_udp.srcPort 	                    = meta.meta_udp.srcPort                 ;
        hdr.outer_udp.dstPort 			    = meta.meta_udp.dstPort                 ;
        hdr.outer_udp.plength 			    = meta.meta_udp.plength - 36            ;
        hdr.outer_udp.checksum 			    = meta.meta_udp.checksum                ;

        hdr.ethernet1.srcAddr 			    = VIRTUAL_EPG_MAC                       ;
        hdr.ethernet1.dstAddr 			    = VIRTUAL_DCGW_MAC                      ;
        hdr.ethernet1.etherType 		    = ETHERTYPE_IPV4                        ;

}

    @name(".gtp_decap") table gtp_decap {
    key = {
          hdr.inner_ipv4.dstAddr : exact    ;
    }

    actions = { gtp_decapsulate; drop;}
    size = 10;
    default_action = drop;

}

/************************** GTP Encap **********************************************/

    @name(".gtp_encapsulate") action gtp_encapsulate(bit<32> teid, bit<32> eNB_IP) {


        meta.meta_inner_tcp.srcPort 		   =   hdr.inner_tcp.srcPort             ;
        meta.meta_inner_tcp.dstPort    		   =   hdr.inner_tcp.dstPort             ;
        meta.meta_inner_tcp.seqNo     		   =   hdr.inner_tcp.seqNo               ;
        meta.meta_inner_tcp.ackNo      		   =   hdr.inner_tcp.ackNo               ;
        meta.meta_inner_tcp.dataOffset 		   =   hdr.inner_tcp.dataOffset          ;
        meta.meta_inner_tcp.res        		   =   hdr.inner_tcp.res                 ;
        meta.meta_inner_tcp.flags      		   =   hdr.inner_tcp.flags               ;
        meta.meta_inner_tcp.window     		   =   hdr.inner_tcp.window              ;
        meta.meta_inner_tcp.checksum   		   =   hdr.inner_tcp.checksum            ;
        meta.meta_inner_tcp.urgentPtr  		   =   hdr.inner_tcp.urgentPtr           ;

        meta.meta_inner_ipv4.version               =   hdr.inner_ipv4.version            ;
        meta.meta_inner_ipv4.ihl                   =   hdr.inner_ipv4.ihl                ;
        meta.meta_inner_ipv4.diffserv              =   hdr.inner_ipv4.diffserv           ;
        meta.meta_inner_ipv4.totalLen              =   hdr.inner_ipv4.totalLen           ;
        meta.meta_inner_ipv4.identification        =   hdr.inner_ipv4.identification     ;
        meta.meta_inner_ipv4.flags                 =   hdr.inner_ipv4.flags              ;
        meta.meta_inner_ipv4.fragOffset            =   hdr.inner_ipv4.fragOffset         ;
        meta.meta_inner_ipv4.ttl                   =   hdr.inner_ipv4.ttl                ;
        meta.meta_inner_ipv4.protocol              =   hdr.inner_ipv4.protocol           ;
        meta.meta_inner_ipv4.hdrChecksum           =   hdr.inner_ipv4.hdrChecksum        ;
        meta.meta_inner_ipv4.srcAddr               =   hdr.inner_ipv4.srcAddr            ;
        meta.meta_inner_ipv4.dstAddr               =   hdr.inner_ipv4.dstAddr            ;

        meta.meta_udp.srcPort                      =   hdr.udp.srcPort                   ;
        meta.meta_udp.dstPort            	   =   hdr.udp.dstPort    	         ;
        meta.meta_udp.plength                      =   hdr.udp.plength      	         ;
        meta.meta_udp.checksum          	   =   hdr.udp.checksum                  ;

        meta.meta_ipv4.version            	   =   hdr.ipv4.version       	         ;
        meta.meta_ipv4.ihl                	   =   hdr.ipv4.ihl                      ;
        meta.meta_ipv4.diffserv          	   =   hdr.ipv4.diffserv                 ;
        meta.meta_ipv4.totalLen           	   =   hdr.ipv4.totalLen      	         ;
        meta.meta_ipv4.identification     	   =   hdr.ipv4.identification	         ;
        meta.meta_ipv4.flags              	   =   hdr.ipv4.flags         	         ;
        meta.meta_ipv4.fragOffset         	   =   hdr.ipv4.fragOffset               ;
        meta.meta_ipv4.ttl                	   =   hdr.ipv4.ttl                      ;
        meta.meta_ipv4.protocol           	   =   hdr.ipv4.protocol                 ;
        meta.meta_ipv4.hdrChecksum        	   =   hdr.ipv4.hdrChecksum              ;
        meta.meta_ipv4.srcAddr            	   =   hdr.ipv4.srcAddr                  ;
        meta.meta_ipv4.dstAddr            	   =   hdr.ipv4.dstAddr                  ;

        meta.meta_ethernet.srcAddr                 =   hdr.ethernet.srcAddr              ;
        meta.meta_ethernet.dstAddr                 =   hdr.ethernet.dstAddr              ;
        meta.meta_ethernet.etherType    	   =   hdr.ethernet.etherType            ;


        /* removing header */

        hdr.inner_tcp.setInvalid();
        hdr.inner_ipv4.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.vxlan.setInvalid();
        hdr.udp.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.ethernet.setInvalid();

        /* adding header  */

        hdr.inn_tcp.setValid();
        hdr.inn1_ipv4.setValid();
        hdr.gtp.setValid();
        hdr.inner_udp.setValid();
        hdr.inn_ipv4.setValid();
        hdr.ethernet1.setValid();
        hdr.vxlan_new.setValid();
        hdr.outer_udp.setValid();
        hdr.ipv4_outer.setValid();

        hdr.inn_tcp.srcPort    		          =  meta.meta_inner_tcp.srcPort          ;
        hdr.inn_tcp.dstPort         		  =  meta.meta_inner_tcp.dstPort          ;
        hdr.inn_tcp.seqNo               	  =  meta.meta_inner_tcp.seqNo            ;
        hdr.inn_tcp.ackNo 	                  =  meta.meta_inner_tcp.ackNo            ;
        hdr.inn_tcp.dataOffset                    =  meta.meta_inner_tcp.dataOffset       ;
        hdr.inn_tcp.res           	          =  meta.meta_inner_tcp.res              ;
        hdr.inn_tcp.flags           		  =  meta.meta_inner_tcp.flags            ;
        hdr.inn_tcp.window          		  =  meta.meta_inner_tcp.window           ;
        hdr.inn_tcp.checksum        		  =  meta.meta_inner_tcp.checksum         ;
        hdr.inn_tcp.urgentPtr      	          =  meta.meta_inner_tcp.urgentPtr        ;

        hdr.inn1_ipv4.version        		  = meta.meta_inner_ipv4.version          ;
        hdr.inn1_ipv4.ihl            		  = meta.meta_inner_ipv4.ihl              ;
        hdr.inn1_ipv4.diffserv       		  = meta.meta_inner_ipv4.diffserv         ;
        hdr.inn1_ipv4.totalLen       		  = meta.meta_inner_ipv4.totalLen         ;
        hdr.inn1_ipv4.identification 		  = meta.meta_inner_ipv4.identification   ;
        hdr.inn1_ipv4.flags          		  = meta.meta_inner_ipv4.flags            ;
        hdr.inn1_ipv4.fragOffset     		  = meta.meta_inner_ipv4.fragOffset       ;
        hdr.inn1_ipv4.ttl            		  = meta.meta_inner_ipv4.ttl              ;
        hdr.inn1_ipv4.protocol       		  = meta.meta_inner_ipv4.protocol         ;
        hdr.inn1_ipv4.hdrChecksum    		  = meta.meta_inner_ipv4.hdrChecksum      ;
        hdr.inn1_ipv4.srcAddr        		  = meta.meta_inner_ipv4.srcAddr          ;
        hdr.inn1_ipv4.dstAddr      	          = meta.meta_inner_ipv4.dstAddr          ;

        hdr.gtp.teid                              = teid                                  ;
        hdr.gtp.version                           = 1                                     ;
        hdr.gtp.pFlag                             = 1                                     ;
        hdr.gtp.messageType                       = 0xff                                  ;

        hdr.inner_udp.srcPort                     = 2152                                  ;
        hdr.inner_udp.dstPort                     = 2152                                  ;
        hdr.inner_udp.plength                     = meta.meta_udp.plength -14             ;
        hdr.inner_udp.checksum                    = meta.meta_udp.checksum                ;

        hdr.inn_ipv4.version                      = meta.meta_ipv4.version                ;
        hdr.inn_ipv4.ihl                          = meta.meta_ipv4.ihl                    ;
        hdr.inn_ipv4.diffserv                     = meta.meta_ipv4.diffserv               ;
        hdr.inn_ipv4.totalLen                     = meta.meta_ipv4.totalLen - 14          ;
        hdr.inn_ipv4.identification               = meta.meta_ipv4.identification         ;
        hdr.inn_ipv4.flags                        = meta.meta_ipv4.flags                  ;
        hdr.inn_ipv4.fragOffset                   = meta.meta_ipv4.fragOffset             ;
        hdr.inn_ipv4.ttl                          = meta.meta_ipv4.ttl                    ;
        hdr.inn_ipv4.protocol                     = meta.meta_ipv4.protocol               ;
        hdr.inn_ipv4.hdrChecksum                  = meta.meta_ipv4.hdrChecksum            ;
        hdr.inn_ipv4.srcAddr                      = VIRTUAL_EPG_IP                        ;
        hdr.inn_ipv4.dstAddr                      = eNB_IP                                ;

        hdr.ethernet1.srcAddr                     = VIRTUAL_EPG_MAC                        ;
        hdr.ethernet1.dstAddr                     = VIRTUAL_DCGW_MAC                       ;
        hdr.ethernet1.etherType                   = meta.meta_ethernet.etherType           ;

        hdr.outer_udp.srcPort                     = 45149                                  ;
        hdr.outer_udp.dstPort                     = 4789                                   ;
        hdr.outer_udp.plength                     = meta.meta_ipv4.totalLen  + 16          ;
        hdr.outer_udp.checksum                    = 0                                      ;

        hdr.ipv4_outer.version                    = meta.meta_ipv4.version                 ;
        hdr.ipv4_outer.ihl                        = meta.meta_ipv4.ihl                     ;
        hdr.ipv4_outer.diffserv                   = meta.meta_ipv4.diffserv                ;
        hdr.ipv4_outer.totalLen                   = meta.meta_ipv4.totalLen + 36           ;
        hdr.ipv4_outer.identification             = meta.meta_ipv4.identification          ;
        hdr.ipv4_outer.flags                      = meta.meta_ipv4.flags                   ;
        hdr.ipv4_outer.fragOffset                 = meta.meta_ipv4.fragOffset              ;
        hdr.ipv4_outer.ttl                        = meta.meta_ipv4.ttl                     ;
        hdr.ipv4_outer.protocol                   = meta.meta_ipv4.protocol                ;
        hdr.ipv4_outer.hdrChecksum                = meta.meta_ipv4.hdrChecksum             ;
        hdr.ipv4_outer.srcAddr                    = GW_IP                                  ;
        hdr.ipv4_outer.dstAddr                    = DCGW_IP_DL                             ;

    }

    @name(".vEPG_DL") table gtp_encap {
    key = {

           hdr.inner_ipv4.dstAddr : exact;
    }

    actions = { gtp_encapsulate; drop;}
    size = 100000;
    default_action = drop;

}

/******************************** Forwarding *************************************/


    @name(".pkt_send") action pkt_send(bit<48> macd, bit<9> port, bit<48> own_mac ) {

        hdr.ethernet_outer.setValid()                                                 ;
        hdr.ethernet_outer.srcAddr          = own_mac                                 ;
        hdr.ethernet_outer.dstAddr          = macd                                    ;
        hdr.ethernet_outer.etherType        = ETHERTYPE_IPV4                          ;
        standard_metadata.egress_port       = port                                    ;

    }

     @name(".ipv4_forward") table ipv4_forward {
     key = {
           meta.routing_metadata.nhgrp : lpm;
           }

     actions = { pkt_send; drop; }
     size = 100;
     default_action = drop;
     }

    @name(".set_nhgrp") action set_nhgrp(bit<8> nhgrp) {

        meta.routing_metadata.nhgrp         = nhgrp                                    ;
        hdr.ipv4_outer.ttl                  = hdr.ipv4_outer.ttl - 1                   ;
    }

    @name(".ipv4_lpm") table ipv4_lpm {
    key = {

          hdr.ipv4_outer.dstAddr : lpm;

    }
    actions = { set_nhgrp; drop; }
    size = 100;
    default_action = drop;
    }

/*********************************************************************************/
/*********************************** Firewall_DL *********************************/
/*********************************************************************************/

    @name(".firewall_DL") table firewall_dl {
    key = {

	      hdr.inner_ipv4.srcAddr   : exact;
    }

    actions = { drop; nop;}
    size = 1000;
    default_action = nop();
    }

/*********************************************************************************/
/********************************* Firewall_UL ***********************************/
/*********************************************************************************/

    @name(".firewall_UL") table firewall_ul {
    key = {

	      hdr.inner1_ipv4.dstAddr   : exact;
    }

    actions = { drop; nop;}
    size = 1000;
    default_action = nop();
    }

/*********************************************************************************/
/********************************** Rate Limiter *********************************/
/*********************************************************************************/

/*
    DirectMeter( MeterType_t.BYTES) teid_meters;
    @name(".apply_meter") action apply_meter() {
         teid_meters.execute(); // 0- Green, 1-Yellow, 2. Red
    }

    @name(".teid_rate_limiter") table teid_rate_limiter {
    key = {
        meta.gtp_metadata.teid : exact;
    }
    actions = { apply_meter; nop;}
    size = 256;
    default_action = nop;
    }

*/

/*********************************************************************************/
/************************************* Counter ***********************************/
/*********************************************************************************/

/*

    counter(64, CounterType.packets_and_bytes) port_counter;

    action tally() {
    port_counter.count((ByteCounter_t) standard_metadata.ingress_port);
   }

    @name(".count_table") table count_table {

    key = {
        standard_metadata.ingress_port: exact ;
    }

    actions = {tally; nop;
              }

//    default_action = nop;
     size = 512;

    }

*/


/*********************************************************************************/
/**************************** Apply **********************************************/
/*********************************************************************************/

apply {
	    smac.apply();
      dmac.apply();
      {

        if ( hdr.ipv4.isValid() )
      {
           if (hdr.gtp.isValid())
              {
	            firewall_ul.apply();
              gtp_decap.apply();
               }
	       else
              {
              firewall_dl.apply();
              gtp_encap.apply();
              }
      ipv4_lpm.apply();
      ipv4_forward.apply();

	  }
       }
   }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

        apply {
              }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control Ipv4ComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { /*

	      update_checksum(
	      hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
             */
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
/*
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.inner1_tcp);
        packet.emit(hdr.gtp);
        packet.emit(hdr.gtp_teid);
        packet.emit(hdr.inner1_ipv4);
        packet.emit(hdr.inner1_tcp);
  */

    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
 }

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
Ipv4ComputeChecksum(),
MyDeparser()
) main;
