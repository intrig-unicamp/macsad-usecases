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


#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "include/parser.p4"
#include "include/size.p4"
#include "include/standard_headers.p4"
#include "include/packet_io.p4"

/*************************************************************************/
/**************  I N G R E S S   P R O C E S S I N G   *******************/
/*************************************************************************/

control SwitchIngress(
        inout header_t hdr,
        inout ingress_metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

        packetio_ingress() pkting;
        packetio_egress() pktout;

        action drop() {
   
        ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.  
  
        }

        action nop() {
       
        }

 
/**************************** mac_learn ******************************************/

     action mac_learn() {
        
       /*
        digest(MAC_LEARN_RECEIVER, { hdr.ethernet.srcAddr, ig_intr_md.ingress_port } );
	meta.routing_metadata.mac_da = hdr.inner_ethernet.dstAddr;
        meta.routing_metadata.mac_sa = hdr.inner_ethernet.srcAddr;
        */ 

       }

/*********************** match src/dst mac addr ***********************************/

    table smac {
    key = {
        hdr.ethernet.srcAddr : lpm;
    }
    actions = {mac_learn; nop; }
    size = smac_tbl_size;
    default_action = nop;
    }
    
    table dmac {
    key = {
        hdr.ethernet.dstAddr : lpm;
    }
    actions = {nop; drop;}
    size = dmac_tbl_size;
    default_action = drop;
    }    

    action bcast() {
       // standard_metadata.egress_spec = 100;
    }


/*********************************** gtp encap ****************************************/
    
     action gtp_encapsulate() {

        meta.meta_inner_ipv4.version           =   hdr.inner_ipv4.version          ;
        meta.meta_inner_ipv4.ihl               =   hdr.inner_ipv4.ihl              ;
        meta.meta_inner_ipv4.diffserv          =   hdr.inner_ipv4.diffserv         ;
        meta.meta_inner_ipv4.totalLen          =   hdr.inner_ipv4.totalLen         ;
        meta.meta_inner_ipv4.identification    =   hdr.inner_ipv4.identification   ;
        meta.meta_inner_ipv4.flags             =   hdr.inner_ipv4.flags            ;
        meta.meta_inner_ipv4.fragOffset        =   hdr.inner_ipv4.fragOffset       ;
        meta.meta_inner_ipv4.ttl               =   hdr.inner_ipv4.ttl              ;
        meta.meta_inner_ipv4.protocol          =   hdr.inner_ipv4.protocol         ;
        meta.meta_inner_ipv4.hdrChecksum       =   hdr.inner_ipv4.hdrChecksum      ;
        meta.meta_inner_ipv4.srcAddr           =   hdr.inner_ipv4.srcAddr          ;
        meta.meta_inner_ipv4.dstAddr           =   hdr.inner_ipv4.dstAddr          ;

        meta.meta_udp.plength                  =   hdr.udp.plength                 ;
        meta.meta_ipv4.totalLen                =   hdr.ipv4.totalLen               ;


        hdr.inner_ipv4.srcAddr                   =   VIRTUAL_EPG_IP                    ;
        hdr.inner_ipv4.dstAddr                   =   meta.epg.enb_ip                   ;

        /* adding header  */

        hdr.inner1_ipv4.setValid();
        hdr.inner_udp.setValid();
        hdr.gtp.setValid();

        hdr.inner1_ipv4.totalLen                 =  meta.meta_inner_ipv4.totalLen + 36   ;
        hdr.inner1_ipv4.protocol                 =  IPPROTO_UDP                          ;
        hdr.inner1_ipv4.srcAddr                  =  hdr.inner_ipv4.srcAddr               ;
        hdr.inner1_ipv4.dstAddr                  =  hdr.inner_ipv4.dstAddr               ;
        hdr.inner1_ipv4.version                  =  meta.meta_inner_ipv4.version         ;
        hdr.inner1_ipv4.ihl                      =  meta.meta_inner_ipv4.ihl             ;
        hdr.inner1_ipv4.diffserv                 =  meta.meta_inner_ipv4.diffserv        ;
        hdr.inner1_ipv4.identification           =  meta.meta_inner_ipv4.identification  ;
        hdr.inner1_ipv4.flags                    =  meta.meta_inner_ipv4.flags           ;
        hdr.inner1_ipv4.fragOffset               =  meta.meta_inner_ipv4.fragOffset      ;
        hdr.inner1_ipv4.ttl                      =  meta.meta_inner_ipv4.ttl             ;
        hdr.inner1_ipv4.hdrChecksum              =  0                                    ;


        hdr.inner_udp.srcPort                  =  2152                                 ;
        hdr.inner_udp.dstPort                  =  2152                                 ;
        hdr.inner_udp.plength                  =  56                                   ;
        hdr.inner_udp.checksum                 =  0                                    ;

        hdr.gtp.teid                           =  meta.epg.teid                        ;
        hdr.gtp.version                        =  0x01                                 ;
        hdr.gtp.pFlag                          =  1                                    ;
        hdr.gtp.messageType                    =  0xff                                 ;
        hdr.gtp.messageLength                  =  meta.meta_inner_ipv4.totalLen        ;

        hdr.inner_ethernet.srcAddr             =  VIRTUAL_EPG_MAC                      ;
        hdr.inner_ethernet.dstAddr             =  VIRTUAL_DCGW_MAC                     ;
        hdr.inner_ethernet.etherType           =  ETHERTYPE_IPV4                       ;

}

    action set_dl_sess_info(teid_t teid, bit<32> enb_ip) 
  
    {
     meta.epg.teid = teid;
     meta.epg.enb_ip = enb_ip;
    }

    table dl_sess_lookup {
    key = {
           // UD addr for downlink
           hdr.inner_ipv4.dstAddr : exact @name("ipv4_dst");
    }

    actions = {set_dl_sess_info; drop;}
    size = dl_sess_lookup_tbl_size;
    default_action = drop;

    }


/*************************************** firewall dl ***********************************/

    table firewall_dl {
    key = {
             hdr.inner_ipv4.srcAddr  : exact @name("ipv4_dst");
    }

    actions = { drop; nop; }
    size = firewall_dl_tbl_size;
    default_action = nop();
    }

/**************************************** gtp decap ***********************************/


    action gtp_decapsulate() {

        meta.meta_ipv4.totalLen           = hdr.ipv4.totalLen             ;
        meta.meta_udp.plength 		  = hdr.udp.plength               ;
        meta.meta_inner1_ipv4.srcAddr     = hdr.inner1_ipv4.srcAddr       ;
        meta.meta_inner1_ipv4.dstAddr     = hdr.inner1_ipv4.dstAddr       ;
        meta.meta_inner1_ipv4.totalLen    = hdr.inner1_ipv4.totalLen      ;
        meta.gtp_metadata.teid            = hdr.gtp.teid                  ;

        /* removing header */

        hdr.inner1_ipv4.setInvalid();
        hdr.gtp.setInvalid();
        hdr.inner_udp.setInvalid();

        hdr.inner_ipv4.protocol          = IPPROTO_TCP                           ;
        hdr.inner_ipv4.srcAddr           = meta.meta_inner1_ipv4.srcAddr         ;
        hdr.inner_ipv4.dstAddr           = meta.meta_inner1_ipv4.dstAddr         ;
        hdr.inner_ipv4.totalLen          = meta.meta_inner1_ipv4.totalLen        ;                                     

        hdr.inner_ethernet.srcAddr       = VIRTUAL_EPG_MAC 			 ;
        hdr.inner_ethernet.dstAddr 	 = VIRTUAL_DCGW_MAC			 ;
        hdr.inner_ethernet.etherType 	 = ETHERTYPE_IPV4		         ;	            

}
  
    table gtp_decap {
    key = {

          hdr.inner_ipv4.dstAddr : lpm @name("ipv4_dst");
    }

    actions = { gtp_decapsulate; drop;}
    size = gtp_decap_tbl_size;
    default_action = drop;

    }

/*************************************** firewall ul *********************************/

    table firewall_ul {
    key = {
              hdr.inner1_ipv4.dstAddr : exact  @name("ipv4_dst");
    }

    actions = { nop; drop; }
    size = firewall_ul_tbl_size;
    default_action = drop();
    }
 
/*************************************** Forwarding **********************************/


    action set_nhop(bit<32> dcgw_ip, bit<48> dcgw_dmac) {

        hdr.udp.srcPort                        =  45149                                ;
        hdr.udp.dstPort                        =  4789                                 ;
        hdr.udp.plength                        =  meta.meta_udp.plength  + 36          ;
        hdr.udp.checksum                       =  0                                    ;

        hdr.ipv4.totalLen                      =  meta.meta_ipv4.totalLen + 36         ;
        hdr.ipv4.srcAddr                       =  GW_IP                                ;
        hdr.ipv4.dstAddr                       =  dcgw_ip                              ;

        hdr.ethernet.srcAddr                   =  OWN_MAC                              ;
        hdr.ethernet.dstAddr                   =  dcgw_dmac                            ;
        hdr.ethernet.etherType                 =  ETHERTYPE_IPV4                       ;

       hdr.ipv4.ttl  = hdr.ipv4.ttl - 1;
    }
 
    table ipv4_lpm {
    key = {
        hdr.ipv4.dstAddr : lpm @name("ipv4_dst");
    }
    actions = { set_nhop; drop; }
    size = ipv4_lpm_tbl_size;
    default_action = drop;
    }

    action pkt_send() {

       ig_tm_md.ucast_egress_port = port;

     }

/**************************************** Apply ***************************************/ 

apply {
       
    // pkting.apply(hdr, ig_intr_md, ig_tm_md);
    // pktout.apply(hdr, ig_intr_md, ig_tm_md);
	
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
             dl_sess_lookup.apply();
             gtp_encapsulate();           
           }

      ipv4_lpm.apply();
      pkt_send();
      ig_tm_md.bypass_egress = true;
    
   // Filtering.apply(hdr, meta);
   // Count.apply(hdr, meta, ig_intr_md);  

	}
     }
  } 
}

/**************************  E G R E S S   P R O C E S S I N G  ******** ******************/

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

        apply{ }
}



/********************************  S W I T C H  *******************************************/

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;


Switch(pipe) main;

