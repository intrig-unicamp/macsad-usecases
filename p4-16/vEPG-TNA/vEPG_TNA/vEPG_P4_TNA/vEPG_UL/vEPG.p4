#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "include/parser.p4"
//#include "include/Filtering.p4"
//#include "include/Counter.p4"
#include "include/size.p4"
#include "include/standard_headers.p4"
#include "include/packet_io.p4"


/**************  I N G R E S S   P R O C E S S I N G   *******************/

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
 
   /*********************** MAC_LEARN ***********************************/

       action mac_learn() {
        
       /*
        digest(MAC_LEARN_RECEIVER, { hdr.ethernet.srcAddr, ig_intr_md.ingress_port } );
	meta.routing_metadata.mac_da = hdr.inner_ethernet.dstAddr;
        meta.routing_metadata.mac_sa = hdr.inner_ethernet.srcAddr;
        */ 
 
       }     

    table smac {
    key = {
        hdr.ethernet.srcAddr : exact;
    }
    actions = {mac_learn; nop; }
    size = SMAC_TABLE_SIZE;
    default_action = nop;
    }
    

    table dmac {
    key = {
        hdr.ethernet.dstAddr : exact;
    }
    actions = {nop; drop;}
    size = 1024;
    default_action = drop;
    }    

    action bcast() {
       // standard_metadata.egress_spec = 100;
    }

   /***************************** GTP ENCAP **********************************/


       action gtp_encapsulate(teid_t teid ) {


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
        meta.meta_udp.checksum                 =   hdr.udp.checksum                ;
        meta.meta_ipv4.totalLen                =   hdr.ipv4.totalLen               ;

        /* adding header  */

        hdr.inn1_ipv4.setValid();
        hdr.gtp.setValid();
        hdr.inner_udp.setValid();

        hdr.inn1_ipv4.version                  =  meta.meta_inner_ipv4.version         ;
        hdr.inn1_ipv4.ihl                      =  meta.meta_inner_ipv4.ihl             ;
        hdr.inn1_ipv4.diffserv                 =  meta.meta_inner_ipv4.diffserv        ;
        hdr.inn1_ipv4.totalLen                 =  meta.meta_inner_ipv4.totalLen        ;
        hdr.inn1_ipv4.identification           =  meta.meta_inner_ipv4.identification  ;
        hdr.inn1_ipv4.flags                    =  meta.meta_inner_ipv4.flags           ;
        hdr.inn1_ipv4.fragOffset               =  meta.meta_inner_ipv4.fragOffset      ;
        hdr.inn1_ipv4.ttl                      =  meta.meta_inner_ipv4.ttl             ;
        hdr.inn1_ipv4.protocol                 =  meta.meta_inner_ipv4.protocol        ;
        hdr.inn1_ipv4.hdrChecksum              =  meta.meta_inner_ipv4.hdrChecksum     ;
        hdr.inn1_ipv4.srcAddr                  =  meta.meta_inner_ipv4.srcAddr         ;
        hdr.inn1_ipv4.dstAddr                  =  meta.meta_inner_ipv4.dstAddr         ;

        hdr.gtp.teid                           =  teid                                 ;
        hdr.gtp.version                        =  1                                    ;
        hdr.gtp.pFlag                          =  1                                    ;
        hdr.gtp.messageType                    =  0xff                                 ;
       // hdr.gtp.messageLength = hdr.inner1_ipv4.totalLen + 8                         ;

        hdr.inner_udp.srcPort                  =  2152                                 ;
        hdr.inner_udp.dstPort                  =  2152                                 ;
        hdr.inner_udp.plength                  =  meta.meta_udp.plength -14            ;
        hdr.inner_udp.checksum                 =  0                                    ;

        hdr.inner_ipv4.totalLen                =  meta.meta_inner_ipv4.totalLen + 36   ;
        hdr.inner_ipv4.protocol                =  IPPROTO_UDP                          ;
        hdr.inner_ipv4.srcAddr                 =  VIRTUAL_EPG_IP                       ;
        hdr.inner_ipv4.dstAddr                 =  VIRTUAL_DCGW_IP                      ;

        hdr.inner_ethernet.srcAddr             =  VIRTUAL_EPG_MAC                      ;
        hdr.inner_ethernet.dstAddr             =  VIRTUAL_DCGW_MAC                     ;
        hdr.inner_ethernet.etherType           =  ETHERTYPE_IPV4                       ;

        hdr.udp.srcPort                        =  45149                                ;
        hdr.udp.dstPort                        =  4789                                 ;
        hdr.udp.plength                        =  meta.meta_udp.plength  + 36          ;
        hdr.udp.checksum                       =  0                                    ;

        hdr.ipv4.totalLen                      =  meta.meta_ipv4.totalLen + 36         ;
        hdr.ipv4.srcAddr                       =  GW_IP                                ;
        hdr.ipv4.dstAddr                       =  IP                                   ;

        hdr.ethernet.srcAddr                   =  OWN_MAC                              ;
        hdr.ethernet.dstAddr                   =  MACD                                 ;
        hdr.ethernet.etherType                 =  ETHERTYPE_IPV4                       ;

    }

    table vEPG_DL {
    key = {
           hdr.inner_ipv4.dstAddr : lpm @name("ipv4_dst");
    }

    actions = { gtp_encapsulate; drop;}
    size = vEPG_DL_TABLE_SIZE;
    default_action = drop;

    }

   /***************************** Firewall DL *****************************/ 
  
    table firewall_DL {
    key = {
              hdr.inner_ipv4.srcAddr  : exact @name("ipv4_dst");   
    }

    actions = { drop; nop; }
    size = FIREWALL_DL_TABLE_SIZE;
    default_action = nop();
    }

   /****************************** GTP Decap *****************************/


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

        hdr.udp.plength      		 = meta.meta_udp.plength - 36  		 ;
        
        hdr.ipv4.totalLen      		 = meta.meta_ipv4.totalLen - 36   	 ;
        hdr.ipv4.srcAddr         	 = GW_IP  	  		         ;
        hdr.ipv4.dstAddr        	 = IP    			         ;
    
        hdr.ethernet.srcAddr 		 = OWN_MAC				 ;
        hdr.ethernet.dstAddr 		 = MACD					 ;
        hdr.ethernet.etherType 		 = ETHERTYPE_IPV4			 ;       

}

    table vEPG_UL {
    key = {

          hdr.inner_ipv4.dstAddr : exact @name("ipv4_dst");
    }

    actions = { gtp_decapsulate; drop;}
    size = vEPG_UL_TABLE_SIZE;
    default_action = drop;

    }

   /******************************* Firewall UL ****************************/

    table firewall_UL {
    key = {
              hdr.inner1_ipv4.dstAddr : lpm  @name("ipv4_dst");
    }

    actions = { nop; drop; }
    size = FIREWALL_UL_TABLE_SIZE;
    default_action = drop();
    }
 
  /********************************* Forwarding ***************************/

    action pkt_send() {

            ig_tm_md.ucast_egress_port = port;  

     }

    action set_nhgrp() {
            hdr.ipv4.ttl  = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
    key = {
        hdr.ipv4.dstAddr : exact @name("ipv4_dst");
        // hdr.ipv4.dstAddr : lpm;
    }
    actions = { set_nhgrp; drop; }
    size = IPV4_LPM_TABLE_SIZE;
    default_action = drop;
    }


   /***************************** Apply *****************************************/ 

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
	      firewall_UL.apply();
              vEPG_UL.apply();
            }
	else
           { 
              firewall_DL.apply();
              vEPG_DL.apply();
           }
    

   // Filtering.apply(hdr, meta);
   // Count.apply(hdr, meta, ig_intr_md);  

      ipv4_lpm.apply();
      pkt_send();

	}
     } 
  } 
}

/***************  E G R E S S   P R O C E S S I N G   ******************/

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

        apply { 
             }
        }    
    
/***********************  S W I T C H  **********************************/

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;


Switch(pipe) main;

