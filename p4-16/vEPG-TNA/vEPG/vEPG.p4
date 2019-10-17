
 // code is missing to follow the Barefoot SLACA terms & conditions

#include "include/parser.p4"
#include "include/size.p4"
#include "include/standard_headers.p4"
#include "include/packet_io.p4"

/*************************************************************************/
/**************  I N G R E S S   P R O C E S S I N G   *******************/
/*************************************************************************/

control SwitchIngress(

        // code is missing to follow the Barefoot SLACA terms & conditions

        action drop() {

        // code is missing to follow the Barefoot SLACA terms & conditions

        }

        action nop() {

        }

/*********************** MAC_LEARN ***************************************/

       action mac_learn() {

       // code is missing to follow the Barefoot SLACA terms & conditions

       }

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

/***************************** GTP ENCAP ***********************************/


      action gtp_encapsulate(teid_t teid, bit<32> enb_ip ) {


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

        hdr.inn1_ipv4.version	               =  meta.meta_inner_ipv4.version         ;
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

        hdr.gtp.teid                           =  teid	                 	       ;
        hdr.gtp.version 		       =  1	                               ;
        hdr.gtp.pFlag 			       =  1	                               ;
        hdr.gtp.messageType 		       =  0xff		                       ;
       // hdr.gtp.messageLength                =  hdr.inner1_ipv4.totalLen + 8         ;

        hdr.inner_udp.srcPort                  =  2152 			               ;
        hdr.inner_udp.dstPort                  =  2152                                 ;
        hdr.inner_udp.plength                  =  meta.meta_udp.plength -14            ;
        hdr.inner_udp.checksum                 =  0	                               ;

        hdr.inner_ipv4.totalLen       	       =  meta.meta_inner_ipv4.totalLen + 36   ;
        hdr.inner_ipv4.protocol                =  IPPROTO_UDP                          ;
        hdr.inner_ipv4.srcAddr        	       =  VIRTUAL_EPG_IP                       ;
        hdr.inner_ipv4.dstAddr       	       =  enb_ip                               ;

        hdr.inner_ethernet.srcAddr             =  VIRTUAL_EPG_MAC                      ;
        hdr.inner_ethernet.dstAddr             =  VIRTUAL_DCGW_MAC                     ;
        hdr.inner_ethernet.etherType           =  ETHERTYPE_IPV4                       ;

    }

    table gtp_encap {
    key = {
           hdr.inner_ipv4.dstAddr : exact @name("ipv4_dst");
    }

    actions = { gtp_encapsulate; drop;}
    size = gtp_encap_tbl_size;
    default_action = drop;

    }

/********************************** Firewall DL *****************************/

    table firewall_dL {
    key = {
              hdr.inner_ipv4.srcAddr  : exact @name("ipv4_dst");
    }

    actions = { drop; nop; }
    size = firewall_dl_tbl_size;
    default_action = nop();
    }

/****************************** GTP Decap ***********************************/


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

        hdr.inner_ethernet.srcAddr       = VIRTUAL_EPG_MAC                 	 ;
        hdr.inner_ethernet.dstAddr 	 = VIRTUAL_DCGW_MAC	                 ;
        hdr.inner_ethernet.etherType 	 = ETHERTYPE_IPV4                        ;

   }

    table gtp_decap {
    key = {

          hdr.inner_ipv4.dstAddr : lpm @name("ipv4_dst");
    }

    actions = { gtp_decapsulate; drop;}
    size = gtp_decap_tbl_size;
    default_action = drop;

    }

/******************************* Firewall UL **********************************/

    table firewall_ul {
    key = {
              hdr.inner1_ipv4.dstAddr : exact  @name("ipv4_dst");
    }

    actions = { nop; drop; }
    size = firewall_ul_tbl_size;
    default_action = drop();
    }

/********************************* Forwarding **********************************/

   action set_nhop_dl(bit<32> dcgw_ip, bit<48> dcgw_dmac) {

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

    table ipv4_lpm_dl {
    key = {
        hdr.ipv4.dstAddr : lpm @name("ipv4_dst");
    }
    actions = { set_nhop_dl; drop; }
    size = ipv4_lpm_dl_tbl_size;
    default_action = drop;
    }


    action set_nhop_ul(bit<32> dcgw_ip, bit<48> dcgw_dmac) {

        hdr.udp.srcPort                        =  45149                                ;
        hdr.udp.dstPort                        =  4789                                 ;
        hdr.udp.plength                        =  meta.meta_udp.plength  - 36          ;
        hdr.udp.checksum                       =  0                                    ;

        hdr.ipv4.totalLen                      =  meta.meta_ipv4.totalLen - 36         ;
        hdr.ipv4.srcAddr                       =  GW_IP                                ;
        hdr.ipv4.dstAddr                       =  dcgw_ip                              ;

        hdr.ethernet.srcAddr                   =  OWN_MAC                              ;
        hdr.ethernet.dstAddr                   =  dcgw_dmac                            ;
        hdr.ethernet.etherType                 =  ETHERTYPE_IPV4                       ;

        hdr.ipv4.ttl  = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm_ul {
    key = {
        hdr.ipv4.dstAddr : lpm @name("ipv4_dst");
    }
    actions = { set_nhop_ul; drop; }
    size = ipv4_lpm_ul_tbl_size;
    default_action = drop;
    }


    action pkt_send() {

       ig_tm_md.ucast_egress_port = port;

     }


/***************************** Apply *******************************************/

apply {

  // code is missing to follow the Barefoot SLACA terms & conditions

        smac.apply();
        dmac.apply();

       {
        if ( hdr.ipv4.isValid() )
       {
        if (hdr.gtp.isValid())
           {
              firewall_ul.apply();
              gtp_decap.apply();
              ipv4_lpm_ul.apply();
           }
	else
           {
             firewall_dl.apply();
             gtp_encap.apply();
             ipv4_lpm_dl.apply();
           }

      pkt_send();

      // code is missing to follow the Barefoot SLACA terms & conditions

    	}
    }
  }
}

/***************  E G R E S S   P R O C E S S I N G   **************************/

control SwitchEgress(

        // code is missing to follow the Barefoot SLACA terms & conditions

        ) {

        apply {
             }
        }

/***********************  S W I T C H  *****************************************/

Pipeline(
// code is missing to follow the Barefoot SLACA terms & conditions)


Switch(pipe) main;
