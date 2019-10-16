
#include <core.p4>
// code is missing to follow the Barefoot SLACA terms & conditions
#include "standard_headers.p4"
#include "constants.p4"

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser TofinoIngressParser(
        packet_in pkt,

   // code is missing to follow the Barefoot SLACA terms & condotions

parser TofinoEgressParser(

   // code is missing to follow the Barefoot SLACA terms & condotions

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------

parser SwitchIngressParser(

    // code is missing to follow the Barefoot SLACA terms & condotions

        ) {

    // code is missing to follow the Barefoot SLACA terms & condotions


   state start {
        tofino_parser.apply(packet, ig_intr_md);
        transition parse_ethernet;
  }


   state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }


   state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }

    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        ig_md.arp_metadata.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }


   state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP  : parse_udp;
            IPPROTO_ICMP : parse_icmp;
            default      : accept;
        }
    }


   state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            UDP_PORT_VXLAN : parse_vxlan;
            default        : accept;
        }
    }


    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }


    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_inner_ipv4;
            default 	   : accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            IPPROTO_UDP  : parse_inner_udp;
            IPPROTO_TCP  : parse_inner_tcp;
            default      : accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition select(hdr.inner_udp.dstPort) {
            GTP_UDP_PORT : parse_gtp;
            default      : accept;
        }
    }

   state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        transition accept;
    }


   state parse_gtp {
        packet.extract(hdr.gtp);
        transition parse_inner1_ipv4;

}


   state parse_inner1_ipv4 {
        packet.extract(hdr.inner1_ipv4);
        transition select( hdr.inner1_ipv4.protocol) {
            IPPROTO_TCP  : parse_inner1_tcp;
            default      : accept;
        }

     }

   state parse_inner1_tcp {
        packet.extract(hdr.inner1_tcp);
        transition accept;
    }

}


// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------

// code is missing to follow the Barefoot SLACA terms & conditions

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------

// code is missing to follow the Barefoot SLACA terms & conditions


// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        // code is missing to follow the Barefoot SLACA terms & conditions
        ) {

    apply {

    }

}
