/****************Parser********************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#include "standard_headers.p4"
#include "constants.p4"

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
#if __TARGET_TOFINO__ == 2
        pkt.advance(192);
#else
        pkt.advance(64);
#endif
        transition accept;
    }
}


parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------

parser SwitchIngressParser(
        packet_in packet,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    //Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;
    TofinoIngressParser() tofino_parser;
/*
    state start {
        tofino_parser.apply(packet, ig_intr_md);
        transition select(ig_intr_md.ingress_port) {
              CPU_PORT: parse_packet_out;
              default: parse_ethernet;
    }

   }


    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
   }

*/

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

control SwitchIngressDeparser(
        packet_out packet,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
 
        packet.emit(hdr.ethernet);        
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.gtp);
        packet.emit(hdr.inn1_ipv4);
        packet.emit(hdr.inner_tcp);

 
    }
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------

parser SwitchEgressParser(
        packet_in packet,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

 	TofinoEgressParser() tofino_parser;

	state start {
        tofino_parser.apply(packet, eg_intr_md);
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
       //Checksum<bit<16>>(HashAlgorithm_t.CSUM16) ipv4_checksum;

    apply {
       
    }

}


