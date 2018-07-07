#include <core.p4>
#include <v1model.p4>
#include "include/standard_headers.p4"

/***********************  C O N S T A N T S  *****************************/
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;

/***********************  H E A D E R S  *********************************/
struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/***********************  M E T A D A T A  *******************************/
struct routing_metadata_t {
    bit<32> dst_ipv4;
    bit<32> nhop_ipv4;
    bit<48>  mac_da;
    bit<48>  mac_sa;
    bit<9>   egress_port;

    bit<8>  if_index;    
    bit<48> if_mac_addr;
    bit<8>  is_int_if;
    
}

struct metadata {
    @name(".routing_metadata") 
    routing_metadata_t routing_metadata;
}

/***********************  P A R S E R  ***********************************/
parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".start") state start {
        transition parse_ethernet;
    }
    @name ("parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            default        : accept;
        }
    }
    @name ("parse_arp") state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    @name("parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6 :         parse_tcp;
            default      : accept;
        }
    }
    @name("parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        transition accept;
    }
}
@name("mac_learn_digest") struct mac_learn_digest {
    bit<8> in_port;    /* 9 bits?, it doesnt compile with other value like 16, why? */
    bit<48> mac_sa;
}

@name("natTcp_learn_digest") struct natTcp_learn_digest {
    bit<32> srcAddr;
    bit<16> srcPort;
}


/**************  I N G R E S S   P R O C E S S I N G   ******************/
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    /***************************** Drop  **************************/
     @name(".drop")action drop() {
        /*mark_to_drop();*/

    }
    /***************************** set IF info and others  **************************/
    /*action set_if_info(bit<32> ipv4_addr, bit<48> mac_addr, bit<1> is_ext) { */
    @name(".set_if_info") action set_if_info(bit<8> is_int) {
        meta.routing_metadata.mac_da = hdr.ethernet.dstAddr;
        meta.routing_metadata.mac_sa = hdr.ethernet.srcAddr;
        meta.routing_metadata.if_mac_addr = 0x010101010100;
        meta.routing_metadata.is_int_if = is_int;
        /* meta.routing_metadata.is_int_if = 1; */
    }
    @name(".if_info") table if_info {
        key = { standard_metadata.ingress_port: exact;}
        actions = {   drop;  set_if_info; }
    default_action = drop();     
   
    }
    /***************************** process mac learn  *****************************/
   
    @name(".generate_learn_notify") action generate_learn_notify() {
        digest<mac_learn_digest>(32w1024, {meta.routing_metadata.if_index, hdr.ethernet.srcAddr });
    }
    @name(".forward_l2") action forward_l2(bit<9> port) {
        standard_metadata.egress_port = port;
    }
    @name(".smac") table smac {
        actions = {
            generate_learn_notify;
        }
        key = { hdr.ethernet.srcAddr: exact; }
        size = 512;
    }
    
    @name(".dmac") table dmac {
        actions = { forward_l2; }
        key = {  hdr.ethernet.dstAddr: exact;    }
        size = 512;
    }
    /***************************** Nat control *****************************************/
    @name(".natTcp_learn") action natTcp_learn() {
        digest<natTcp_learn_digest>((bit<32>)1025, { hdr.ipv4.srcAddr, hdr.tcp.srcPort });
    }
    /*@name(".nat_hit_int_to_ext") action nat_hit_int_to_ext(bit<32> srcAddr, bit<16> srcPort) {*/ 
    /*precisa adicionar srcPort????*/
    @name(".nat_hit_int_to_ext") action nat_hit_int_to_ext(bit<32> srcAddr) {
        hdr.ipv4.srcAddr= srcAddr;
        /*hdr.tcp.srcPort = srcPort;*/
    }

    @name(".nat_up") table nat_up {
        actions = {natTcp_learn; nat_hit_int_to_ext; }
        key = { hdr.ipv4.srcAddr: exact;}
        /*key = { hdr.tcp.srcPort: exact;}*/
        size = 1024;
        default_action = natTcp_learn();     
    }

    /*@name(".nat_hit_ext_to_int") action nat_hit_ext_to_int(bit<32> dstAddr, bit<16> dstPort) {*/
    @name(".nat_hit_ext_to_int") action nat_hit_ext_to_int(bit<32> dstAddr) {
        hdr.ipv4.dstAddr = dstAddr;
        /*hdr.tcp.dstPort = dstPort; */
    }
    @name(".nat_dw") table nat_dw {
        actions = { drop; nat_hit_ext_to_int;  }
	/*key = { hdr.tcp.dstPort: ternary;} */
	key = { hdr.tcp.dstPort: exact;}
	/*key = { hdr.ipv4.dstAddr: exact;}*/
        size = 1024;
        default_action = drop();
    }
    

    /************** forwarding ipv4 ******************/
    @name(".set_dmac") action set_dmac(bit<48> dstmac) {
        hdr.ethernet.dstAddr = dstmac;
    }      
          
    @name(".set_nhop") action set_nhop(bit<9> port, bit<32> nhop_ipv4){
        standard_metadata.egress_port =  port; 
        standard_metadata.egress_spec = port;
        meta.routing_metadata.nhop_ipv4 = nhop_ipv4;
    }
    
    @name(".ipv4_lpm") table ipv4_lpm {
        key = {hdr.ipv4.dstAddr : lpm;}  
        actions = { set_nhop; drop;  }
    }
    
    @name(".rewrite_src_mac") action rewrite_src_mac(bit<48> src_mac) {
           /*hdr.ethernet.dstAddr =  meta.routing_metadata.mac_da; */
           hdr.ethernet.srcAddr =  src_mac;
           hdr.ethernet.etherType = 16w0x800;
    } 

    @name(".sendout") table sendout {
        actions = {drop; rewrite_src_mac; }
        key = {  standard_metadata.egress_port: exact; }
        size = 512;
    }    
    @name(".ping") table ping {
        actions = {nat_hit_ext_to_int; }
        key = {  hdr.ipv4.dstAddr: exact; }
        size = 512;
    } 
    @name(".forward") table forward {
        actions = {
            set_dmac;
            drop;
        }
        key = {
            meta.routing_metadata.nhop_ipv4: exact;
        }
        size = 512;
    }


    /************** APPLY ******************/
    apply {
        if_info.apply();
        smac.apply();
        if (hdr.ethernet.etherType == ETHERTYPE_ARP){   
           dmac.apply();  
        }
        else { 
           if(meta.routing_metadata.is_int_if == 1){
                         
               nat_up.apply();
           }
           else { 
             if(hdr.ipv4.protocol != 1){
               nat_dw.apply(); 
             }
             else { 
                ping.apply();
             }

           }  
           ipv4_lpm.apply(); 
           forward.apply();
           sendout.apply();
       } 
    }
    
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {        }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply { 
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
   }
}
/************   C H E C K S U M    V E  I F I C A T I O N   *************/
control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
