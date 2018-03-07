/* -*- P4_16 -*- */
/* -*- Juan -*- */
#include "include/standard_headers.p4"
#include <core.p4>
#include <v1model.p4>

/***********************  C O N S T A N T S  *****************************/
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IPPROTO_ICMP   = 0x01;

/***********************  H E A D E R S  *********************************/
typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<9>   port_id_t; 

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;


const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;


struct my_headers_t {
    ethernet_t   ethernet;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    ipv4_t       ipv4;
    gre_t        gre;
    nvgre_t      nvgre;
    tcp_t        tcp;
    icmp_t       icmp;
    @name("inner_ipv4") 
    ipv4_t       inner_ipv4;
    @name("inner_ethernet") 
    ethernet_t   inner_ethernet;
    @name("inner_tcp") 
    tcp_t        inner_tcp;
    @name("inner_icmp") 
    icmp_t       inner_icmp;
    @name("cpu_header") 
    cpu_header_t cpu_header;
}

/***********************  M E T A D A T A  *******************************/

struct my_metadata_t {
    ipv4_addr_t dst_ipv4;
    ipv4_addr_t src_ipv4;
    mac_addr_t  mac_da;
    mac_addr_t  mac_sa;
    port_id_t   egress_port;
    mac_addr_t  my_mac;

    bit<32> nhop_ipv4;
    bit<1>  do_forward;
    bit<16> tcp_sp;
    bit<16> tcp_dp;

    bit<8>  if_index;    
    bit<32> if_ipv4_addr;
    bit<48> if_mac_addr;
    bit<1>  is_ext_if;
    
    bit<24> tunnel_vni;
    bit<5>  ingress_tunnel_type;
    bit<1>  tcp_inner_en;
    bit<16> lkp_inner_l4_sport;
    bit<16> lkp_inner_l4_dport;

    ipv4_addr_t  dst_inner_ipv4;
    ipv4_addr_t  src_inner_ipv4;

    bit<32> meter_tag;
    
}

/***********************  P A R S E R  ***********************************/
parser MyParser(
    packet_in             packet,
    out   my_headers_t    hdr,
    inout my_metadata_t   meta,
    inout standard_metadata_t  standard_metadata)
{
    @name(".start") state start {
        meta.if_index = (bit<8>)standard_metadata.ingress_port;
        transition select((packet.lookahead<bit<64>>())[63:0]) {  /* see the pkg preambel=0? 8 zeros */
            64w0: parse_cpu_header;
            default: parse_ethernet;
        }
    }
    @name(".parse_cpu_header") state parse_cpu_header {
        packet.extract(hdr.cpu_header);
        meta.if_index = hdr.cpu_header.if_index;
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP  : parse_arp;
            default        : accept;
        }
    }
    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;
            default : accept;
        }
    }
   @name("parse_arp_ipv4") state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }            
    @name("parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.dst_ipv4 = hdr.ipv4.dstAddr;
        transition select(hdr.ipv4.protocol) {
            IPPROTO_ICMP : parse_icmp;
            8w0x6 :         parse_tcp;
            8w47 :         parse_gre;
            default      : accept;
        }
    }
    @name("parse_icmp") state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }    
    @name("parse_tcp") state parse_tcp {
        packet.extract<tcp_t>(hdr.tcp);
        meta.tcp_sp = hdr.tcp.srcPort;
        meta.tcp_dp = hdr.tcp.dstPort;
        transition accept;
    }
    @name("parse_gre") state parse_gre {
        packet.extract<gre_t>(hdr.gre);
        transition select(hdr.gre.C, hdr.gre.R, hdr.gre.K, hdr.gre.S, hdr.gre.s, hdr.gre.recurse, hdr.gre.flags, hdr.gre.ver, hdr.gre.proto) {
            (1w0x0, 1w0x0, 1w0x1, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x6558): parse_nvgre;
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x800): parse_gre_ipv4;
            default: accept;
        }
    }
    @name(".parse_gre_ipv4") state parse_gre_ipv4 {
        meta.ingress_tunnel_type = 5w1;
        transition parse_inner_ipv4;
    }

    @name(".parse_inner_ipv4") state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        meta.dst_inner_ipv4 = hdr.inner_ipv4.dstAddr;
        transition select(hdr.inner_ipv4.fragOffset, hdr.inner_ipv4.ihl, hdr.inner_ipv4.protocol) {
            (13w0x0, 4w0x5, 8w0x1): parse_inner_icmp;
            (13w0x0, 4w0x5, 8w0x6): parse_inner_tcp;
            /*(13w0x0, 4w0x5, 8w0x11): parse_inner_udp;*/
            default: accept;
        }
    }
    @name(".parse_inner_icmp") state parse_inner_icmp {
        packet.extract(hdr.inner_icmp);
        /*meta.lkp_inner_l4_sport = hdr.inner_icmp.typeCode;  ver esto*/
        transition accept;
    }

    @name(".parse_inner_tcp") state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        meta.tcp_inner_en = 1w1;
        meta.lkp_inner_l4_sport = hdr.inner_tcp.srcPort;
        meta.lkp_inner_l4_dport = hdr.inner_tcp.dstPort;
        transition accept;
    }

    @name(".parse_nvgre") state parse_nvgre {
        packet.extract(hdr.nvgre);
        meta.ingress_tunnel_type = 5w5;
        meta.tunnel_vni = hdr.nvgre.tni;
        transition parse_inner_ethernet;
    }

    @name(".parse_inner_ethernet") state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            16w0x800: parse_inner_ipv4;
            default: accept;
        }
    }
}

/************   C H E C K S U M    V E R I F I C A T I O N   *************/
control MyVerifyChecksum(
    /*in    my_headers_t   hdr,*/
    inout    my_headers_t   hdr,
    inout my_metadata_t  meta)
{
    apply {     }
}

/***************************** process meter  *****************************/
control process_meter(inout my_headers_t hdr,
                      inout my_metadata_t meta, 
                      inout standard_metadata_t standard_metadata) {
    @name(".my_meter") meter(32w16384, MeterType.packets) my_meter;
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name("._nop") action _nop() {
    }
    @name(".m_action") action m_action(bit<32> meter_idx) {
        my_meter.execute_meter((bit<32>)meter_idx, meta.meter_tag);
        standard_metadata.egress_spec = 9w2;
    }
    @name(".m_filter") table m_filter {
        actions = {_drop; _nop; }
        key = { meta.meter_tag: exact;}
        size = 16;
    }
    @name(".m_table") table m_table {
        actions = {m_action; _nop; }
        key = { hdr.ethernet.srcAddr: exact;}
        size = 16384;
    }
    apply {
        m_table.apply();
        m_filter.apply();
    }
}


/***************************** process meter dl  *****************************/
control proc_meter_dl(inout my_headers_t hdr,
                      inout my_metadata_t meta, 
                      inout standard_metadata_t standard_metadata) {
    @name(".my_meter") meter(32w16384, MeterType.packets) my_meter_dl;
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name("._nop") action _nop() {
    }
    @name(".m_action_dl") action m_action(bit<32> meter_idx) {
        my_meter_dl.execute_meter((bit<32>)meter_idx, meta.meter_tag);
        standard_metadata.egress_spec = 9w2;
    }
    @name(".m_filter_dl") table m_filter_dl {
        actions = {_drop; _nop; }
        key = { meta.meter_tag: exact;}
        size = 16;
    }
    @name(".m_table_dl") table m_table_dl {
        actions = {m_action; _nop; }
        key = { hdr.ethernet.srcAddr: exact;}
        size = 16384;
    }
    apply {
        m_table_dl.apply();
        m_filter_dl.apply();
    }
}





@name("mac_learn_digest") struct mac_learn_digest {
    bit<8> in_port;    /* 9 bits?, it doesnt compile with other value like 16, why? */
    bit<48> mac_sa;
}


/***************************** process mac learn  *****************************/
control process_mac_learning(inout my_headers_t hdr, 
                             inout my_metadata_t meta, 
                             inout standard_metadata_t standard_metadata) {
    @name(".nop") action nop() {
    }
    @name(".generate_learn_notify") action generate_learn_notify() {
        digest<mac_learn_digest>(32w1024, {meta.if_index, hdr.ethernet.srcAddr });
    }
    @name(".smac") table smac {
        actions = {
            nop;
            generate_learn_notify;
        }
        key = {
            /*standard_metadata.ingress_port: exact;*/
            hdr.ethernet.srcAddr: exact;
            /*hdr.ethernet.isValid()                : exact;*/
        }
        size = 512;
    }
    apply {
         smac.apply();
        
    }
}



/***************************** tunnel control decap *****************************/
control tunnel_decap(inout my_headers_t hdr, 
                     inout my_metadata_t meta, 
                     inout standard_metadata_t standard_metadata) {

   @name("decap_gre_inner_ipv4") action decap_gre_inner_ipv4() {
           hdr.ipv4 = hdr.inner_ipv4;
           hdr.inner_ipv4.setInvalid();
           hdr.ethernet.etherType = 16w0x800;
           hdr.gre.setInvalid();
               hdr.ipv4.protocol = 8w0x6;
               hdr.tcp.setValid();
               hdr.tcp.srcPort = meta.lkp_inner_l4_sport;
               hdr.tcp.dstPort = meta.lkp_inner_l4_dport;
           meta.dst_ipv4 = hdr.ipv4.dstAddr;
   }
   @name("decap_tcp_inner") action decap_tcp_inner() {
               hdr.ipv4.protocol = 8w0x6;
               hdr.tcp.setValid();
               hdr.tcp.srcPort = meta.lkp_inner_l4_sport;
               hdr.tcp.dstPort = meta.lkp_inner_l4_dport;
   }
   @name("tunnel_decap_process_outer") table tunnel_decap_process_outer {
        actions = {
            decap_gre_inner_ipv4;
            decap_tcp_inner;
            /*@default_only NoAction;*/
        }
        key = {
            meta.ingress_tunnel_type    : exact; 
            hdr.ipv4.isValid()          : exact;
        }
        const entries = {
           (1, true) : decap_gre_inner_ipv4();
           /*(1, true) : decap_tcp_inner(); */
        }
        size = 1024;
        default_action = decap_gre_inner_ipv4();
    } 
    apply {
          tunnel_decap_process_outer.apply();

           if(meta.tcp_inner_en == 1){
             
           }

    }

}

/***************************** tunnel control encap *****************************/
control process_tunnel_encap(inout my_headers_t hdr,
                             inout my_metadata_t meta,
                             inout standard_metadata_t standard_metadata) {
  @name(".nop") action nop() {
  }

  @name(".f_insert_inner_ipv4_header") action f_insert_inner_ipv4_header(bit<8> proto) {
      hdr.inner_ipv4.setValid();
      hdr.inner_ipv4.protocol = proto;
      hdr.inner_ipv4.ttl = 8w64;
      hdr.inner_ipv4.version = 4w0x4;
      hdr.inner_ipv4.ihl = 4w0x5;
      hdr.inner_ipv4.identification = 16w0;
      hdr.inner_tcp.setValid(); 
      hdr.inner_tcp.srcPort = hdr.tcp.srcPort; 
      hdr.inner_tcp.dstPort = hdr.tcp.dstPort; 
  }

  @name(".ipv4_gre_rewrite") action ipv4_gre_rewrite(bit<32> gre_srcAddr, bit<32> gre_dstAddr) {
           

      hdr.ethernet.etherType = 16w0x800;
      /*hdr.gre.proto = hdr.ethernet.etherType; */
      /*f_insert_inner_ipv4_header(8w02);*/
            

      hdr.inner_tcp.setValid(); 
      hdr.inner_tcp = hdr.tcp;
      hdr.tcp.setInvalid(); 

      meta.dst_ipv4 = hdr.ipv4.dstAddr; 
      meta.src_ipv4 = hdr.ipv4.srcAddr;

      hdr.inner_ipv4.setValid();
      hdr.inner_ipv4 = hdr.ipv4;
      hdr.ipv4.setInvalid();
      
 
      hdr.ipv4.setValid();
      hdr.ipv4.protocol = 8w47;
      hdr.ipv4.ttl = 8w64;
      hdr.ipv4.version = 4w0x4;
      hdr.ipv4.ihl = 4w0x5;
      hdr.ipv4.identification = 16w0;
      hdr.ipv4.srcAddr = gre_srcAddr;
      hdr.ipv4.dstAddr = gre_dstAddr;

      hdr.gre.setValid();
      hdr.gre.proto = 16w0x800;
      
      /*hdr.ipv4.totalLen = meta.egress_metadata.payload_length + 16w24;*/
 
  }

  @name(".tunnel_encap_process_outer") table tunnel_encap_process_outer {
      actions = {
          nop;
          ipv4_gre_rewrite;
      }
      key = {  hdr.ipv4.dstAddr       : exact; }
      size = 1024;
      /*const entries = {
             ( true) : send_arp_reply();
      default_action = ipv4_gre_rewrite(0 0); */
  }
  apply {
     tunnel_encap_process_outer.apply();
  }

}   
 


/***************************** Nat control *****************************/
control nat_control(inout my_headers_t hdr, 
                     inout my_metadata_t meta, 
                     inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".nat_miss_int_to_ext") action nat_miss_int_to_ext() {
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata });
    }
    @name(".nat_miss_ext_to_int") action nat_miss_ext_to_int() {
        meta.do_forward = 1w0;
        mark_to_drop();
    }
    @name(".nat_hit_int_to_ext") action nat_hit_int_to_ext(bit<32> srcAddr, bit<16> srcPort) {
        meta.do_forward = 1w1;
        /*meta.src_ipv4 = srcAddr; */
        hdr.ipv4.srcAddr= srcAddr;
        /*meta.tcp_sp = srcPort;*/
        meta.dst_ipv4 = hdr.inner_ipv4.dstAddr; /* see this par*/

        hdr.tcp.srcPort = srcPort;
    }
    @name(".nat_hit_ext_to_int") action nat_hit_ext_to_int(bit<32> dstAddr, bit<16> dstPort) {
        meta.do_forward = 1w1;
        meta.dst_ipv4 = dstAddr; /* to lpm */
        hdr.ipv4.dstAddr = dstAddr;
        /*meta.src_ipv4 = hdr.ipv4.srcAddr;*/
        hdr.tcp.dstPort = dstPort;
        /*meta.tcp_dp = dstPort; */

    }
    @name(".nat_no_nat") action nat_no_nat() {
        meta.do_forward = 1w1;
    }
    @name(".nat") table nat {
        actions = {
            _drop;
            nat_miss_int_to_ext;
            nat_miss_ext_to_int;
            nat_hit_int_to_ext;
            nat_hit_ext_to_int;
            nat_no_nat;
        }
        key = {
            meta.is_ext_if     : exact;
            hdr.ipv4.isValid() : exact;
            hdr.tcp.isValid()  : exact;
            hdr.ipv4.srcAddr   : ternary;
            hdr.ipv4.dstAddr   : ternary;
            hdr.tcp.srcPort    : ternary;
            hdr.tcp.dstPort    : ternary;
        }
        size = 128;
        default_action = nat_no_nat();
    } 
    apply {
          nat.apply();
    }
}

/***************************** firewall UL control *****************************/
control firewall_up(inout my_headers_t hdr, 
                     inout my_metadata_t meta, 
                     inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop();
        exit;
    }
    @name(".fw_drop_up") table fw_drop {
        actions = {
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr   : exact;
            hdr.tcp.dstPort    : exact;
        }
        size = 128;
    }
    apply {
        fw_drop.apply();
    }
}

/***************************** firewall DW control *****************************/
control firewall_dw(inout my_headers_t hdr, 
                     inout my_metadata_t meta, 
                     inout standard_metadata_t standard_metadata) {
    @name("._drop") action _drop() {
        mark_to_drop();
        exit;
    }
    @name(".fw_drop_dw") table fw_drop_dw {
        actions = {
            _drop;
        }
        key = {
            hdr.inner_ipv4.dstAddr   : exact;
            hdr.inner_tcp.dstPort    : exact;
        }
        size = 128;
    }
    apply {
        fw_drop_dw.apply();
    }
}

/**************  I N G R E S S   P R O C E S S I N G   ******************/
control MyIngress(
    inout my_headers_t     hdr,
    inout my_metadata_t    meta,
    inout standard_metadata_t  standard_metadata)
{

    action set_if_info(bit<32> ipv4_addr, bit<48> mac_addr, bit<1> is_ext) {
        meta.if_ipv4_addr = ipv4_addr;
        meta.if_mac_addr = mac_addr;
        meta.is_ext_if = is_ext;
    }

    action drop() {
        mark_to_drop();
        exit;
    }
    @name(".set_dmac") action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    @name(".set_nhop") action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    
    @name(".ipv4_lpm") table ipv4_lpm {
        key     = { meta.dst_ipv4 : lpm; }
        actions = { set_nhop; drop;  }
        /*default_action = drop(); */
    }
    @name(".if_info") table if_info {
        key = { meta.if_index: exact;}
        actions = {
            drop;
            set_if_info;
        }
    }
    @name(".ipv4_forward") table ipv4_forward {
        key = { meta.nhop_ipv4         : exact; }
        actions = {set_dmac; drop; }
        /*const default_action = drop();*/
    }
    
    @name("process_meter") process_meter() process_meter_ul;
    @name("proc_meter_dl") proc_meter_dl() process_meter_dl;
    @name("process_mac_learning") process_mac_learning() process_mac_learning_0;
    @name("process_nat_control") nat_control() process_nat_control_0;
    @name("process_tunnel_decap") tunnel_decap() process_tunnel_decap_0;
    @name("process_tunnel_encap") process_tunnel_encap() process_tunnel_encap_0;
    @name("process_firewall_up") firewall_up() process_firewall_up_0;
    @name("proc_firewall_dw") firewall_dw() proc_firewall_dw_0;
    apply {
        if_info.apply();
        process_mac_learning_0.apply(hdr, meta, standard_metadata); 
        if(hdr.ipv4.protocol== 8w47){
             process_tunnel_decap_0.apply(hdr, meta, standard_metadata);
             process_meter_ul.apply(hdr, meta, standard_metadata); 
             process_firewall_up_0.apply(hdr, meta, standard_metadata);
        }
        process_nat_control_0.apply(hdr, meta, standard_metadata);
        if(meta.is_ext_if == 1){
           process_meter_dl.apply(hdr, meta, standard_metadata);
           process_tunnel_encap_0.apply(hdr, meta, standard_metadata);
           proc_firewall_dw_0.apply(hdr, meta, standard_metadata); 
        }
         
        if (meta.do_forward == 1w1 && hdr.ipv4.ttl > 8w0) {
           meta.my_mac = 0x000102030405;
           ipv4_lpm.apply();
           ipv4_forward.apply();
        } 

    }
}


/****************  E G R E S S   P R O C E S S I N G   *******************/
control MyEgress(
    inout my_headers_t        hdr,
    inout my_metadata_t       meta,
    inout standard_metadata_t  standard_metadata) {
    @name(".do_rewrites") action do_rewrites(bit<48> smac) {
        hdr.cpu_header.setInvalid();
        hdr.ethernet.srcAddr = smac;
        /*hdr.ipv4.srcAddr = meta.src_ipv4;
        hdr.ipv4.dstAddr = meta.dst_ipv4;
        hdr.tcp.srcPort = meta.tcp_sp;
        hdr.tcp.dstPort = meta.tcp_dp;*/
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".do_cpu_encap") action do_cpu_encap() {
        clone3(CloneType.I2E, (bit<32>)32w250, { standard_metadata });
        hdr.cpu_header.setValid();
        hdr.cpu_header.preamble = 64w0;
        hdr.cpu_header.device = 8w0;
        hdr.cpu_header.reason = 8w0xab;
        hdr.cpu_header.if_index = meta.if_index;
    }
    @name(".send_frame") table send_frame {
        actions = {
            do_rewrites;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    @name(".send_to_cpu") table send_to_cpu {
        actions = {
            do_cpu_encap;
        }
    }
    apply {
       if (standard_metadata.instance_type == 32w0) {
         /*   process_nat_control_0.apply(hdr, meta, standard_metadata); */
         send_frame.apply();
       }
       else{
         send_to_cpu.apply();
       } 
  
    }
}

/*************   C H E C K S U M    C O M P U T A T I O N   **************/
control MyComputeChecksum(
    inout my_headers_t  hdr,
    inout my_metadata_t meta)
    {
      apply {}
    }
/***********************  D E P A R S E R  *******************************/
control MyDeparser(
    packet_out      packet,
    in my_headers_t hdr)
    
{
    apply {
        packet.emit(hdr.cpu_header);
        packet.emit(hdr.ethernet);
        /* ARP Case */
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        /* IPv4 case */
        packet.emit(hdr.ipv4);
        packet.emit(hdr.gre);
        packet.emit(hdr.tcp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
