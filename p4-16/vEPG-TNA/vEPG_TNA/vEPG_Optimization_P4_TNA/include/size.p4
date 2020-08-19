#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define smac_tbl_size 10
#define dmac_tbl_size 10
#define dl_sess_lookup_tbl_size 1100000
#define gtp_encap_tbl_size 65536
#define firewall_dl_tbl_size 1000
#define gtp_decap_tbl_size 10
#define firewall_ul_tbl_size 1000
#define ipv4_lpm_tbl_size 10
