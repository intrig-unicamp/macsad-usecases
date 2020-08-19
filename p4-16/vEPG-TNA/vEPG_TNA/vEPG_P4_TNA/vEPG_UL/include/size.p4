#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define COUNTER_TABLE_SIZE 1000
#define TEID_RATE_LIMITER_TABLE_SIZE 10000
#define M_FILTER_TABLE_SIZE 1000
#define IPV4_FORWARD_TABLE_SIZE 1000
#define IPV4_LPM_TABLE_SIZE 1000
#define vEPG_UL_TABLE_SIZE 1000
#define FIREWALL_UL_TABLE_SIZE 1000
#define vEPG_DL_TABLE_SIZE 1024
#define FIREWALL_DL_TABLE_SIZE 1024
#define SMAC_TABLE_SIZE 1024

