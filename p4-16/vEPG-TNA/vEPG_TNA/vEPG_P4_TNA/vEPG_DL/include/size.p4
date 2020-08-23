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

#define COUNTER_TABLE_SIZE 1000
#define TEID_RATE_LIMITER_TABLE_SIZE 10000
#define M_FILTER_TABLE_SIZE 1000
#define IPV4_FORWARD_TABLE_SIZE 1000
#define IPV4_LPM_TABLE_SIZE 1000
#define vEPG_UL_TABLE_SIZE 1000
#define FIREWALL_UL_TABLE_SIZE 200000
#define vEPG_DL_TABLE_SIZE 200000
#define FIREWALL_DL_TABLE_SIZE 200000
#define SMAC_TABLE_SIZE 1024

