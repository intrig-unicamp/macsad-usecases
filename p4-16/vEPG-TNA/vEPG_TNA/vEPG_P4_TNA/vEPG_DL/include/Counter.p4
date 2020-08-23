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
#include "standard_headers.p4"
#include "size.p4"



control counter(inout header_t hdr,
        inout ingress_metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md
			) {

    /************************************* Counter ********************************************/


  //  Counter<ByteCounter_t, PortId_t>(NUM_PORTS, CounterType_t.BYTES) port_count;
 
    Counter(NUM_PORTS, CounterType_t.packets) ingress_port_count;
/*
    
    action drop() {
     // mark_to_drop(); 
     //	hdr.ethernet.setInvalid();
    }

    action nop() {
       
    }

    action tally() {
    port_count.count((bit<9>) ig_intr_md.ingress_port);
    }

    table count_table {

    key = {
           ig_intr_md.ingress_port: exact ;
    }
    
    actions = {tally; nop;
              }

     size = COUNTER_TABLE_SIZE;

    }

*/
     apply {
    
     //   count_table.apply();
         ingress_port_count.count((bit<9>) ig_intr_md.ingress_port);
      
    }

}


