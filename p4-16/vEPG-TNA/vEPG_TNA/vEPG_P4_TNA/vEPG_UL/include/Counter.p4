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


