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
//#include "constants.p4"


control packetio_ingress(inout header_t hdr,
        in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_tm_md		
           ) {

    apply {
        if (ig_intr_md.ingress_port == CPU_PORT) {
            ig_tm_md.ucast_egress_port = hdr.packet_out.egress_port;
            hdr.packet_out.setInvalid();
            return;
          }
        }
     }




control packetio_egress(inout header_t hdr,
        in ingress_intrinsic_metadata_t ig_intr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
           ) {

    
       action send_to_cpu() {
       ig_tm_md.ucast_egress_port = CPU_PORT;
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire.
       hdr.packet_in.setValid();
       hdr.packet_in.ingress_port = ig_intr_md.ingress_port;
       }

      table t_l2_fwd {
        key = {
              ig_intr_md.ingress_port         : ternary;
           // hdr.ethernet.dst_addr           : ternary;
          //  hdr.ethernet.src_addr           : ternary;
           // hdr.ethernet.ether_type         : ternary;
        }
        actions = {
            send_to_cpu;
            NoAction;
        }
        default_action = NoAction();
        }

    apply {
          if (t_l2_fwd.apply().hit) {
                // Packet hit an entry in t_l2_fwd table. A forwarding action
                // has already been taken. No need to apply other tables, exit
                // this control block.
                return;
             }
          }
     }

