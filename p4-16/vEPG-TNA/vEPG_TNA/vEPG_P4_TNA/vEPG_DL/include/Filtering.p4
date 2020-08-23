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


control Filter(inout header_t hdr,
        inout ingress_metadata_t meta
			) {

    /**************************** Rate Limiter *****************************************/

    DirectMeter(MeterType_t.BYTES) teid_meter;


    action drop() {
     // mark_to_drop(); 
     //	hdr.ethernet.setInvalid();
    }

    action set_color() {
        // Execute the meter 
        meta.gtp_metadata.color = teid_meter.execute();
    }

    table teid_rate_limiter {
        key = {
            meta.gtp_metadata.teid : exact;
        }

        actions = {
            set_color;
        }

        size = TEID_RATE_LIMITER_TABLE_SIZE;
    }


    table m_filter {
    key = {
        meta.gtp_metadata.color : exact;
    }
    actions = { drop; NoAction; }   
    size = M_FILTER_TABLE_SIZE;
    const default_action = drop;
    const entries = { ( 0 ) : NoAction();} /* GREEN */
    }


     apply {
    
        teid_rate_limiter.apply();
        m_filter.apply();
    }

}


