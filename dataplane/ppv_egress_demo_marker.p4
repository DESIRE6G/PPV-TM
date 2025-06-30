#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#define BIN_T bit<32>
#define PV_T bit<16>
#define HIST_SIZE 2048 // 2048*number of PV-enabled ports - currently 1 ports stored on 3 bits


// 5TONIC settings
#define PORT_2_0 140
// Changed from 141 to 156 as the AP moved to Port4
#define PORT_2_1 156   
#define PORT_2_2 142
#define PORT_5 164
#define PORT_6 172


// HEADERS AND TYPES ************************************************************

header ethernet_t {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header vlan_t {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> etherType;
}


header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<4>  diffserv;
    bit<1>  policy;
    bit<1>  l4s;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<1> _reserved;
    bit<1> dont_fragment;
    bit<1> more_fragments;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<9>  eport;
    bit<23> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

header bridge_t {
    bit<48> ingress_global_tstamp;
    bit<16> rate_cut;
//    bit<32> ts;
}

struct ingress_metadata_t {
    PV_T pv;
    PV_T pv_tmp;
    PV_T pv_ctv;
    bool pv_udp;
    bit<16> pv_ps;
    bit<32> pv_vql4s;
    bit<32> pv_vqcl;
    bit<48> pv_ts;
    bit<32> pv_trunc_ts;
    bit<32> pv_drop;
    bit<16> ueid;
}

struct egress_metadata_t {
    bridge_t bridge;
    PV_T pv;
    PV_T pv_tmp;
    PV_T pv_hist_idx;
    PV_T pv_ctv;
    bit<32> latency;
}

struct ppv_digest_t {
	bit<32> vql4s;
	bit<32> vqcl;
	bit<48> ts;
        bit<32> drop;
}

struct header_t {
    bridge_t bridge;
    ethernet_t ethernet;
    vlan_t vlan;
    ipv4_t ipv4;
    tcp_t tcp;
}


// INGRESS ************************************************************

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


parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ingress_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {


    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x8100: parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
       pkt.extract(hdr.vlan);
       transition select(hdr.vlan.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
	ig_md.pv = hdr.ipv4.identification;
	ig_md.pv_ps = hdr.ipv4.totalLen;
        transition select(hdr.ipv4.protocol) {
		17 : parse_udp;
		6 : parse_tcp;
		default : parse_else; // TODO handling ICMP
	}
    }

    state parse_udp {
        pkt.extract(hdr.tcp);
        ig_md.pv_udp = true;
        transition select(hdr.tcp.dstPort) {
                 8472: parse_vxlan;
                 default: parse_othudp;
        }
    }
    
    state parse_vxlan {
       ig_md.ueid = 8472;
       transition accept;
    }

    state parse_othudp {
       ig_md.ueid = hdr.tcp.srcPort;
       transition accept;
    }

    state parse_tcp {
	pkt.extract(hdr.tcp);
        ig_md.pv_udp = false;
        ig_md.ueid = hdr.tcp.srcPort;
        transition accept;
    }

    state parse_else {
	ig_md.pv_udp = false;
        transition accept;
    }

}

#include "p4marker.p4"

control SwitchIngress(
        inout header_t hdr,
        inout ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

   
    Counter<bit<64>, PV_T>(HIST_SIZE, CounterType_t.BYTES) pvhist; 
    PV_T pv_hist_idx;

    Counter<bit<64>, bit<1>>(2, CounterType_t.BYTES) cnt_in;
    Counter<bit<64>, bit<1>>(2, CounterType_t.BYTES) cnt_drop;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) cpkt_in;


    Register<bit<32>, PV_T>(1) pv_drop;
    RegisterAction<bit<32>,PV_T,bit<32>>(pv_drop) pv_do_drop = {
        void apply(inout bit<32> data,out bit<32> new_value){
           data = data + (bit<32>)ig_md.pv_ps;;
	   new_value = data;
        }
    };

    RegisterAction<bit<32>,PV_T,bit<32>>(pv_drop) pv_get_drop = {
        void apply(inout bit<32> data,out bit<32> new_value){
           new_value = data;
        }
    };

    Register<bit<32>, bit<1>>(1) pv_last_trts;
    RegisterAction<bit<32>,bit<1>,bit<32>>(pv_last_trts) pv_update_trts = {
	void apply(inout bit<32> data, out bit<32> result){
		result = data - ig_md.pv_trunc_ts;
		data = ig_md.pv_trunc_ts;
	}
    };

    Register<bit<32>, PV_T>(1) pv_vq_l4s;
    RegisterAction<bit<32>,PV_T,bit<32>>(pv_vq_l4s) pv_inc_vq_l4s = {
        void apply(inout bit<32> data,out bit<32> new_value){
           data = data+(bit<32>)ig_md.pv_ps;
	   new_value = data;
        }
    };

    RegisterAction<bit<32>,PV_T,bit<32>>(pv_vq_l4s) pv_get_vq_l4s = {
        void apply(inout bit<32> data,out bit<32> new_value){
           new_value = data;
        }
    };

    Register<bit<32>, PV_T>(1) pv_vq_cl;
    RegisterAction<bit<32>,PV_T,bit<32>>(pv_vq_cl) pv_inc_vq_cl = {
        void apply(inout bit<32> data,out bit<32> new_value){
           data = data+(bit<32>)ig_md.pv_ps;
	   new_value = data;
        }
    };
    RegisterAction<bit<32>,PV_T,bit<32>>(pv_vq_cl) pv_get_vq_cl = {
        void apply(inout bit<32> data,out bit<32> new_value){
           new_value = data;
        }
    };

    action set_ppv_port_l4s(PV_T ctv, bit<5> qid) {
	ig_md.pv_ctv = ctv;
	ig_tm_md.qid = qid;
//        pv_hist_idx = ig_md.pv;
//        ig_md.pv_vql4s = pv_inc_vq_l4s.execute(0);
//      ig_md.pv_vqcl = pv_get_vq_cl.execute(0);
    }

    action set_ppv_port_cl(PV_T ctv, bit<5> qid) {
	ig_md.pv_ctv = ctv;
	ig_tm_md.qid = qid;
//        pv_hist_idx = 1024 | ig_md.pv;
//      ig_md.pv_vqcl = pv_inc_vq_cl.execute(0);
//        ig_md.pv_vql4s = pv_get_vq_l4s.execute(0);
    }



    table ig_ppv {
      key = {hdr.ipv4.isValid() : exact; hdr.ipv4.l4s: exact; ig_tm_md.ucast_egress_port : exact;}
      actions = {set_ppv_port_l4s;set_ppv_port_cl;NoAction;}
      default_action = NoAction();
      size = 8;
    }

    action drop() {
	ig_dprsr_md.drop_ctl = ig_dprsr_md.drop_ctl | 0b001;
	cnt_drop.count(hdr.ipv4.l4s);
        ig_md.pv_drop = pv_do_drop.execute(0);
        exit;
    }

    action get_drop() {
        ig_md.pv_drop = pv_get_drop.execute(0);
    }

    table ig_ppv_do_drop {
      key = {ig_md.pv_tmp : ternary; hdr.ipv4.l4s : exact; ig_md.pv_udp : exact;}
      actions = {drop; get_drop;}
      const default_action = get_drop();
      size = 3;
      const entries = {
	(0b1000000000000000 &&& 0b1000000000000000, 0b0, false) : drop(); // non-ECT
        (0b1000000000000000 &&& 0b1000000000000000, 0b0, true)  : drop(); // non-ECT UDP
        (0b1000000000000000 &&& 0b1000000000000000, 0b1, true)  : drop(); // UDP
      }
    }


    action set_direct(PortId_t port) {
    	ig_tm_md.ucast_egress_port = port;   
    }

    action set_eport(PortId_t port, PortId_t ppv_port) {
        ig_tm_md.ucast_egress_port = ppv_port;
        hdr.ipv4.eport = port;
    }

    action get_eport() {
        ig_tm_md.ucast_egress_port = hdr.ipv4.eport;
        hdr.ipv4.eport = 10 << 1;
    }

    table testbed_switching {
      key = {ig_intr_md.ingress_port : exact; hdr.ethernet.dstAddr : exact;}
      actions = {set_direct;}
      const default_action = set_direct( PORT_2_1 ); // EDGEServer1 -> wifi AP
      size = 6;
      const entries = {
         (PORT_2_1, 48w0x40a6b7c178c5) : set_direct( PORT_5 ); // wifi AP -> EDGEServer1
         (PORT_2_0, 48w0x40a6b7c178c5) : set_direct( PORT_5 ); // TRG -> EDGEServer1
         (PORT_6, 48w0x40a6b7c178c5) : set_direct( PORT_2_2 ); // wifi AP -> EDGEServer1
         (PORT_2_2, 48w0x569df06aa2e2) : set_direct( PORT_2_0 ); // EDGEServer1 -> TRG
         (PORT_2_0, 48w0xffffffffffff) : set_direct( PORT_2_2 ); // TRG -> EDGEServer1
         (PORT_2_1, 48w0xffffffffffff) : set_direct( PORT_2_2 ); // TRG -> EDGEServer1         
      }
    }



    bit<32> tmp;

    P4Marker() p4m;

    apply {
        testbed_switching.apply();

	ig_md.pv_ps = ig_md.pv_ps + 20; // ethernet frame + interframe gap etc.

	if (ig_ppv.apply().hit) {
                hdr.bridge.rate_cut=0;
                if (hdr.ipv4._reserved==0) {
			p4m.apply(hdr, ig_md, ig_dprsr_md);
			hdr.ipv4._reserved = 1;
		}
                if (hdr.ipv4.l4s == 0) {
                    pv_hist_idx = 1024 | ig_md.pv;
		} else {
                    pv_hist_idx = ig_md.pv;	
		}
                pvhist.count(pv_hist_idx);
                hdr.ipv4.identification = ig_md.pv;
		cnt_in.count(hdr.ipv4.l4s);

		ig_md.pv_tmp = ig_md.pv - ig_md.pv_ctv;
		ig_ppv_do_drop.apply(); // exit if drops


		/* PPV-enabled egress port */
		if (hdr.ipv4.l4s==0b0) {
			ig_md.pv_vqcl = pv_inc_vq_cl.execute(0);
		}
		else {
			ig_md.pv_vqcl = pv_get_vq_cl.execute(0);
		}

		if (hdr.ipv4.l4s==0b1)
		{
			ig_md.pv_vql4s = pv_inc_vq_l4s.execute(0);
		}
		else 
		{
			ig_md.pv_vql4s = pv_get_vq_l4s.execute(0);
		}

		/* Check update period and set digest generation */
		ig_md.pv_trunc_ts = (bit<32>)(ig_prsr_md.global_tstamp >> 23);
		tmp = pv_update_trts.execute(0);
	
		if (tmp!=0) {
			ig_dprsr_md.digest_type = 1;
			ig_md.pv_ts = ig_prsr_md.global_tstamp;
			//hdr.bridge.ts = (bit<32>)(ig_prsr_md.global_tstamp >> 23);
		}
		cpkt_in.count(0);
	}

        hdr.bridge.ingress_global_tstamp = ig_prsr_md.global_tstamp;
        hdr.bridge.setValid();
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ingress_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Digest<ppv_digest_t>() ppv_digest;
    Checksum() ipv4_checksum;

    apply {

	if (ig_dprsr_md.digest_type == 1) {
		ppv_digest.pack({ig_md.pv_vql4s, ig_md.pv_vqcl, ig_md.pv_ts, ig_md.pv_drop});
	}

        hdr.ipv4.hdrChecksum = ipv4_checksum.update({
                        hdr.ipv4.version,
                        hdr.ipv4.ihl,
                        hdr.ipv4.diffserv,
			hdr.ipv4.policy,
                        hdr.ipv4.l4s,
                        hdr.ipv4.ecn,
                        hdr.ipv4.totalLen,
                        hdr.ipv4.identification,
                        hdr.ipv4._reserved,
                        hdr.ipv4.dont_fragment,
                        hdr.ipv4.more_fragments,
                        hdr.ipv4.fragOffset,
                        hdr.ipv4.ttl,
                        hdr.ipv4.protocol,
                        hdr.ipv4.eport,
                        hdr.ipv4.srcAddr,
                        hdr.ipv4.dstAddr
                });

	pkt.emit(hdr.bridge);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
	pkt.emit(hdr.ipv4);
 	pkt.emit(hdr.tcp);	
    }
}

// EGRESS ************************************************************

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        pkt.extract(eg_md.bridge);
        transition parse_ethernet; //parse_bridge;
    }

    state parse_bridge {
        pkt.extract(hdr.bridge);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x8100: parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
       pkt.extract(hdr.vlan);
       transition select(hdr.vlan.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        eg_md.pv = hdr.ipv4.identification;
        //eg_md.pv_ps = hdr.ipv4.totalLen;
        transition accept;
    }

}

control SwitchEgress(
        inout header_t hdr,
        inout egress_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    Counter<bit<64>, PV_T>(HIST_SIZE, CounterType_t.BYTES) pvhist;
    Counter<bit<64>, bit<1>>(1, CounterType_t.BYTES) cnt_ecn;
    Counter<bit<64>, bit<1>>(2, CounterType_t.BYTES) cnt_out;
    Counter<bit<64>, bit<1>>(1, CounterType_t.PACKETS) cpkt_out;

    bit<32> queue_delay_for_storing;

    Register<bit<16>, bit>(2, 0) delay_reg;
    RegisterAction<bit<16>, bit, bit<16>>(delay_reg) set_delay_action = {
        void apply(inout bit<16> reg_data, out bit<16>  result) {
            reg_data = (bit<16>) queue_delay_for_storing[25:10];
            result = reg_data;
        }
    };

    Register<bit<32>, bit<1>>(2) reg_latency;
    RegisterAction<bit<32>,bit<1>,bit<32>>(reg_latency) update_latency = {
        void apply(inout bit<32> data){
                data = (bit<32>)(eg_intr_md.enq_qdepth);
        }
    };

    action set_l4s(PV_T ctv_l4s, PV_T offset) {
        eg_md.pv_ctv = ctv_l4s;
        eg_md.pv_hist_idx = offset | eg_md.pv;
    }
 
    action set_cl(PV_T offset) { // offset & 1024 != 0
	eg_md.pv_ctv = 0;
	eg_md.pv_hist_idx = offset | eg_md.pv;
    }

    table eg_ppv_filter {
      key = {hdr.ipv4.isValid() : exact;hdr.ipv4.l4s: exact; eg_intr_md.egress_port : exact;}
      actions = {set_l4s;set_cl;NoAction;}
      default_action = NoAction();
      size = 16;
    }

    action ecnmark() {
        hdr.ipv4.ecn = 0b11;
	cnt_ecn.count(0);
    }

    table eg_ppv_do_ecnmark {
      key = {eg_md.pv_tmp : ternary; hdr.ipv4.ecn : exact;}
      actions = {ecnmark; NoAction;}
      const default_action = NoAction();
      size = 2;
      const entries = {
        (0b1000000000000000 &&& 0b1000000000000000, 0b01) : ecnmark();
        (0b1000000000000000 &&& 0b1000000000000000, 0b10) : ecnmark();
      }
    }

    bit<32> tmp;

//    action calc_latency() {
//	eg_md.latency = eg_md.latency - hdr.bridge.ts;
//    }

    apply {
	queue_delay_for_storing = (bit<32>)(eg_intr_from_prsr.global_tstamp - eg_md.bridge.ingress_global_tstamp);
	eg_md.latency = (bit<32>)(eg_intr_from_prsr.global_tstamp >> 23);
        if (eg_ppv_filter.apply().hit) {
                set_delay_action.execute(hdr.ipv4.l4s);
                cnt_out.count(hdr.ipv4.l4s);
		/* Update pv histogram */
		pvhist.count(eg_md.pv_hist_idx); // PV Histogram is also computed here, but we only use the ingress hist in the CP
		/* Check ctv limit and mark with ECN CE */
		eg_md.pv_tmp = eg_md.pv - eg_md.pv_ctv;
                eg_ppv_do_ecnmark.apply();

		update_latency.execute(hdr.ipv4.l4s);
	//	hdr.ipv4.identification = eg_md.bridge.rate_cut;
		cpkt_out.count(0);
        }
//        hdr.ipv4.identification = eg_md.bridge.rate_cut;
	//hdr.bridge.setInvalid();
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

	Checksum() ipv4_checksum;


	apply {
		hdr.ipv4.hdrChecksum = ipv4_checksum.update({
			hdr.ipv4.version,
			hdr.ipv4.ihl,
			hdr.ipv4.diffserv,
			hdr.ipv4.policy,
			hdr.ipv4.l4s,
			hdr.ipv4.ecn,
			hdr.ipv4.totalLen,
			hdr.ipv4.identification,
			hdr.ipv4._reserved,
			hdr.ipv4.dont_fragment,
			hdr.ipv4.more_fragments,
			hdr.ipv4.fragOffset,
			hdr.ipv4.ttl,
			hdr.ipv4.protocol,
			hdr.ipv4.eport,
			hdr.ipv4.srcAddr,
			hdr.ipv4.dstAddr
		});

		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.vlan);
		pkt.emit(hdr.ipv4);
	}
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
