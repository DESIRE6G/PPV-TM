/****
 * Author: Sandor Laki (ELTE CNL, Budapest, Hungary - lakis@inf.elte.hu)
 * Compilation: 
 * g++ -std=c++11 -I/p4sde/bf-sde-9.1.0/install/include/ -I m4 -Wl,--no-as-needed -L /p4sde/bf-sde-9.1.0/install/lib/ -lbfutils -lbfsys -ldriver -lbf_switchd_lib -lpiall -lpifeproto -lboost_system -lboost_thread ppv_egress_demo_marker.cpp -o ppv_egress_demo_marker
 *
*****/

#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_learn.hpp>
#include <bf_rt/bf_rt_table_key.hpp>
#include <bf_rt/bf_rt_table_data.hpp>
#include <bf_rt/bf_rt_table.hpp>
#include <bf_rt/bf_rt_table_operations.hpp>
//#include <bf_rt/bf_rt_p4/bf_rt_p4_table_data_impl.hpp>
#include <getopt.h>
//#include <boost/thread/thread.hpp>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <mutex>
#include <limits>
#include <stdio.h>
#include <vector>
#include <iostream>
#include <fstream>

#include <dvm/bf_drv_intf.h>
#include <csignal>

extern "C" {
#include <tofino/pdfixed/pd_common.h>
#include <tofino/pdfixed/pd_tm.h>
#include <traffic_mgr/tm_intf.h>
#include <tofino/bf_pal/bf_pal_types.h>
#include <bf_pm/bf_pm_intf.h>
#include <bf_types/bf_types.h> 
}


#define EWMA_ALPHA 0.01
#define SWITCH_STATUS_FAILURE 0x00000001L
#define POLICY_FILE "/home/netcom/ppv/policy.conf"

#ifdef __cplusplus
extern "C" {
#endif
#include <bf_switchd/bf_switchd.h>
#ifdef __cplusplus
}
#endif

// ./run_bfshell.sh --no-status-srv -f ~/list_ports | grep ENB | cut -d'|' -f1,3 | sed 's/\/.*|/ /' | awk '{printf("#define PORT_%d %d\n", $1,$2);}'

// 5TONIC settings
#define PORT_2_0 140
#define PORT_2_1 141
#define PORT_2_2 142
#define PORT_5 164
#define PORT_6 172


using namespace std::literals;

/***********************************************************************************
 * This sample cpp application code is based on the P4 program
 * ppvwc_single.p4
 * Please refer to the P4 program and the generated bf-rt.json for information
 *on
 * the tables contained in the P4 program, and the associated key and data
 *fields.
 **********************************************************************************/

namespace bfrt {
namespace elte {
namespace ppv_egress_demo_marker {

// Structure definition to represent the key of the ig_ppv table
struct IgPpvKey {
  bool ipv4_valid;
  bool ipv4_l4s;
  uint16_t egress_port;
};

// Structure definition to represent the data of the ig_ppv table for action
// "set_ppv_port_conf"
struct IgPpvSPPCData {
  uint16_t ctv;
  uint8_t qid;
};

struct IgPpvSPPLData {
  uint16_t ctv;
  uint8_t qid;
};


// Structure definition to represent the key of the eg_ppv_filter table
struct EgPpvFilterKey {
  bool ipv4_valid;
  bool ipv4_l4s;
  uint16_t egress_port;
};

// Structure definition to represent the data of the ig_ppv table for action
// "set_ppv_port_conf"

struct EgPpvFilterSCData {
  uint16_t offset;
};

struct EgPpvFilterSLData {
  uint16_t ctv_l4s;
  uint16_t offset;
};

// Structure definition to represent the key of the port_fwd table
struct PortFwdKey {
  uint16_t ingress_port;
  bool ipv4_valid;
};

// Structure definition to represent the data of the port_fwd table for action
// "set_direct"
struct PortFwdSetDirectData {
  uint16_t port;
};

// "set_eport"
struct PortFwdEportData {
  uint16_t port;
  uint16_t ppv_port;
};

//struct NoActionData {
//};

// Structure definition tp represent the data of the ig_ppv table
struct IgPpvData {
  union {
    IgPpvSPPCData c;
    IgPpvSPPLData l;
  } data;
  // Based on the action_id, contents of the enum are interpreted
  bf_rt_id_t action_id;
};

// Structure definition tp represent the data of the eg_ppv_filter table
struct IgPpvFilterData {
  union {
    EgPpvFilterSCData c;
    EgPpvFilterSLData l;
  } data;
  // Based on the action_id, contents of the enum are interpreted
  bf_rt_id_t action_id;
};

// Structure definition to represent the data of the port_fwd table
//struct PortFwdData {
//  union {
//    PortFwdSetDirectData d;
//    PortFwdEportData e;
//  } data;
//  // Based on the action_id, contents of the enum are interpreted
//  bf_rt_id_t action_id;
//};

struct P4MarkerFIKey {
   uint16_t tcp_srcport;
};

struct P4MarkerFIHFData {
  uint16_t pflowid;
  uint8_t pol;
};

struct P4MarkerTVFKey {
  uint8_t policyid;
  uint16_t rndidx; // 10 bits
};

struct P4MarkerTVFSPData {
  uint16_t ppv;
};



namespace {
// Key field ids, table data field ids, action ids, Table object required for
// interacting with the table
const bfrt::BfRtInfo *bfrtInfo = nullptr;
const bfrt::BfRtLearn *learn_obj = nullptr;
const bfrt::BfRtTable *igPpvTable = nullptr;
const bfrt::BfRtTable *egPpvFilterTable = nullptr;
//const bfrt::BfRtTable *portFwdTable = nullptr;
const bfrt::BfRtTable *pvhistTable = nullptr;
const bfrt::BfRtTable *cntecnTable = nullptr;
const bfrt::BfRtTable *reglatencyTable = nullptr;
const bfrt::BfRtTable *reglatency2Table = nullptr;
const bfrt::BfRtTable *P4MarkerFITable = nullptr;
const bfrt::BfRtTable *P4MarkerTVFTable = nullptr;
const bfrt::BfRtTable *P4MarkerLRTable = nullptr;
const bfrt::BfRtTable *sel_rateTable = nullptr;



const bfrt::BfRtTable *cntinTable = nullptr;
const bfrt::BfRtTable *cntdropTable = nullptr;
const bfrt::BfRtTable *cntoutTable = nullptr;

const bfrt::BfRtTable *pktinTable = nullptr;
const bfrt::BfRtTable *pktoutTable = nullptr;

std::shared_ptr<bfrt::BfRtSession> session;

std::unique_ptr<bfrt::BfRtTableKey> igppvbfrtTableKey;
std::unique_ptr<bfrt::BfRtTableData> igppvbfrtTableDataSPPC;
std::unique_ptr<bfrt::BfRtTableData> igppvbfrtTableDataSPPL;

std::unique_ptr<bfrt::BfRtTableKey> egppvbfrtTableKey;
std::unique_ptr<bfrt::BfRtTableData> egppvbfrtTableDataSC;
std::unique_ptr<bfrt::BfRtTableData> egppvbfrtTableDataSL;

std::unique_ptr<bfrt::BfRtTableKey> portfwdTableKey;
std::unique_ptr<bfrt::BfRtTableData> portfwdTableDataDirect;
std::unique_ptr<bfrt::BfRtTableData> portfwdTableDataEport;
std::unique_ptr<bfrt::BfRtTableData> portfwdTableDataGetEport;

std::unique_ptr<bfrt::BfRtTableKey> P4MarkerFIbfrtTableKey;
std::unique_ptr<bfrt::BfRtTableData> P4MarkerFIbfrtTableData;
std::unique_ptr<bfrt::BfRtTableKey> P4MarkerTVFbfrtTableKey;
std::unique_ptr<bfrt::BfRtTableData> P4MarkerTVFbfrtTableData;
std::unique_ptr<bfrt::BfRtTableKey> P4MarkerLRbfrtTableKey;
std::unique_ptr<bfrt::BfRtTableData> P4MarkerLRbfrtTableData;


// Key field ids
bf_rt_id_t igPpv_ipv4_valid_field_id = 0;
bf_rt_id_t igPpv_ipv4_l4s_field_id = 0;
bf_rt_id_t igPpv_meta_egress_port_field_id = 0;
bf_rt_id_t egPpvFilter_ipv4_valid_field_id = 0;
bf_rt_id_t egPpvFilter_ipv4_l4s_field_id = 0;
bf_rt_id_t egPpvFilter_meta_egress_port_field_id = 0;
//bf_rt_id_t portFwd_ipv4_valid_field_id = 0;
//bf_rt_id_t portFwd_ingress_port_field_id = 0;
bf_rt_id_t counter_spec_bytes_field_id = 0;
bf_rt_id_t cntin_key_field_id = 0;
bf_rt_id_t cntin_field_id = 0;
bf_rt_id_t cntout_key_field_id = 0;
bf_rt_id_t cntout_field_id = 0;
bf_rt_id_t pktin_key_field_id = 0;
bf_rt_id_t pktin_field_id = 0;
bf_rt_id_t pktout_key_field_id = 0;
bf_rt_id_t pktout_field_id = 0;
bf_rt_id_t cntdrop_key_field_id = 0;
bf_rt_id_t cntdrop_field_id = 0;
bf_rt_id_t cntecn_key_field_id = 0;
bf_rt_id_t cntecn_field_id = 0;
bf_rt_id_t reglatency_key_field_id = 0;
bf_rt_id_t reglatency_field_id = 0;
bf_rt_id_t reglatency2_key_field_id = 0;
bf_rt_id_t reglatency2_field_id = 0;
bf_rt_id_t P4MarkerFI_tcp_srcport_field_id = 0;
bf_rt_id_t P4MarkerTVF_policyid_field_id = 0;
bf_rt_id_t P4MarkerTVF_rndidx_field_id = 0;
bf_rt_id_t P4MarkerLR_lpf_index_field_id = 0;
bf_rt_id_t sel_rate_key_field_id = 0;
bf_rt_id_t sel_rate_field_id = 0;

// Action Ids
bf_rt_id_t igPpv_SPPL_action_id = 0;
bf_rt_id_t igPpv_SPPC_action_id = 0;
bf_rt_id_t egPpvFilter_SC_action_id = 0;
bf_rt_id_t egPpvFilter_SL_action_id = 0;
//bf_rt_id_t portFwd_Direct_action_id = 0;
//bf_rt_id_t portFwd_Eport_action_id = 0;
//bf_rt_id_t portFwd_Get_Eport_action_id = 0;
bf_rt_id_t P4MarkerFI_HF_action_id = 0;
bf_rt_id_t P4MarkerTVF_SP_action_id = 0;

// Data field Ids
bf_rt_id_t igPpv_SPPC_action_ctv_field_id = 0;
bf_rt_id_t igPpv_SPPC_action_qid_field_id = 0;
bf_rt_id_t igPpv_SPPL_action_ctv_field_id = 0;
bf_rt_id_t igPpv_SPPL_action_qid_field_id = 0;
bf_rt_id_t egPpvFilter_SC_action_offset_field_id = 0;
bf_rt_id_t egPpvFilter_SL_action_ctv_l4s_field_id = 0;
bf_rt_id_t egPpvFilter_SL_action_offset_field_id = 0;
//bf_rt_id_t portFwd_Direct_action_port_field_id = 0;
//bf_rt_id_t portFwd_Eport_action_port_field_id = 0;
//bf_rt_id_t portFwd_Eport_action_ppv_port_field_id = 0;
bf_rt_id_t P4MarkerFI_HF_action_pflowid_field_id = 0;
bf_rt_id_t P4MarkerFI_HF_action_pol_field_id = 0;
bf_rt_id_t P4MarkerTVF_SP_action_ppv_field_id = 0;
bf_rt_id_t P4MarkerLR_lpf_spec_type_field_id = 0;
bf_rt_id_t P4MarkerLR_lpf_spec_gain_time_constant_ns_field_id = 0;
bf_rt_id_t P4MarkerLR_lpf_spec_decay_time_constant_ns_field_id = 0;
bf_rt_id_t P4MarkerLR_lpf_spec_out_scale_down_factor_field_id = 0;

// Digest fields
bf_rt_id_t learn_vql4s_field_id = 0;
bf_rt_id_t learn_vqcl_field_id = 0;
bf_rt_id_t learn_ts_field_id = 0;
bf_rt_id_t learn_drop_field_id = 0;


// Counter
BfRtTable::keyDataPairs key_data_pairs;
std::unique_ptr<BfRtTableKey> keys[2048];
std::unique_ptr<BfRtTableData> data[2048];

// Stat counters
//BfRtTable::keyDataPairs cntin_kdp;
std::unique_ptr<BfRtTableKey> cntin_keys[2];
std::unique_ptr<BfRtTableData> cntin_data[2];


//BfRtTable::keyDataPairs cntdrop_kdp;
std::unique_ptr<BfRtTableKey> cntdrop_keys[2];
std::unique_ptr<BfRtTableData> cntdrop_data[2];

//BfRtTable::keyDataPairs cntin_kdp;
std::unique_ptr<BfRtTableKey> cntout_keys[2];
std::unique_ptr<BfRtTableData> cntout_data[2];

//BfRtTable::keyDataPairs cntecn_kdp;
std::unique_ptr<BfRtTableKey> cntecn_key;
std::unique_ptr<BfRtTableData> cntecn_data;

std::unique_ptr<BfRtTableKey> pktin_key;
std::unique_ptr<BfRtTableData> pktin_data;
std::unique_ptr<BfRtTableKey> pktout_key;
std::unique_ptr<BfRtTableData> pktout_data;


// Stat registers
std::unique_ptr<BfRtTableKey> reglatency_keys[2];
std::unique_ptr<BfRtTableData> reglatency_data[2];
std::unique_ptr<BfRtTableKey> reglatency2_keys[2];
std::unique_ptr<BfRtTableData> reglatency2_data[2];
std::unique_ptr<BfRtTableKey> sel_rate_keys;
std::unique_ptr<BfRtTableData> sel_rate_data;


// Parameters
double capacityGbps;
const float  markerTimeWindowNs = 10e6; // 10ms -> bound to P4 code!!!! DO NOT MODIFY
const double updateTimeInSec = 0.1; //0.1; //0.05; // 50ms
bool isDirectPortFwd = false;
bool isDpdkMarkerMode = false;
bool taildrop_mode = false;

//VQ helpers
double capacity;
double cv[2];
double vq_target[2];
double pq_target[2];
const double vq_srate = 0.98;

double rates[2];
uint8_t qid_l4s = 0;
uint8_t qid_cl  = 0;

bool policy_map[10];
bool load_policy_trigger;


inline void config_capacity(double cap=10)
{
  capacityGbps = cap;
  capacity = capacityGbps * 1e9/8.0;
  cv[0] = 0.95 * capacity;
  cv[1] = 0.95 * capacity;
  rates[0] = 0.0;
  rates[1] = 0.0;
  if (cap<20.1) {
    vq_target[0] = 0.01 * capacity;
    vq_target[1] = 0.01 * capacity;
    pq_target[0] = 0.01 * capacity;
    pq_target[1] = 0.01 * capacity;
    qid_l4s = 0;
    qid_cl = 0;
  } else {
    vq_target[0] = 0.0005 * capacity;
    vq_target[1] = 0.0005 * capacity;
    pq_target[0] = 0.0001 * capacity;
    pq_target[1] = 0.0001 * capacity;
    qid_cl = 0;
    qid_l4s = 0;
  }

  if (taildrop_mode) {
    qid_cl  = 0;
    qid_l4s = 0;
  }
  
}

//Globals for calculations
uint64_t pers_hist[2][1024];
uint64_t last_hist[2][1024];
uint64_t pers_incoming_bytes[2];
uint64_t lastvq[2];
uint64_t lastdrop;
uint64_t vq[2];
uint64_t pq[2];

uint64_t inst_vq[2];
uint64_t ewma_vq[2];
uint64_t ctv[4] = {0,0,0,0};
double ppr_mark = 0;
uint64_t lastts;
std::mutex pers_mtx;
std::mutex hist_mtx;

//Counters for stats
std::chrono::time_point<std::chrono::system_clock> logtime;
uint64_t log_ctv1max;
uint64_t log_ctv2max;
uint64_t log_pq1min;
uint64_t log_pq2min;
uint64_t log_pq1max;
uint64_t log_pq2max;
uint64_t log_vq1max;
uint64_t log_vq2max;
uint64_t log_ctv1min;
uint64_t log_ctv2min;
uint64_t log_vq1min;
uint64_t log_vq2min;
uint64_t log_vq1mean;
uint64_t log_vq2mean;
uint64_t log_n;
double log_pr_cl;
double log_pr_l4s;
double log_ppr_cl;
double log_ppr_l4s;
uint64_t stat_cin_cl;
uint64_t stat_cin_l4s;
uint64_t stat_cout_cl;
uint64_t stat_cout_l4s;
uint64_t stat_cdrop_cl;
uint64_t stat_cdrop_l4s;
uint64_t stat_in_cl;
uint64_t stat_in_l4s;
uint64_t stat_out_cl;
uint64_t stat_out_l4s;
uint64_t stat_drop_cl;
uint64_t stat_drop_l4s;
uint64_t stat_lat_cl;
uint64_t stat_lat_l4s;
uint64_t stat_lat2_cl;
uint64_t stat_lat2_l4s;
uint64_t stat_ecn_ce;
uint64_t stat_cecn_ce;
uint64_t stat_sel_rate;
uint64_t pktin_old = 0;
uint64_t pktout_old = 0;


double log_digest_delta_max;
double log_hist_delta_max;
long int stat_ctm_drop = 0;
long int stat_tm_drop = 0;
long int stat_pktin = 0;
uint64_t hctv[2];
FILE *f;

//Helper functions for safe substraction of two numbers
inline uint64_t safe_sub_hist(uint64_t newv, uint64_t oldv) {
	const uint64_t max = std::numeric_limits<uint64_t>::max();
	if(oldv > newv) {
		//printf("overflow: %lu %lu %lu\n", oldv, newv, max - oldv + newv);
		return max - oldv + newv;
	}
	return newv - oldv;
}

inline uint64_t safe_sub_vqlen(uint64_t newv, uint64_t oldv) {
	const uint64_t max = std::numeric_limits<uint32_t>::max();
	if(oldv > newv) {
		//printf("overflow: %lu %lu %lu\n", oldv, newv, max - oldv + newv);
		return max - oldv + newv;
	}
	return newv - oldv;
}


#define ALL_PIPES 0xffff
bf_rt_target_t dev_tgt;
}  // anonymous namespace

// This function does the initial setUp of getting bfrtInfo object associated
// with the P4 program from which all other required objects are obtained
void setUp() {
  dev_tgt.dev_id = 0;
  dev_tgt.pipe_id = ALL_PIPES;
  // Get devMgr singleton instance
  auto &devMgr = bfrt::BfRtDevMgr::getInstance();

  // Get bfrtInfo object from dev_id and p4 program name
  auto bf_status =
      devMgr.bfRtInfoGet(dev_tgt.dev_id, "ppv_egress_demo_marker", &bfrtInfo);
  // Check for status
  assert(bf_status == BF_SUCCESS);

  // Create a session object
  session = bfrt::BfRtSession::sessionCreate();
}

/**********************************************************************
 * CALLBACK funciton that gets invoked upon a learn event
 *  1. session : Session object that was used to register the callback. This is
 *               the session that has to be used to manipulate the table in
 *response to a learn
 *               event. Its always advisable to use a single session to
 *manipulate a single
 *               table.
 *  2. vec : Vector of learnData objects
 *  3. learn_msg_hdl : Pointer to the underlying learn message object, on which
 *                     an ack needs to be done in order for the hardware
 *resource to be freed up.
 *                     This is to be done once all the processing on the learn
 *update is done.
 *
 *********************************************************************/
bf_status_t learn_callback(const bf_rt_target_t &bf_rt_tgt,
                           const std::shared_ptr<BfRtSession> session,
                           std::vector<std::unique_ptr<BfRtLearnData>> vec,
                           bf_rt_learn_msg_hdl *const learn_msg_hdl,
                           const void *cookie);


void update_hist();

// This function does the initial set up of getting key field-ids, action-ids
// and data field ids associated with the ipRoute table. This is done once
// during init time.
void tableSetUp() {
  // Get table object from name
  auto bf_status =
      bfrtInfo->bfrtTableFromNameGet("SwitchIngress.ig_ppv", &igPpvTable);
  assert(bf_status == BF_SUCCESS);

  // Get action Ids for route and nat actions
  bf_status = igPpvTable->actionIdGet("SwitchIngress.set_ppv_port_l4s",
                                        &igPpv_SPPL_action_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = igPpvTable->actionIdGet("SwitchIngress.set_ppv_port_cl",
                                        &igPpv_SPPC_action_id);
  assert(bf_status == BF_SUCCESS);


  // Get field-ids for key field and data fields
  bf_status = igPpvTable->keyFieldIdGet("hdr.ipv4.$valid",
                                          &igPpv_ipv4_valid_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = igPpvTable->keyFieldIdGet("hdr.ipv4.l4s", &igPpv_ipv4_l4s_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = igPpvTable->keyFieldIdGet("ig_tm_md.ucast_egress_port", &igPpv_meta_egress_port_field_id);
  assert(bf_status == BF_SUCCESS);

  /***********************************************************************
   * DATA FIELD IDs for SPPC @ ingress
   **********************************************************************/

  bf_status =
      igPpvTable->dataFieldIdGet("ctv",
                                   igPpv_SPPC_action_id,
                                   &igPpv_SPPC_action_ctv_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status =
      igPpvTable->dataFieldIdGet("qid",
                                   igPpv_SPPC_action_id,
                                   &igPpv_SPPC_action_qid_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status =
      igPpvTable->dataFieldIdGet("ctv",
                                   igPpv_SPPL_action_id,
                                   &igPpv_SPPL_action_ctv_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status =
      igPpvTable->dataFieldIdGet("qid",
                                   igPpv_SPPL_action_id,
                                   &igPpv_SPPL_action_qid_field_id);
  assert(bf_status == BF_SUCCESS);



  bf_status =
      bfrtInfo->bfrtTableFromNameGet("SwitchEgress.eg_ppv_filter", &egPpvFilterTable);
  assert(bf_status == BF_SUCCESS);

  // Get action Ids for route and nat actions
  bf_status = egPpvFilterTable->actionIdGet("SwitchEgress.set_cl",
                                        &egPpvFilter_SC_action_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = egPpvFilterTable->actionIdGet("SwitchEgress.set_l4s",
                                        &egPpvFilter_SL_action_id);
  assert(bf_status == BF_SUCCESS);

  // Get field-ids for key field and data fields
  bf_status = egPpvFilterTable->keyFieldIdGet("hdr.ipv4.$valid",
                                          &egPpvFilter_ipv4_valid_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = egPpvFilterTable->keyFieldIdGet("hdr.ipv4.l4s", &egPpvFilter_ipv4_l4s_field_id);
  assert(bf_status == BF_SUCCESS);


  bf_status = egPpvFilterTable->keyFieldIdGet("eg_intr_md.egress_port", &egPpvFilter_meta_egress_port_field_id);
  assert(bf_status == BF_SUCCESS);


  /***********************************************************************
   * DATA FIELD IDs for SC @ egress
   **********************************************************************/
  bf_status = egPpvFilterTable->dataFieldIdGet(
      "offset", egPpvFilter_SC_action_id, &egPpvFilter_SC_action_offset_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = egPpvFilterTable->dataFieldIdGet(
      "ctv_l4s", egPpvFilter_SL_action_id, &egPpvFilter_SL_action_ctv_l4s_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = egPpvFilterTable->dataFieldIdGet(
      "offset", egPpvFilter_SL_action_id, &egPpvFilter_SL_action_offset_field_id);
  assert(bf_status == BF_SUCCESS);

  // Get table object from name
//  bf_status =
//      bfrtInfo->bfrtTableFromNameGet("SwitchIngress.port_fwd", &portFwdTable);
//  assert(bf_status == BF_SUCCESS);

  // Get action Ids
/*  bf_status = portFwdTable->actionIdGet("SwitchIngress.set_direct",
                                        &portFwd_Direct_action_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = portFwdTable->actionIdGet("SwitchIngress.set_eport",
                                        &portFwd_Eport_action_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = portFwdTable->actionIdGet("SwitchIngress.get_eport",
                                        &portFwd_Get_Eport_action_id);
  assert(bf_status == BF_SUCCESS);

  // Get field-ids for key field and data fields
  bf_status = portFwdTable->keyFieldIdGet("hdr.ipv4.$valid",
                                          &portFwd_ipv4_valid_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = portFwdTable->keyFieldIdGet("ig_intr_md.ingress_port", &portFwd_ingress_port_field_id);
  assert(bf_status == BF_SUCCESS);
*/
  /***********************************************************************
   * DATA FIELD IDs for port_fwd
   **********************************************************************/
/*
  bf_status =
      portFwdTable->dataFieldIdGet("port",
                                   portFwd_Direct_action_id,
                                   &portFwd_Direct_action_port_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status =
      portFwdTable->dataFieldIdGet("port",
                                   portFwd_Eport_action_id,
                                   &portFwd_Eport_action_port_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status =
      portFwdTable->dataFieldIdGet("ppv_port",
                                   portFwd_Eport_action_id,
                                   &portFwd_Eport_action_ppv_port_field_id);
  assert(bf_status == BF_SUCCESS);
*/
  /***********************************************************************
   * LEARN OBJECT GET FOR "digest" extern
   **********************************************************************/
  bf_status = bfrtInfo->bfrtLearnFromNameGet("SwitchIngressDeparser.ppv_digest",
                                             &learn_obj);
  assert(bf_status == BF_SUCCESS);

    /***********************************************************************
   * LEARN FIELD ID GET FROM LEARN OBJECT
   **********************************************************************/
  bf_status =
      learn_obj->learnFieldIdGet("vql4s", &learn_vql4s_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = learn_obj->learnFieldIdGet("vqcl", &learn_vqcl_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status =
      learn_obj->learnFieldIdGet("ts", &learn_ts_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status =
      learn_obj->learnFieldIdGet("drop", &learn_drop_field_id);
  assert(bf_status == BF_SUCCESS);


  /***********************************************************************
   * LEARN callback registration
   **********************************************************************/
  bf_status = learn_obj->bfRtLearnCallbackRegister(
      session, dev_tgt, learn_callback, nullptr);
  assert(bf_status == BF_SUCCESS);

  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.pvhist", &pvhistTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = pvhistTable->dataFieldIdGet( "$COUNTER_SPEC_BYTES", &counter_spec_bytes_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.cnt_in", &cntinTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = cntinTable->dataFieldIdGet( "$COUNTER_SPEC_BYTES", &cntin_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = cntinTable->keyFieldIdGet( "$COUNTER_INDEX", &cntin_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.cpkt_in", &pktinTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = pktinTable->dataFieldIdGet( "$COUNTER_SPEC_PKTS", &pktin_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = pktinTable->keyFieldIdGet( "$COUNTER_INDEX", &pktin_field_id);
  assert(bf_status == BF_SUCCESS);


  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchEgress.cpkt_out", &pktoutTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = pktoutTable->dataFieldIdGet( "$COUNTER_SPEC_PKTS", &pktout_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = pktoutTable->keyFieldIdGet( "$COUNTER_INDEX", &pktout_field_id);
  assert(bf_status == BF_SUCCESS);



  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.cnt_drop", &cntdropTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = cntdropTable->dataFieldIdGet( "$COUNTER_SPEC_BYTES", &cntdrop_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = cntdropTable->keyFieldIdGet( "$COUNTER_INDEX", &cntdrop_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchEgress.cnt_out", &cntoutTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = cntoutTable->dataFieldIdGet( "$COUNTER_SPEC_BYTES", &cntout_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = cntoutTable->keyFieldIdGet( "$COUNTER_INDEX", &cntout_field_id);
  assert(bf_status == BF_SUCCESS);




  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchEgress.cnt_ecn", &cntecnTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = cntecnTable->dataFieldIdGet( "$COUNTER_SPEC_BYTES", &cntecn_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = cntecnTable->keyFieldIdGet( "$COUNTER_INDEX", &cntecn_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchEgress.reg_latency", &reglatencyTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = reglatencyTable->dataFieldIdGet( "SwitchEgress.reg_latency.f1", &reglatency_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = reglatencyTable->keyFieldIdGet( "$REGISTER_INDEX", &reglatency_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchEgress.delay_reg", &reglatency2Table);
  assert(bf_status == BF_SUCCESS);

  bf_status = reglatency2Table->dataFieldIdGet( "SwitchEgress.delay_reg.f1", &reglatency2_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = reglatency2Table->keyFieldIdGet( "$REGISTER_INDEX", &reglatency2_field_id);
  assert(bf_status == BF_SUCCESS);


  /*
  * P4Marker
  * ********************************************************************/
 

  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.p4m.sel_rate", &sel_rateTable);
  assert(bf_status == BF_SUCCESS);

  bf_status = sel_rateTable->dataFieldIdGet( "SwitchIngress.p4m.sel_rate.f1", &sel_rate_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = sel_rateTable->keyFieldIdGet( "$REGISTER_INDEX", &sel_rate_field_id);
  assert(bf_status == BF_SUCCESS);



  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.p4m.FlowIdentification", &P4MarkerFITable);
  assert(bf_status == BF_SUCCESS);
  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.p4m.TVF", &P4MarkerTVFTable);
  assert(bf_status == BF_SUCCESS);
  bf_status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.p4m.lpf_rate", &P4MarkerLRTable);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerFITable->actionIdGet("SwitchIngress.p4m.handle_flow",
                                        &P4MarkerFI_HF_action_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerTVFTable->actionIdGet("SwitchIngress.p4m.set_pv",
                                        &P4MarkerTVF_SP_action_id);
  assert(bf_status == BF_SUCCESS);



  // Get field-ids for key field and data fields
  bf_status = P4MarkerFITable->keyFieldIdGet("ig_md.ueid",
                                          &P4MarkerFI_tcp_srcport_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerFITable->dataFieldIdGet(
      "pflowid", P4MarkerFI_HF_action_id, &P4MarkerFI_HF_action_pflowid_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerFITable->dataFieldIdGet(
      "pol", P4MarkerFI_HF_action_id, &P4MarkerFI_HF_action_pol_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerTVFTable->keyFieldIdGet("policy",
                                          &P4MarkerTVF_policyid_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerTVFTable->keyFieldIdGet("rndidx",
                                          &P4MarkerTVF_rndidx_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerTVFTable->dataFieldIdGet(
      "ppv", P4MarkerTVF_SP_action_id, &P4MarkerTVF_SP_action_ppv_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = P4MarkerLRTable->keyFieldIdGet("$LPF_INDEX",
		  &P4MarkerLR_lpf_index_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerLRTable->dataFieldIdGet(
      "$LPF_SPEC_TYPE", &P4MarkerLR_lpf_spec_type_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerLRTable->dataFieldIdGet(
      "$LPF_SPEC_GAIN_TIME_CONSTANT_NS", &P4MarkerLR_lpf_spec_gain_time_constant_ns_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerLRTable->dataFieldIdGet(
      "$LPF_SPEC_DECAY_TIME_CONSTANT_NS", &P4MarkerLR_lpf_spec_decay_time_constant_ns_field_id);
  assert(bf_status == BF_SUCCESS);
  bf_status = P4MarkerLRTable->dataFieldIdGet(
      "$LPF_SPEC_OUT_SCALE_DOWN_FACTOR", &P4MarkerLR_lpf_spec_out_scale_down_factor_field_id);
  assert(bf_status == BF_SUCCESS);

  // Allocate key and data once, and use reset across different uses
  bf_status = igPpvTable->keyAllocate(&igppvbfrtTableKey);
  assert(bf_status == BF_SUCCESS);

  bf_status = igPpvTable->dataAllocate(igPpv_SPPL_action_id, &igppvbfrtTableDataSPPL);
  assert(bf_status == BF_SUCCESS);

  bf_status = igPpvTable->dataAllocate(igPpv_SPPC_action_id, &igppvbfrtTableDataSPPC);
  assert(bf_status == BF_SUCCESS);

  bf_status = egPpvFilterTable->keyAllocate(&egppvbfrtTableKey);
  assert(bf_status == BF_SUCCESS);

  bf_status = egPpvFilterTable->dataAllocate(egPpvFilter_SL_action_id, &egppvbfrtTableDataSL);
  assert(bf_status == BF_SUCCESS);

  bf_status = egPpvFilterTable->dataAllocate(egPpvFilter_SC_action_id, &egppvbfrtTableDataSC);
  assert(bf_status == BF_SUCCESS);

/*  bf_status = portFwdTable->keyAllocate(&portfwdTableKey);
  assert(bf_status == BF_SUCCESS);

  bf_status = portFwdTable->dataAllocate(portFwd_Direct_action_id, &portfwdTableDataDirect);
  assert(bf_status == BF_SUCCESS);

  bf_status = portFwdTable->dataAllocate(portFwd_Eport_action_id, &portfwdTableDataEport);
  assert(bf_status == BF_SUCCESS);

  bf_status = portFwdTable->dataAllocate(portFwd_Get_Eport_action_id, &portfwdTableDataGetEport);
  assert(bf_status == BF_SUCCESS);
*/
  bf_status = P4MarkerFITable->keyAllocate(&P4MarkerFIbfrtTableKey);
  assert(bf_status == BF_SUCCESS);

  bf_status = P4MarkerFITable->dataAllocate(P4MarkerFI_HF_action_id, &P4MarkerFIbfrtTableData);
  assert(bf_status == BF_SUCCESS);

  bf_status = P4MarkerTVFTable->keyAllocate(&P4MarkerTVFbfrtTableKey);
  assert(bf_status == BF_SUCCESS);

  bf_status = P4MarkerTVFTable->dataAllocate(P4MarkerTVF_SP_action_id, &P4MarkerTVFbfrtTableData);
  assert(bf_status == BF_SUCCESS);

  bf_status = P4MarkerLRTable->keyAllocate(&P4MarkerLRbfrtTableKey);
  assert(bf_status == BF_SUCCESS);

  bf_status = P4MarkerLRTable->dataAllocate(&P4MarkerLRbfrtTableData);
  assert(bf_status == BF_SUCCESS);




  for (uint32_t i=0;i<2048;++i) {
    bf_status = pvhistTable->keyAllocate(&keys[i]);
    assert(bf_status == BF_SUCCESS);
    bf_status = pvhistTable->dataAllocate(&data[i]);
    assert(bf_status == BF_SUCCESS);
    if (i>0) {
      key_data_pairs.push_back(std::make_pair(keys[i].get(), data[i].get()));
    }
  }

  for (uint32_t i=0;i<2;++i) {
    bf_status = cntinTable->keyAllocate(&cntin_keys[i]);
    assert(bf_status == BF_SUCCESS);
    bf_status = cntin_keys[i]->setValue(cntin_field_id, static_cast<uint64_t>(i));
    assert(bf_status == BF_SUCCESS);
    bf_status = cntinTable->dataAllocate(&cntin_data[i]);
    assert(bf_status == BF_SUCCESS);
  }

  for (uint32_t i=0;i<2;++i) {
    bf_status = cntdropTable->keyAllocate(&cntdrop_keys[i]);
    assert(bf_status == BF_SUCCESS);
    bf_status = cntdrop_keys[i]->setValue(cntdrop_field_id, static_cast<uint64_t>(i));
    assert(bf_status == BF_SUCCESS);
    bf_status = cntdropTable->dataAllocate(&cntdrop_data[i]);
    assert(bf_status == BF_SUCCESS);
  }

  for (uint32_t i=0;i<2;++i) {
    bf_status = cntoutTable->keyAllocate(&cntout_keys[i]);
    assert(bf_status == BF_SUCCESS);
    bf_status = cntout_keys[i]->setValue(cntout_field_id, static_cast<uint64_t>(i));
    assert(bf_status == BF_SUCCESS);
    bf_status = cntoutTable->dataAllocate(&cntout_data[i]);
    assert(bf_status == BF_SUCCESS);
  }

  for (uint32_t i=0;i<2;++i) {
    bf_status = reglatencyTable->keyAllocate(&reglatency_keys[i]);
    assert(bf_status == BF_SUCCESS);
    bf_status = reglatency_keys[i]->setValue(reglatency_field_id, i); //static_cast<uint64_t>(i));
    assert(bf_status == BF_SUCCESS);
    bf_status = reglatencyTable->dataAllocate(&reglatency_data[i]);
    assert(bf_status == BF_SUCCESS);
  }

  for (uint32_t i=0;i<2;++i) {
    bf_status = reglatency2Table->keyAllocate(&reglatency2_keys[i]);
    assert(bf_status == BF_SUCCESS);
    bf_status = reglatency2_keys[i]->setValue(reglatency2_field_id, i); //static_cast<uint64_t>(i));
    assert(bf_status == BF_SUCCESS);
    bf_status = reglatency2Table->dataAllocate(&reglatency2_data[i]);
    assert(bf_status == BF_SUCCESS);
  }



    bf_status = sel_rateTable->keyAllocate(&sel_rate_keys);
    assert(bf_status == BF_SUCCESS);
    bf_status = sel_rate_keys->setValue(sel_rate_field_id, 0); //static_cast<uint64_t>(i));
    assert(bf_status == BF_SUCCESS);
    bf_status = sel_rateTable->dataAllocate(&sel_rate_data);
    assert(bf_status == BF_SUCCESS);
 


  uint64_t idx = 0;
  bf_status = cntecnTable->keyAllocate(&cntecn_key);
  assert(bf_status == BF_SUCCESS);
  bf_status = cntecn_key->setValue(cntecn_field_id, idx);
  assert(bf_status == BF_SUCCESS);
  bf_status = cntecnTable->dataAllocate(&cntecn_data);
  assert(bf_status == BF_SUCCESS);

  idx = 0;
  bf_status = pktinTable->keyAllocate(&pktin_key);
  assert(bf_status == BF_SUCCESS);
  bf_status = pktin_key->setValue(pktin_field_id, idx);
  assert(bf_status == BF_SUCCESS);
  bf_status = pktinTable->dataAllocate(&pktin_data);
  assert(bf_status == BF_SUCCESS);

  idx = 0;
  bf_status = pktoutTable->keyAllocate(&pktout_key);
  assert(bf_status == BF_SUCCESS);
  bf_status = pktout_key->setValue(pktout_field_id, idx);
  assert(bf_status == BF_SUCCESS);
  bf_status = pktoutTable->dataAllocate(&pktout_data);
  assert(bf_status == BF_SUCCESS);

}

/*******************************************************************************
 * Utility functions associated with tables in the P4 program.
 ******************************************************************************/

// This function sets the passed in ip_dst and vrf value into the key object
// passed using the setValue methods on the key object
void igPpv_key_setup(const IgPpvKey &igPpv_key,
                       bfrt::BfRtTableKey *table_key) {
  // Set value into the key object. Key type is "EXACT"
  auto bf_status = table_key->setValue(
      igPpv_ipv4_valid_field_id, static_cast<bool>(igPpv_key.ipv4_valid));
  assert(bf_status == BF_SUCCESS);
  
  bf_status = table_key->setValue(igPpv_ipv4_l4s_field_id,
                                  static_cast<bool>(igPpv_key.ipv4_l4s));
  assert(bf_status == BF_SUCCESS);

  bf_status = table_key->setValue(igPpv_meta_egress_port_field_id,
                                  static_cast<uint64_t>(igPpv_key.egress_port));
  assert(bf_status == BF_SUCCESS);

  return;
}

void egPpvFilter_key_setup(const EgPpvFilterKey &egPpvFilter_key,
                       bfrt::BfRtTableKey *table_key) {
  // Set value into the key object. Key type is "EXACT"
  auto bf_status = table_key->setValue(
      egPpvFilter_ipv4_valid_field_id, static_cast<bool>(egPpvFilter_key.ipv4_valid));
  assert(bf_status == BF_SUCCESS);

  bf_status = table_key->setValue(egPpvFilter_ipv4_l4s_field_id,
                                  static_cast<bool>(egPpvFilter_key.ipv4_l4s));

  bf_status = table_key->setValue(egPpvFilter_meta_egress_port_field_id,
                                  static_cast<uint64_t>(egPpvFilter_key.egress_port));
  assert(bf_status == BF_SUCCESS);

  return;
}
/*
void portFwd_key_setup(const PortFwdKey &portFwd_key,
                       bfrt::BfRtTableKey *table_key) {
  // Set value into the key object. Key type is "EXACT"
  auto bf_status = table_key->setValue(
      portFwd_ipv4_valid_field_id, static_cast<bool>(portFwd_key.ipv4_valid));
  assert(bf_status == BF_SUCCESS);

  bf_status = table_key->setValue(portFwd_ingress_port_field_id,
                                  static_cast<uint64_t>(portFwd_key.ingress_port));
  assert(bf_status == BF_SUCCESS);

  return;
}
*/
void igPpv_data_setup_SPPC(const IgPpvSPPCData &igPpv_data,
                                  bfrt::BfRtTableData *table_data) {
  // Set value into the data object
  auto bf_status = table_data->setValue(igPpv_SPPC_action_ctv_field_id,
                                        static_cast<uint64_t>(igPpv_data.ctv));
  assert(bf_status == BF_SUCCESS);

  bf_status = table_data->setValue(igPpv_SPPC_action_qid_field_id,
                                   static_cast<uint64_t>(igPpv_data.qid));
  assert(bf_status == BF_SUCCESS);

  return;
}

void igPpv_data_setup_SPPL(const IgPpvSPPLData &igPpv_data,
                                  bfrt::BfRtTableData *table_data) {
  // Set value into the data object
  auto bf_status = table_data->setValue(igPpv_SPPL_action_ctv_field_id,
                                        static_cast<uint64_t>(igPpv_data.ctv));
//  std::cout << igPpv_SPPL_action_ctv_field_id << " " << igPpv_data.ctv << std::endl;
  assert(bf_status == BF_SUCCESS);

  bf_status = table_data->setValue(igPpv_SPPL_action_qid_field_id,
                                   static_cast<uint64_t>(igPpv_data.qid));
  assert(bf_status == BF_SUCCESS);

  return;
}



void egPpvFilter_data_setup_SC(const EgPpvFilterSCData &egPpv_data,
                                  bfrt::BfRtTableData *table_data) {
  // Set value into the data object
  auto bf_status = table_data->setValue(egPpvFilter_SC_action_offset_field_id,
                                        static_cast<uint64_t>(egPpv_data.offset));
  assert(bf_status == BF_SUCCESS);

  return;
}

void egPpvFilter_data_setup_SL(const EgPpvFilterSLData &egPpv_data,
                                  bfrt::BfRtTableData *table_data) {
  // Set value into the data object
  auto bf_status = table_data->setValue(egPpvFilter_SL_action_ctv_l4s_field_id,
                                        static_cast<uint64_t>(egPpv_data.ctv_l4s));
  assert(bf_status == BF_SUCCESS);

  bf_status = table_data->setValue(egPpvFilter_SL_action_offset_field_id,
                                   static_cast<uint64_t>(egPpv_data.offset));
  assert(bf_status == BF_SUCCESS);

  return;
}
/*
void portFwd_data_setup_Direct(const PortFwdSetDirectData &portFwd_data,
                                  bfrt::BfRtTableData *table_data) {
  // Set value into the data object
  auto bf_status = table_data->setValue(portFwd_Direct_action_port_field_id,
                                        static_cast<uint64_t>(portFwd_data.port));
  assert(bf_status == BF_SUCCESS);

  return;
}

void portFwd_data_setup_Eport(const PortFwdEportData &portFwd_data,
                                  bfrt::BfRtTableData *table_data) {
  // Set value into the data object
  auto bf_status = table_data->setValue(portFwd_Eport_action_port_field_id,
                                        static_cast<uint64_t>(portFwd_data.port));
  assert(bf_status == BF_SUCCESS);

  bf_status = table_data->setValue(portFwd_Eport_action_ppv_port_field_id,
                                   static_cast<uint64_t>(portFwd_data.ppv_port));
  assert(bf_status == BF_SUCCESS);

  return;
}
*/

void P4MarkerFI_key_setup(const P4MarkerFIKey &key,
                       bfrt::BfRtTableKey *table_key) {
  // Set value into the key object. Key type is "EXACT"
  auto bf_status = table_key->setValue(
      P4MarkerFI_tcp_srcport_field_id, static_cast<uint64_t>(key.tcp_srcport));
  assert(bf_status == BF_SUCCESS);
  return;
}

void P4MarkerTVF_key_setup(const P4MarkerTVFKey &key,
                       bfrt::BfRtTableKey *table_key) {
  // Set value into the key object. Key type is "EXACT"
  auto bf_status = table_key->setValue(
      P4MarkerTVF_policyid_field_id, static_cast<uint8_t>(key.policyid));
  assert(bf_status == BF_SUCCESS);
  bf_status = table_key->setValue(
      P4MarkerTVF_rndidx_field_id, static_cast<uint64_t>(key.rndidx));
  assert(bf_status == BF_SUCCESS);
  return;
}

void P4MarkerFI_data_setup_HF(const P4MarkerFIHFData &data,
                                  bfrt::BfRtTableData *table_data) {
  // Set value into the data object
  auto bf_status = table_data->setValue(P4MarkerFI_HF_action_pflowid_field_id,
                                        static_cast<uint64_t>(data.pflowid));
  assert(bf_status == BF_SUCCESS);
  bf_status = table_data->setValue(P4MarkerFI_HF_action_pol_field_id,
                                        static_cast<uint64_t>(data.pol));
  assert(bf_status == BF_SUCCESS);
  return;
}

void P4MarkerTVF_data_setup_SP(const P4MarkerTVFSPData &data,
                                  bfrt::BfRtTableData *table_data) {
  // Set value into the data object
  auto bf_status = table_data->setValue(P4MarkerTVF_SP_action_ppv_field_id,
                                        static_cast<uint64_t>(data.ppv));
  assert(bf_status == BF_SUCCESS);
  return;
}

void P4MarkerFI_entry_add_modify_with_HF(const P4MarkerFIKey &key,
                                         const P4MarkerFIHFData &data,
                                         const bool &add) {
  // Adding a match entry with below mac Addr to be forwarded to the below port
  // Reset key and data before use
  P4MarkerFITable->keyReset(P4MarkerFIbfrtTableKey.get());
  P4MarkerFITable->dataReset(P4MarkerFI_HF_action_id, P4MarkerFIbfrtTableData.get());
  // Fill in the Key and Data object
  P4MarkerFI_key_setup(key, P4MarkerFIbfrtTableKey.get());
  P4MarkerFI_data_setup_HF(data, P4MarkerFIbfrtTableData.get());
  // Call table entry add API, if the request is for an add, else call modify
  bf_status_t status = BF_SUCCESS;
  if (add) {
    status = P4MarkerFITable->tableEntryAdd(
        *session, dev_tgt, *P4MarkerFIbfrtTableKey, *P4MarkerFIbfrtTableData);
  } else {
    status = P4MarkerFITable->tableEntryMod(
        *session, dev_tgt, *P4MarkerFIbfrtTableKey, *P4MarkerFIbfrtTableData);
  }
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}

void P4MarkerTVF_entry_add_modify_with_SP(const P4MarkerTVFKey &key,
                                         const P4MarkerTVFSPData &data,
                                         const bool &add) {
  // Adding a match entry with below mac Addr to be forwarded to the below port
  // Reset key and data before use
  P4MarkerTVFTable->keyReset(P4MarkerTVFbfrtTableKey.get());
  P4MarkerTVFTable->dataReset(P4MarkerTVF_SP_action_id, P4MarkerTVFbfrtTableData.get());
  // Fill in the Key and Data object
  P4MarkerTVF_key_setup(key, P4MarkerTVFbfrtTableKey.get());
  P4MarkerTVF_data_setup_SP(data, P4MarkerTVFbfrtTableData.get());
  // Call table entry add API, if the request is for an add, else call modify
  bf_status_t status = BF_SUCCESS;
  if (add) {
    status = P4MarkerTVFTable->tableEntryAdd(
        *session, dev_tgt, *P4MarkerTVFbfrtTableKey, *P4MarkerTVFbfrtTableData);
  } else {
    status = P4MarkerTVFTable->tableEntryMod(
        *session, dev_tgt, *P4MarkerTVFbfrtTableKey, *P4MarkerTVFbfrtTableData);
  }
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}


void igPpv_entry_add_modify_with_SPPC(const IgPpvKey &igPpv_key,
                                         const IgPpvSPPCData &data,
                                         const bool &add) {
  // Adding a match entry with below mac Addr to be forwarded to the below port
  // Reset key and data before use
  igPpvTable->keyReset(igppvbfrtTableKey.get());
  igPpvTable->dataReset(igPpv_SPPC_action_id, igppvbfrtTableDataSPPC.get());

  // Fill in the Key and Data object
  igPpv_key_setup(igPpv_key, igppvbfrtTableKey.get());
  igPpv_data_setup_SPPC(data, igppvbfrtTableDataSPPC.get());

  // Call table entry add API, if the request is for an add, else call modify
  bf_status_t status = BF_SUCCESS;
  if (add) {
    status = igPpvTable->tableEntryAdd(
        *session, dev_tgt, *igppvbfrtTableKey, *igppvbfrtTableDataSPPC);
  } else {
    status = igPpvTable->tableEntryMod(
        *session, dev_tgt, *igppvbfrtTableKey, *igppvbfrtTableDataSPPC);
  }
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}

//set_ppv_port_l4s
//igPpv_key -> ipv4, l4sbit, port, etc
//IgPpvSPPLData -> max(ctv1,ctv2), 1
void igPpv_entry_add_modify_with_SPPL(const IgPpvKey &igPpv_key,
                                         const IgPpvSPPLData &data,
                                         const bool &add) {
  // Adding a match entry with below mac Addr to be forwarded to the below port
  // Reset key and data before use
  bf_status_t status = igPpvTable->keyReset(igppvbfrtTableKey.get());
  assert(status == BF_SUCCESS);

  status = igPpvTable->dataReset(igPpv_SPPL_action_id, igppvbfrtTableDataSPPL.get());
  assert(status == BF_SUCCESS);
  // Fill in the Key and Data object
  igPpv_key_setup(igPpv_key, igppvbfrtTableKey.get());
  igPpv_data_setup_SPPL(data, igppvbfrtTableDataSPPL.get());

  // Call table entry add API, if the request is for an add, else call modify
  status = BF_SUCCESS;
  if (add) {
    status = igPpvTable->tableEntryAdd(
        *session, dev_tgt, *igppvbfrtTableKey, *igppvbfrtTableDataSPPL);
    assert(status == BF_SUCCESS);
  } else {
//    status = igPpvTable->tableEntryDel(*session, dev_tgt, *igppvbfrtTableKey);
//    assert(status == BF_SUCCESS);
    status = igPpvTable->tableEntryMod(
        *session, dev_tgt, *igppvbfrtTableKey, *igppvbfrtTableDataSPPL);
    assert(status == BF_SUCCESS);
  }
//  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}

void egPpvFilter_entry_add_modify_with_SC(const EgPpvFilterKey &egPpv_key,
                                         const EgPpvFilterSCData &data,
                                         const bool &add) {
  // Adding a match entry with below mac Addr to be forwarded to the below port
  // Reset key and data before use
  egPpvFilterTable->keyReset(egppvbfrtTableKey.get());
  egPpvFilterTable->dataReset(egPpvFilter_SC_action_id, egppvbfrtTableDataSC.get());

  // Fill in the Key and Data object
  egPpvFilter_key_setup(egPpv_key, egppvbfrtTableKey.get());
  egPpvFilter_data_setup_SC(data, egppvbfrtTableDataSC.get());

  // Call table entry add API, if the request is for an add, else call modify
  bf_status_t status = BF_SUCCESS;
  if (add) {
    status = egPpvFilterTable->tableEntryAdd(
        *session, dev_tgt, *egppvbfrtTableKey, *egppvbfrtTableDataSC);
  } else {
    status = egPpvFilterTable->tableEntryMod(
        *session, dev_tgt, *egppvbfrtTableKey, *egppvbfrtTableDataSC);
  }
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}

void egPpvFilter_entry_add_modify_with_SL(const EgPpvFilterKey &egPpv_key,
                                         const EgPpvFilterSLData &data,
                                         const bool &add) {
  // Adding a match entry with below mac Addr to be forwarded to the below port
  // Reset key and data before use
  egPpvFilterTable->keyReset(egppvbfrtTableKey.get());
  egPpvFilterTable->dataReset(egPpvFilter_SL_action_id, egppvbfrtTableDataSL.get());

  // Fill in the Key and Data object
  egPpvFilter_key_setup(egPpv_key, egppvbfrtTableKey.get());
  egPpvFilter_data_setup_SL(data, egppvbfrtTableDataSL.get());

  // Call table entry add API, if the request is for an add, else call modify
  bf_status_t status = BF_SUCCESS;
  if (add) {
    status = egPpvFilterTable->tableEntryAdd(
        *session, dev_tgt, *egppvbfrtTableKey, *egppvbfrtTableDataSL);
  } else {
    status = egPpvFilterTable->tableEntryMod(
        *session, dev_tgt, *egppvbfrtTableKey, *egppvbfrtTableDataSL);
  }
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}
/*
void portFwd_entry_add_modify_with_Direct(const PortFwdKey &portFwd_key,
                                          const PortFwdSetDirectData &data,
                                          const bool &add) {
  // Reset key and data before use
  portFwdTable->keyReset(portfwdTableKey.get());
  portFwdTable->dataReset(portFwd_Direct_action_id, portfwdTableDataDirect.get());

  // Fill in the Key and Data object
  portFwd_key_setup(portFwd_key, portfwdTableKey.get());
  portFwd_data_setup_Direct(data, portfwdTableDataDirect.get());

  // Call table entry add API, if the request is for an add, else call modify
  bf_status_t status = BF_SUCCESS;
  if (add) {
    status = portFwdTable->tableEntryAdd(
        *session, dev_tgt, *portfwdTableKey, *portfwdTableDataDirect);
  } else {
    status = portFwdTable->tableEntryMod(
        *session, dev_tgt, *portfwdTableKey, *portfwdTableDataDirect);
  }
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}

void portFwd_entry_add_modify_with_Eport(const PortFwdKey &portFwd_key,
                                          const PortFwdEportData &data,
                                          const bool &add) {
  // Reset key and data before use
  portFwdTable->keyReset(portfwdTableKey.get());
  portFwdTable->dataReset(portFwd_Eport_action_id, portfwdTableDataEport.get());

  // Fill in the Key and Data object
  portFwd_key_setup(portFwd_key, portfwdTableKey.get());
  portFwd_data_setup_Eport(data, portfwdTableDataEport.get());

  // Call table entry add API, if the request is for an add, else call modify
  bf_status_t status = BF_SUCCESS;
  if (add) {
    status = portFwdTable->tableEntryAdd(
        *session, dev_tgt, *portfwdTableKey, *portfwdTableDataEport);
  } else {
    status = portFwdTable->tableEntryMod(
        *session, dev_tgt, *portfwdTableKey, *portfwdTableDataEport);
  }
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}

void portFwd_entry_add_modify_with_Get_Eport(const PortFwdKey &portFwd_key,
                                          const bool &add) {
  // Reset key before use
  portFwdTable->keyReset(portfwdTableKey.get());
  portFwdTable->dataReset(portFwd_Get_Eport_action_id, portfwdTableDataGetEport.get());

  // Fill in the Key object
  portFwd_key_setup(portFwd_key, portfwdTableKey.get());

  // Call table entry add API, if the request is for an add, else call modify
  bf_status_t status = BF_SUCCESS;
  if (add) {
    status = portFwdTable->tableEntryAdd(
        *session, dev_tgt, *portfwdTableKey, *portfwdTableDataGetEport);
  } else {
    status = portFwdTable->tableEntryMod(
        *session, dev_tgt, *portfwdTableKey, *portfwdTableDataGetEport);
  }
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}
*/


void init_ctvs(uint16_t port, uint16_t ctv1, uint16_t ctv2) {
  uint8_t offset = 0;
  bool add_flag = true;
  load_policy_trigger = false;

  for (int i=0;i<10;++i)
	  policy_map[i] = false;

  //Ingress
  IgPpvKey k_ig = { true, true, port }; //ipv4_valid, ipv4_l4s, egress_port
  IgPpvSPPLData v_igl = { std::max(ctv1, ctv2), qid_l4s };
  igPpv_entry_add_modify_with_SPPL(k_ig, v_igl, add_flag);

  k_ig.ipv4_l4s = false; //now init the classic CTV
  IgPpvSPPCData v_igc = { ctv2, qid_cl };
  igPpv_entry_add_modify_with_SPPC(k_ig, v_igc, add_flag);

  //Egress
  EgPpvFilterKey k_eg = { true, true, port };
  EgPpvFilterSLData v_egl = { std::max(ctv1, ctv2), offset };
  egPpvFilter_entry_add_modify_with_SL(k_eg, v_egl, add_flag);

  k_eg.ipv4_l4s = false; //now init the classic
  EgPpvFilterSCData v_egc = { offset };
  egPpvFilter_entry_add_modify_with_SC(k_eg, v_egc, add_flag);

  for (int i=0;i<1024;++i) {
      P4MarkerTVFKey k_tvf = {1, i}; // policy id, rate index
      P4MarkerTVFSPData k_data = {0}; //{1023-i}; // PV
      P4MarkerTVF_entry_add_modify_with_SP(k_tvf, k_data, add_flag);
  }

  policy_map[1] = true;

  for (int i=0;i<1024;++i) {
      P4MarkerTVFKey k_tvf = {0, i}; // policy id, PPV
      P4MarkerTVFSPData k_data = {std::max(0,924-i)};
      P4MarkerTVF_entry_add_modify_with_SP(k_tvf, k_data, add_flag);
  }

  policy_map[0] = true;

  //20-30K
  for (int i=0; i < 30000; ++i) {
      P4MarkerFIKey fi_port = {20000 + i}; // UEid
      P4MarkerFIHFData fi_data = {i, 1}; // flow id representing the traffic aggregate and policy id used in the TVF table
      P4MarkerFI_entry_add_modify_with_HF(fi_port, fi_data, add_flag);
  }

  // vxlan traffic on uid=8472
  P4MarkerFIKey fi_port = {8472}; // UEid
  P4MarkerFIHFData fi_data = {30000, 1}; // flow id representing the traffic aggregate and policy id used in the TVF table
  P4MarkerFI_entry_add_modify_with_HF(fi_port, fi_data, add_flag);

}

void load_policy() {
  std::ifstream pFile;
  pFile.open(POLICY_FILE);
  if (!pFile) {
    std::cout << "\nPolicy file not found.\n";
    return;
  }

  int policyId;
  int val;
  int fid;
 
  pFile >> policyId;
  bool add_flag = !policy_map[policyId];

  for (int i=0;i<1024;++i) {
    pFile >> val;
    P4MarkerTVFKey k_tvf = {policyId, i}; // policy id, rate index
    P4MarkerTVFSPData k_data = {val}; // PV
    P4MarkerTVF_entry_add_modify_with_SP(k_tvf, k_data, add_flag);
  }
  policy_map[policyId] = true;
  
  while (pFile >> val)
  {
    fid = (val==8472?30000:val-20000);
    P4MarkerFIKey fi_port = {val}; // UEid
    P4MarkerFIHFData fi_data = {fid, policyId}; // flow id representing the traffic aggregate and policy id used in the TVF table
    P4MarkerFI_entry_add_modify_with_HF(fi_port, fi_data, false);
  }

  pFile.close();
  load_policy_trigger = false;
  printf("Policy loaded - id=%d\n", policyId);
}


void config_lpfs() {
  auto bf_status = P4MarkerLRTable->tableClear(*session, dev_tgt);
  assert(bf_status == BF_SUCCESS);
  for (uint64_t i=0;i<35000;++i) {
    bf_status = P4MarkerLRTable->keyReset(P4MarkerLRbfrtTableKey.get());
    assert(bf_status == BF_SUCCESS);
    P4MarkerLRTable->dataReset(P4MarkerLRbfrtTableData.get());
    bf_status = P4MarkerLRbfrtTableKey->setValue(P4MarkerLR_lpf_index_field_id, i);
    assert(bf_status == BF_SUCCESS);
    std::string stmp = "RATE";
    bf_status = P4MarkerLRbfrtTableData->setValue(P4MarkerLR_lpf_spec_type_field_id,stmp);
    assert(bf_status == BF_SUCCESS);

    float p1 = markerTimeWindowNs;
    bf_status = P4MarkerLRbfrtTableData->setValue(P4MarkerLR_lpf_spec_gain_time_constant_ns_field_id, p1); // float???
    assert(bf_status == BF_SUCCESS);
    float p2 = markerTimeWindowNs;
    bf_status = P4MarkerLRbfrtTableData->setValue(P4MarkerLR_lpf_spec_decay_time_constant_ns_field_id, p2); // float???
    assert(bf_status == BF_SUCCESS);
    uint64_t p3 = 9; // 9 in general
    bf_status = P4MarkerLRbfrtTableData->setValue(P4MarkerLR_lpf_spec_out_scale_down_factor_field_id, p3); // float???
    assert(bf_status == BF_SUCCESS);
    bf_status = P4MarkerLRTable->tableEntryAdd(*session, dev_tgt, *P4MarkerLRbfrtTableKey, *P4MarkerLRbfrtTableData);
    assert(bf_status == BF_SUCCESS);
  }
}

void set_ctvs(uint16_t port, uint16_t ctv1, uint16_t ctv2, uint16_t ctv2_l4s) {
  uint8_t offset = 0;
  bool add_flag = false;

  //Ingress
  IgPpvKey k_ig = { true, true, port }; //ipv4_valid, ipv4_l4s, egress_port
  IgPpvSPPLData v_igl = { std::max(ctv1, std::max(ctv2, ctv2_l4s)), qid_l4s };
  igPpv_entry_add_modify_with_SPPL(k_ig, v_igl, add_flag);

  k_ig.ipv4_l4s = false; //now init the classic CTV
  IgPpvSPPCData v_igc = { ctv2, qid_cl };
  igPpv_entry_add_modify_with_SPPC(k_ig, v_igc, add_flag);

  //Egress
  EgPpvFilterKey k_eg = { true, true, port };
  EgPpvFilterSLData v_egl = { std::max(ctv1, ctv2), offset };
  egPpvFilter_entry_add_modify_with_SL(k_eg, v_egl, add_flag);

//  Classic not set here (we only mark L4S at egress, and forward the classic)  
//  k_eg.ipv4_l4s = false; //now init the classic
//  EgPpvFilterSCData v_egc = { offset };
//  egPpvFilter_entry_add_modify_with_SC(k_eg, v_egc, &add_flag);
}
/*
void set_portfwd() {

  PortFwdKey k_pf; // ingress_port, ipv4_valid
  PortFwdSetDirectData d_pf; // port
  PortFwdEportData e_pf; // port, ppv_port

  // path-4
  k_pf = { PORT_30, true };
  d_pf = { PORT_32 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_30, false };
  d_pf = { PORT_32 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_32, false };
  d_pf = { PORT_29 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_32, true };
  if (isDirectPortFwd) {
    d_pf = { PORT_29};
    portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);
  } else {
    e_pf = { PORT_29, PORT_59 };
    portFwd_entry_add_modify_with_Eport(k_pf, e_pf, true);
  }

  //----------------------------------------------------
  // path-3

  k_pf = { PORT_29, true };
  d_pf = { PORT_31 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_29, false };
  d_pf = { PORT_31 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_31, false };
  d_pf = { PORT_29 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_31, true };
  if (isDirectPortFwd) {
    d_pf = { PORT_29};
    portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);
  } else {
    e_pf = { PORT_29, PORT_59 };
    portFwd_entry_add_modify_with_Eport(k_pf, e_pf, true);
  }

  //----------------------------------------------------
  // path-5

  k_pf = { PORT_63, true };
  d_pf = { PORT_64 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_63, false };
  d_pf = { PORT_64 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_64, false };
  d_pf = { PORT_63 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_64, true };
  if (isDirectPortFwd) {
    d_pf = { PORT_63};
    portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);
  } else {
    e_pf = { PORT_63, PORT_59 };
    portFwd_entry_add_modify_with_Eport(k_pf, e_pf, true);
  }

  //----------------------------------------------------
  // isDpdkMarkerMode ? path-1 : path-2

  k_pf = { PORT_27, true };
  d_pf = { isDpdkMarkerMode ? PORT_28 : PORT_62 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { PORT_27, false };
  d_pf = { isDpdkMarkerMode ? PORT_28 : PORT_62 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { isDpdkMarkerMode ? PORT_28 : PORT_62, false };
  d_pf = { PORT_27 };
  portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);

  k_pf = { isDpdkMarkerMode ? PORT_28 : PORT_62, true };
  if (isDirectPortFwd) {
    d_pf = { PORT_27};
    portFwd_entry_add_modify_with_Direct(k_pf, d_pf, true);
  } else {
    e_pf = { PORT_27, PORT_59 };
    portFwd_entry_add_modify_with_Eport(k_pf, e_pf, true);
  }

  //----------------------------------------------------

  k_pf = { PORT_60, true };
  portFwd_entry_add_modify_with_Get_Eport(k_pf, true);
}
*/

void t_logger(uint64_t ctv1, uint64_t ctv2, uint64_t vq1, uint64_t vq2) {
//  return;
  auto tnow = std::chrono::system_clock::now();
  auto tnow_time = std::chrono::duration_cast<std::chrono::milliseconds>(tnow.time_since_epoch()).count();
  if(f == NULL)
    f = fopen("/home/netcom/ctv.log", "w");
  
  if((tnow - logtime) > 10ms) {
	  if(log_n > 0) {
	    log_vq1mean = log_vq1mean / log_n;
	    log_vq2mean = log_vq2mean / log_n;
	  }

	  //TODO: proper file handling
	  fprintf(f, "%lf %lu %lu %lf %lf %lu %lu %lf %lf %lf %lf %lf %lf %lf %lf %lu %lf %lf %lu %lu %lf %lf %lf %lf %f %f %lf %lf %lf %lf %lf %lf %f %f %lf %lf %lf %lf %ld %ld %ld\n", tnow_time/1000.0,
			  ctv1, ctv2, vq1/capacity, vq2/capacity,
			  log_ctv1max, log_ctv2max, log_vq1max/capacity, log_vq2max/capacity,
			  log_vq1mean/capacity, log_vq2mean/capacity, 1.0*stat_in_cl/updateTimeInSec, 1.0*stat_in_l4s/updateTimeInSec,
			  1.0*stat_drop_cl/updateTimeInSec, 1.0*stat_drop_l4s/updateTimeInSec, stat_ecn_ce,
			  stat_lat_cl/capacity, stat_lat_l4s/capacity,
			  //0.001*stat_lat2_cl, 0.001*stat_lat2_l4s,
			  log_ctv1min, log_ctv2min, log_vq1min/capacity, log_vq2min/capacity,
			  log_hist_delta_max, log_digest_delta_max, log_pr_l4s, log_pr_cl, pq[0]/capacity, pq[1]/capacity,log_pq1max/capacity, log_pq2max/capacity, log_pq1min/capacity, log_pq2min/capacity, log_ppr_l4s, log_ppr_cl, 1.0*stat_out_cl/updateTimeInSec, 1.0*stat_sel_rate, 0.001*stat_lat2_cl, 0.001*stat_lat2_l4s, stat_tm_drop, stat_ctm_drop, stat_pktin); //1.0*stat_out_l4s/updateTimeInSec);
	  //printf("%lu %lu %lu %lu\n",stat_in_cl, stat_out_cl, stat_in_l4s, stat_out_l4s);
	  
	  fflush(f);
	  logtime = tnow;
	  log_ctv1max = log_ctv2max = log_vq1max = log_vq2max = log_pq1max = log_pq2max = 0;
	  log_vq1mean = log_vq2mean = log_n = 0;
	  log_hist_delta_max = 0.0;
	  log_digest_delta_max = 0.0;
  }
  if (log_n==0) {
	  log_ctv1min = ctv1;
	  log_ctv2min = ctv2;
	  log_vq1min = vq1;
	  log_vq2min = vq2;
	  log_pq1min = pq[0];
	  log_pq2min = pq[1];
  }
  else {
	  log_ctv1min = std::min(log_ctv1min, ctv1);
	  log_ctv2min = std::min(log_ctv2min, ctv2);
	  log_vq1min = std::min(log_vq1min, vq1);
	  log_vq2min = std::min(log_vq2min, vq2);
	  log_pq1min = std::min(log_pq1min, pq[0]);
          log_pq2min = std::min(log_pq2min, pq[1]);
  }
  log_ctv1max = std::max(log_ctv1max, ctv1);
  log_ctv2max = std::max(log_ctv2max, ctv2);
  log_vq1max = std::max(log_vq1max, vq1);
  log_vq2max = std::max(log_vq2max, vq2);
  log_pq1max = std::max(log_pq1max, pq[0]);
  log_pq2max = std::max(log_pq2max, pq[1]);
  log_vq1mean = log_vq1mean + vq1;
  log_vq2mean = log_vq2mean + vq2;
  log_n += 1;
}

void reset_tables() {
  // Reset tables
  auto status = igPpvTable->tableClear(*session, dev_tgt);
  assert(status == BF_SUCCESS);

  status = egPpvFilterTable->tableClear(*session, dev_tgt);
  assert(status == BF_SUCCESS);

//  status = portFwdTable->tableClear(*session, dev_tgt);
//  assert(status == BF_SUCCESS);

  session->sessionCompleteOperations();
  return;
}

void get_histogram() {

  auto flag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_SW;
  // TODO: this should be done with get using the idx as key
  auto bf_status = pvhistTable->tableEntryGetFirst(
      *session, dev_tgt, flag, keys[0].get(), data[0].get());
  assert(bf_status == BF_SUCCESS);
  session->sessionCompleteOperations();

  //printf("Having the first element.\n");

  uint32_t num_returned = 0;
  bf_status = pvhistTable->tableEntryGetNext_n(*session,
                                                dev_tgt,
                                                *keys[0].get(),
                                                2047,
                                                flag,
                                                &key_data_pairs,
                                                &num_returned);
  assert(bf_status == BF_SUCCESS);
  assert(num_returned == 2047);
  session->sessionCompleteOperations();

  return;
}

void get_stats() {
   auto flag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW;
   uint64_t val = 0;
   auto bf_status = cntinTable->tableEntryGet(*session, dev_tgt, *(cntin_keys[0]), flag,  cntin_data[0].get());
   cntin_data[0]->getValue(cntin_key_field_id, &val);
   /* Process val */
   stat_in_cl = val - stat_cin_cl;
   stat_cin_cl = val;
   bf_status = cntinTable->tableEntryGet(*session, dev_tgt, *(cntin_keys[1]), flag,  cntin_data[1].get());
   cntin_data[1]->getValue(cntin_key_field_id, &val);
   /* Process val */
   stat_in_l4s = val - stat_cin_l4s;
   stat_cin_l4s = val;

   bf_status = cntoutTable->tableEntryGet(*session, dev_tgt, *(cntout_keys[0]), flag,  cntout_data[0].get());
   cntout_data[0]->getValue(cntout_key_field_id, &val);
   /* Process val */
   stat_out_cl = val - stat_cout_cl;
   stat_cout_cl = val;
   bf_status = cntoutTable->tableEntryGet(*session, dev_tgt, *(cntout_keys[1]), flag,  cntout_data[1].get());
   cntout_data[1]->getValue(cntout_key_field_id, &val);
   /* Process val */
   stat_out_l4s = val - stat_cout_l4s;
   stat_cout_l4s = val;

   bf_status = cntdropTable->tableEntryGet(*session, dev_tgt, *(cntdrop_keys[0]), flag,  cntdrop_data[0].get());
   cntdrop_data[0]->getValue(cntdrop_key_field_id, &val);
   /* Process val */
   stat_drop_cl = val - stat_cdrop_cl;
   stat_cdrop_cl = val;
   bf_status = cntdropTable->tableEntryGet(*session, dev_tgt, *(cntdrop_keys[1]), flag,  cntdrop_data[1].get());
   cntdrop_data[1]->getValue(cntdrop_key_field_id, &val);
   /* Process val */
   stat_drop_l4s = val - stat_cdrop_l4s;
   stat_cdrop_l4s = val;

   bf_status = reglatencyTable->tableEntryGet(*session, dev_tgt, *(reglatency_keys[0]), flag,  reglatency_data[0].get());
   assert(bf_status == BF_SUCCESS);
   std::vector<uint64_t> sum;
   reglatency_data[0]->getValue(reglatency_key_field_id, &sum);
   int vlen = sum.size();
   val = sum[vlen-1] + sum[vlen-2] + sum[vlen-3] + sum[vlen-4];
   /* Process val */
   stat_lat_cl = val*80;
//   printf("val %lu\n", val);
   sum.clear();
   bf_status = reglatencyTable->tableEntryGet(*session, dev_tgt, *(reglatency_keys[1]), flag,  reglatency_data[1].get());
   reglatency_data[1]->getValue(reglatency_key_field_id, &sum);
   vlen = sum.size();
   val = sum[vlen-1] + sum[vlen-2] + sum[vlen-3] + sum[vlen-4];
   //val = sum[0] + sum[1] + sum[2] + sum[3];
   /* Process sum */
   stat_lat_l4s = val*80;

   pq[0] = stat_lat_l4s;
   pq[1] = stat_lat_cl;

   bf_status = reglatency2Table->tableEntryGet(*session, dev_tgt, *(reglatency2_keys[0]), flag,  reglatency2_data[0].get());
   assert(bf_status == BF_SUCCESS);
   std::vector<uint64_t> sum2;
   reglatency2_data[0]->getValue(reglatency2_key_field_id, &sum2);
   int vlen2 = sum2.size();
   val = sum2[vlen2-1] + sum2[vlen2-2] + sum2[vlen2-3] + sum2[vlen2-4];
   /* Process val */
   stat_lat2_cl = val;
//   printf("val %lu\n", val);
   sum2.clear();
   bf_status = reglatency2Table->tableEntryGet(*session, dev_tgt, *(reglatency2_keys[1]), flag,  reglatency2_data[1].get());
   reglatency2_data[1]->getValue(reglatency2_key_field_id, &sum2);
   vlen2 = sum2.size();
   val = sum2[vlen2-1] + sum2[vlen2-2] + sum2[vlen2-3] + sum2[vlen2-4];
   //val = sum[0] + sum[1] + sum[2] + sum[3];
   /* Process sum */
   stat_lat2_l4s = val;

   bf_status = cntecnTable->tableEntryGet(*session, dev_tgt, *cntecn_key, flag,  cntecn_data.get());
   cntecn_data->getValue(cntecn_key_field_id, &val);
   /* Process val */
   stat_ecn_ce = val - stat_cecn_ce;
   stat_cecn_ce = val;

   bf_status = sel_rateTable->tableEntryGet(*session, dev_tgt, *(sel_rate_keys), flag,  sel_rate_data.get());
   assert(bf_status == BF_SUCCESS);
   std::vector<uint64_t> sumr;
   sel_rate_data->getValue(sel_rate_key_field_id, &sumr);
   int vlenr = sumr.size();
   val = sumr[vlenr-1] + sumr[vlenr-2] + sumr[vlenr-3] + sumr[vlenr-4];
   /* Process val */
   stat_sel_rate = val/0.01;

   
   bf_status = pktinTable->tableEntryGet(*session, dev_tgt, *pktin_key, flag,  pktin_data.get());
   pktin_data->getValue(pktin_key_field_id, &val);
   
   uint64_t val2 = 0;
   bf_status = pktoutTable->tableEntryGet(*session, dev_tgt, *pktout_key, flag,  pktout_data.get());
   pktout_data->getValue(pktout_key_field_id, &val2);
   stat_tm_drop = (long int)val - (long int)pktin_old - ((long int)val2 -(long int)pktout_old);
   stat_ctm_drop += stat_tm_drop;
   stat_pktin = (long int)val - (long int)pktin_old;
   pktin_old = val;
   pktout_old = val2;

//   stat_ctm_drop += (long int)stat_in_cl-(long int)stat_out_cl + (long int)stat_in_l4s-(long int)stat_out_l4s;// - (long int)stat_drop_cl;
}



std::chrono::time_point<std::chrono::steady_clock> startT;
//std::chrono::time_point<std::chrono::steady_clock> lastT;

void cnt_cb(const bf_rt_target_t &dev_tgt, void* cookie) {
//  auto endT = std::chrono::steady_clock::now();
//  std::chrono::time_point<std::chrono::steady_clock> sT = *(std::chrono::time_point<std::chrono::steady_clock>*)cookie;
//  log_hist_delta_max = std::max(log_hist_delta_max, 1.0*std::chrono::duration_cast<std::chrono::milliseconds>(endT-sT).count()/1000.0);
  get_histogram();
  //update_hist();
  hist_mtx.unlock();
}

void update_pv() {
  hist_mtx.lock();

  std::unique_ptr<BfRtTableOperations> table_ops = nullptr;
  auto status = pvhistTable->operationsAllocate(TableOperationsType::COUNTER_SYNC, &table_ops);
  assert(status == BF_SUCCESS);
  startT = std::chrono::steady_clock::now();
  void *cookie = (void*) &startT;
  status = table_ops->counterSyncSet(*session, dev_tgt, cnt_cb, cookie);
  assert(status == BF_SUCCESS);

  status = pvhistTable->tableOperationsExecute(*table_ops.get());
  assert(status == BF_SUCCESS);
  session->sessionCompleteOperations();
}

//TODO: t_logger for grafana
void update_hist() {

  uint64_t hist[2][1024];
  uint64_t incoming_bytes[2] = { 0, 0 };
  uint64_t _hctv[2] = {0,0};

  for(int iQ = 0; iQ < 2; ++iQ) {
    for(int iH = 0; iH < 1024; ++iH) {
      uint64_t new_value;
      data[iQ * 1024 + iH]->getValue(counter_spec_bytes_field_id, &new_value);
      hist[iQ][iH] = safe_sub_hist(new_value, last_hist[iQ][iH]);
      last_hist[iQ][iH] = new_value;
      if(iQ == 1) { //classic
	hist[iQ][iH] += hist[0][iH];
      }
      if (_hctv[iQ]==0) {
	      _hctv[iQ] = 1;
	      hctv[iQ] = iH;
      }
      incoming_bytes[iQ] += hist[iQ][iH];
    }
  }

  pers_mtx.lock();
  memcpy(pers_hist, hist, sizeof(hist));
  memcpy(pers_incoming_bytes, incoming_bytes, sizeof(incoming_bytes));
  pers_mtx.unlock();
}

double process_red(double current, double minTh, double maxTh, double maxPr) {
	double pr_mark = (current-minTh) / (maxTh-minTh);
	if (pr_mark<0) {
		pr_mark=0;
	} else if (pr_mark > maxPr) {
		pr_mark=maxPr;
	}
	return pr_mark;
}

void find_quantiles(const int n, int iQ, double* p, uint64_t* pv) {
  uint64_t l_mark[n];
  for (int i=0; i<n; i++) {
    l_mark[i]=static_cast<uint64_t>(pers_incoming_bytes[iQ] * p[i]);
    pv[i]=1024;
  }
  uint64_t sumbytes = 0;
  int n_found = 0;

  int iH;
  for(iH = 0; iH < 1023; iH++) { 
    sumbytes += pers_hist[iQ][iH];
    for (int i=0; i<n; i++) 
	  if (pv[i]==1024 && sumbytes >= l_mark[i]) {
	    pv[i]=iH;
	    n_found++;
	  }
    if (n_found >= n) break;
  }
}

//update_ctv_sz1
void update_ctv_sz1() {
  pers_mtx.lock();
  for(int iQ = 0; iQ < 2; ++iQ) {
    if(pers_incoming_bytes[iQ] < 10000)
      continue;

 	// For VQs
	double pr_mark = process_red(vq[iQ],vq_target[iQ],vq_target[iQ]*7,0.75);
	double pr_mark_l4s = process_red(vq[iQ],0,vq_target[iQ]*6,0.75);

	// For PQs
	//
    //double ppr_mark = process_red(pq[iQ],pq_target[iQ]/2,pq_target[iQ]*7,0.75); 
	if (pq[iQ] > pq_target[iQ]) ppr_mark = std::min(0.75, ppr_mark + 0.05);
	else if ( pq[iQ] < pq_target[iQ]/2) ppr_mark = 0;
	
	//FIXME
	//ppr_mark =0;
	
    if (iQ==0) log_pr_l4s = pr_mark;
    else log_pr_cl = pr_mark;
    if (iQ==0) log_ppr_l4s = ppr_mark;
    else log_ppr_cl = ppr_mark;

    //if (ppr_mark > pr_mark) pr_mark = ppr_mark;
    //if (ppr_mark > pr_mark_l4s) pr_mark_l4s = ppr_mark;
	
    if(pr_mark_l4s == 0) {
      if ((iQ==1) && (vq[iQ]==0)) ctv[iQ] = 0;
      if (iQ==0) ctv[iQ] = 0;
      continue;
    }
	
	pr_mark = std::min(pr_mark+ppr_mark,0.75);
	pr_mark_l4s = std::min(pr_mark_l4s+ppr_mark,0.75);
	//FIXME
	pr_mark = std::max(0.0,pr_mark_l4s-0.1); 

    uint64_t l_mark = static_cast<uint64_t>(pers_incoming_bytes[iQ] * pr_mark);
    uint64_t l_mark_l4s = static_cast<uint64_t>(pers_incoming_bytes[iQ] * pr_mark_l4s);
    uint64_t sumbytes = 0;

	ctv[iQ]=1024;
	ctv[iQ+2]=1024;
	
    int iH;
    for(iH = 0; iH < 1023; iH++) { 
      sumbytes += pers_hist[iQ][iH];
      if (ctv[iQ]==1024 && sumbytes >= l_mark) ctv[iQ] = iH;
	  if (ctv[iQ+2]==1024 && sumbytes >= l_mark_l4s) ctv[iQ+2] = iH;
    }
  }
  
  pers_mtx.unlock();
  t_logger(ctv[0], ctv[1], vq[0], vq[1]);
}

void update_ctv_ratio() {
  pers_mtx.lock();
  for(int iQ = 0; iQ < 2; ++iQ) {
    //if(pers_incoming_bytes[iQ] < 10000)
    //  continue;
        
	double pr_mark = 0;
	if (rates[iQ] > cv[iQ])
		pr_mark = 1.0 - cv[iQ]/rates[iQ];

   // printf("%d %f %f %f %u %u\n", iQ, cv[iQ],rates[iQ],pr_mark, stat_in_cl, stat_drop_cl);
    if (iQ==0) log_pr_l4s = pr_mark;
    else log_pr_cl = pr_mark;

    if(pr_mark == 0) {
	  ctv[iQ] = 0;
      continue;
    }

    uint64_t l_mark = static_cast<uint64_t>(pers_incoming_bytes[iQ] * pr_mark);
    uint64_t sumbytes = 0;

//    if (l_mark==0)
//	    continue;
    ctv[iQ]=1024;
	
    int iH;
    for(iH = 0; iH < 1023; iH++) { 
      sumbytes += pers_hist[iQ][iH];
      if (ctv[iQ]==1024 && sumbytes > l_mark) {
		  ctv[iQ] = iH;
		  break;
      }
    }
    if (sumbytes==0) ctv[iQ] = 0;
//    if (vq[iQ]==0) ctv[iQ] = 0;
  }
  ctv[0] = ctv[1]; 
  if (ctv[0] > 1022) {
//	  printf("%lu %f %f %lu %f %lu\n", ctv[0], cv[0], rates[0], vq[0], vq_target[0], pers_incoming_bytes[0]);
//          printf("%lu %f %f %lu %f %lu\n", ctv[1], cv[1], rates[1], vq[1], vq_target[1], pers_incoming_bytes[1]);


	  ctv[0] = ctv[1] = 900;
  }
  pers_mtx.unlock();
  t_logger(ctv[0], ctv[1], vq[0], vq[1]);
}



//update_ctv_anrw20
void update_ctv_anrw20() {
  pers_mtx.lock();
  for(int iQ = 0; iQ < 2; ++iQ) {
    if(pers_incoming_bytes[iQ] < 10000)
      continue;
        
	double pr_mark = 0;
	if (vq[iQ] > vq_target[iQ])
		pr_mark = 1 - vq_target[iQ] / static_cast<double>(vq[iQ]);


	// For PQs
	double ppr_mark = 0;
	//ppr_mark = process_red(pq[iQ],pq_target[iQ]/2,pq_target[iQ]*7,0.75);
	
    if (iQ==0) log_pr_l4s = pr_mark;
    else log_pr_cl = pr_mark;
    if (iQ==0) log_ppr_l4s = ppr_mark;
    else log_ppr_cl = ppr_mark;

    if (ppr_mark > pr_mark) pr_mark = ppr_mark;
	
    if(pr_mark == 0) {
	  ctv[iQ] = 0;
      continue;
    }

    uint64_t l_mark = static_cast<uint64_t>(pers_incoming_bytes[iQ] * pr_mark);
    uint64_t sumbytes = 0;
	
	ctv[iQ]=1024;
	
    int iH;
    for(iH = 0; iH < 1023; iH++) { 
      sumbytes += pers_hist[iQ][iH];
      if (ctv[iQ]==1024 && sumbytes >= l_mark) {
		  ctv[iQ] = iH;
		  break;
	  }
    }
  }
  
  pers_mtx.unlock();
  t_logger(ctv[0], ctv[1], vq[0], vq[1]);
}

//update_ctv_red2
void update_ctv() {
  pers_mtx.lock();
  for(int iQ = 0; iQ < 2; ++iQ) {
    if(pers_incoming_bytes[iQ] < 10000)
      continue;
        
	double pr_mark = process_red(vq[iQ],vq_target[iQ],vq_target[iQ]*7,0.75);
    double ppr_mark = 0;
	//ppr_mark = process_red(pq[iQ],pq_target[iQ]/2,pq_target[iQ]*7,0.75);
	
    if (iQ==0) log_pr_l4s = pr_mark;
    else log_pr_cl = pr_mark;
    if (iQ==0) log_ppr_l4s = ppr_mark;
    else log_ppr_cl = ppr_mark;

    if (ppr_mark > pr_mark) pr_mark = ppr_mark;
	
    if(pr_mark == 0) {
      ctv[iQ] = 0;
      continue;
    }

	find_quantiles(1,iQ, &pr_mark, &(ctv[iQ]));
  }
  
  pers_mtx.unlock();
  t_logger(ctv[0], ctv[1], vq[0], vq[1]);
}

//update_ctv_red
void update_ctv_red() {
  pers_mtx.lock();
  for(int iQ = 0; iQ < 2; ++iQ) {
    if(pers_incoming_bytes[iQ] < 10000)
      continue;
        
    double ppr_mark = 0;
	double pr_mark = 0;
	
	/*if (vq[iQ] <= vq_target[iQ]) {
		 
		//pr_mark = 1 - (static_cast<double>(vq[iQ]) - vq_target[iQ]/2) / vq_target[iQ] *2 * 1e-3;
		pr_mark = 1 - static_cast<double>(vq[iQ]) / vq_target[iQ] * 1e-3;
		
	} else {
	*/

//	if (vq[iQ] > vq_target[iQ])
//		pr_mark = 1 - vq_target[iQ] / static_cast<double>(vq[iQ]);
	/*
	}*/

 	// For VQs
	double mind=vq_target[iQ]/2;
	double maxd=vq_target[iQ]*7;
	pr_mark =  (vq[iQ]-mind) / (maxd-mind);
	if (pr_mark <0) {
		pr_mark =0;
	} else if (pr_mark > 0.75) {
		pr_mark =0.75;
	}

	// For PQs
	mind = pq_target[iQ]/2;
	maxd = pq_target[iQ]*7;
	ppr_mark = (pq[iQ]-mind) / (maxd-mind);
	if (ppr_mark <0) {
		ppr_mark =0;
	} else if (ppr_mark > 0.75) {
		ppr_mark =0.75;
	}
	//FIXME
	ppr_mark =0;
	
	
    if (iQ==0) log_pr_l4s = pr_mark;
    else log_pr_cl = pr_mark;
    if (iQ==0) log_ppr_l4s = ppr_mark;
    else log_ppr_cl = ppr_mark;

    if (ppr_mark > pr_mark) pr_mark = ppr_mark;
	
    if(pr_mark == 0) {
      if ((iQ==1) && (vq[iQ]==0)) ctv[iQ] = 0;
      if (iQ==0) ctv[iQ] = 0;
//      if (ctv[iQ]>0) 
//	      ctv[iQ] = ctv[iQ] - 1; //0;
      continue;
    }
	
	// HACK: now back to old definition
	pr_mark	= 1 - pr_mark;

    double l_mark = pers_incoming_bytes[iQ] * pr_mark;
    uint64_t sumbytes = 0;

    int iH;
    for(iH = 1023; iH > 0; --iH) { //TODO: > 0 ??
      sumbytes += pers_hist[iQ][iH];
      if(sumbytes >= static_cast<uint64_t>(l_mark))
        break;
    }
    ctv[iQ] = iH;
/*    if (iH>ctv[iQ])	ctv[iQ] = iH;
    else if (ctv[iQ]>0)	ctv[iQ] -= 1;*/
  }
  pers_mtx.unlock();
  t_logger(ctv[0], ctv[1], vq[0], vq[1]);
}


bf_status_t learn_callback(const bf_rt_target_t &bf_rt_tgt,
                           const std::shared_ptr<BfRtSession> session,
                           std::vector<std::unique_ptr<BfRtLearnData>> vec,
                           bf_rt_learn_msg_hdl *const learn_msg_hdl,
                           const void *cookie) {
  /***********************************************************
   * INSERT CALLBACK IMPLEMENTATION HERE
   **********************************************************/

  // Extract learn data fields from Learn Data object and use it as needed.
  if (!learn_obj) return SWITCH_STATUS_FAILURE;

  // smi::bf_rt::start_batch();
  int i = 0;
  for (auto const &digest : vec) {
    const uint64_t zero = 0;
    uint64_t vql4s = 0, vqcl = 0;
    uint64_t ts = 0;
    uint64_t drainpq;
    uint64_t drop;

    digest->getValue(learn_vql4s_field_id, &vql4s);
    digest->getValue(learn_vqcl_field_id, &vqcl);
    digest->getValue(learn_ts_field_id, &ts);
    digest->getValue(learn_drop_field_id, &drop);

    if (i==1) printf("multiple digest_%lu\n", ts-lastts);
    i++;

    double delta = (ts - lastts) / 1000000000.0;
    log_digest_delta_max = std::max(log_digest_delta_max, delta);
    if(delta < 0.0) {
      printf("impossible\n");    
      continue;
    }
    if(delta > 1.0) {
      printf("gap impossible %f - reset VQs\n", delta);
      inst_vq[0] = 0;
      inst_vq[1] = 0;
      lastts = ts;
      continue;
    }
    uint64_t oldtmp = lastvq[1];
    uint64_t ibl4s = safe_sub_vqlen(vql4s, lastvq[0]);
    uint64_t ibcl = safe_sub_vqlen(vqcl, lastvq[1]);
    uint64_t dropped = safe_sub_vqlen(drop, lastdrop);
    /*pq[0] += ibl4s;
    pq[1] += ibcl;
    drainpq = delta * capacity;
    if (pq[0]>=drainpq) {
	    pq[0] -= drainpq;
    }
    else {
	    drainpq -= pq[0];
	    pq[0] = 0;
	    if (pq[1]>=drainpq) pq[1] -= drainpq;
	    else pq[1] = 0; 
    }*/
    lastvq[0] = vql4s;
    lastvq[1] = vqcl;
    lastdrop = drop;
    lastts = ts;
    /*inst_vq[0] += ibl4s;
    inst_vq[1] += ibcl;
    drainpq = delta * capacity * vq_srate;
    if (inst_vq[0]>=drainpq) {
            inst_vq[0] -= drainpq;
    }
    else {
            drainpq -= inst_vq[0];
            inst_vq[0] = 0;
            if (inst_vq[1]>=drainpq) inst_vq[1] -= drainpq;
            else inst_vq[1] = 0;
    }
    */

    ibcl += ibl4s;
    //printf("BEFORE: delta: %lf, vql4s: %lu, vqcl: %lu vq1: %lu vq2: %lu vq1/cap: %lf ibl4s: %lu\n", delta, vql4s, vqcl, vq[0], vq[1], vq[0]/capacity, ibl4s);
    if(inst_vq[0] + ibl4s > (delta * cv[0]))
      inst_vq[0] = inst_vq[0] + ibl4s - (uint64_t)(delta * cv[0]);
    else
    {
      //printf("zerovq0 %lu %lu %lf %lu\n", vq[0], ibl4s, delta, (uint64_t)(delta * cv[0]));
      inst_vq[0] = 0; //(1.0-EWMA_ALPHA)*vq[0];//0;
    }
//    vq[0] = std::max(zero, (vq[0] + ibl4s - (uint64_t)(delta * cv[0])));
    if(inst_vq[1] + ibcl > (delta * cv[1]))
      inst_vq[1] = inst_vq[1] + ibcl - (uint64_t)(delta * cv[1]);
    else
    {
      //printf("zerovq1 %lu %lu %lf %lu %lu %lu\n", vq[1], ibcl, delta, (uint64_t)(delta * cv[1]), oldtmp, vqcl);
      inst_vq[1] = 0; //(1.0-EWMA_ALPHA)*vq[1];
    }
//    vq[1] = std::max(zero, static_cast<uint64_t>(vq[1] + ibcl - delta * cv[1]));
    //printf("AFTER: delta: %lf, vql4s: %lu, vqcl: %lu vq1: %lu vq2: %lu vq1/cap: %lf\n", delta, vql4s, vqcl, vq[0], vq[1], vq[0]/capacity);
    
    ewma_vq[0] = EWMA_ALPHA*inst_vq[0] + (1.0-EWMA_ALPHA)*(ewma_vq[0]);
    ewma_vq[1] = EWMA_ALPHA*inst_vq[1] + (1.0-EWMA_ALPHA)*(ewma_vq[1]);
    if (inst_vq[0]>ewma_vq[0]) ewma_vq[0] = inst_vq[0];
    if (inst_vq[1]>ewma_vq[1]) ewma_vq[1] = inst_vq[1];


    vq[0] = inst_vq[0]; //std::max(ewma_vq[0], inst_vq[0]);
    vq[1] = inst_vq[1]; //std::max(ewma_vq[0], inst_vq[0]);

//    rates[0] = 0.875*rates[0] + 0.125*(double)ibl4s/delta; //inst_vq[0]; //std::max(ewma_vq[0], inst_vq[0]);
//    rates[1] = 0.875*rates[1] + 0.125*(double)ibcl/delta; //inst_vq[1]; //std::max(ewma_vq[1], inst_vq[1]);
    rates[0] = (double)ibl4s/delta; //inst_vq[0]; //std::max(ewma_vq[0], inst_vq[0]);
    if (vq[1]>(uint64_t)(vq_target[1])) {
       ibcl += vq[1] - (uint64_t)vq_target[1];
    }
//    if (dropped > 0)
//	    printf("----------------DROPPED %u %u %f %f\n", dropped, ibcl, (double)ibcl/delta, (double)dropped/delta);
    ibcl += dropped;
    rates[1] = (double)ibcl/delta; //inst_vq[1]; //std::max(ewma_vq[1], inst_vq[1]);
    //rates[1] = 0.875*rates[1] + 0.125*(double)ibcl/delta; //inst_vq[1]; //std::max(ewma_vq[1], inst_vq[1]);
//    if (rates[1]>cv[1]) printf("%lu %f %f\n", ibcl, rates[1], delta );

  }

  //Locking is important (digest and ctv calc race!)
  if (!taildrop_mode) {
	  update_ctv_ratio();
  } else {
	  t_logger(ctv[0], ctv[1], vq[0], vq[1]);
  }
  set_ctvs(PORT_5, ctv[0], ctv[1], ctv[3]);

  // smi::bf_rt::end_batch();


  /*********************************************************
  * WHEN DONE, ACK THE learn_msg_hdl
  ********************************************************/
  (void)bf_rt_tgt;
  (void)vec;
  (void)cookie;
//  printf("Learn callback invoked\n");
  auto bf_status = learn_obj->bfRtLearnNotifyAck(session, learn_msg_hdl);
  assert(bf_status == BF_SUCCESS);
  return BF_SUCCESS;
}

}  // ppv_egress_demo_marker
}  // elte
}  // bfrt

static void parse_options(bf_switchd_context_t *switchd_ctx,
                          int argc,
                          char **argv) {
  int option_index = 0;
  enum opts {
    OPT_INSTALLDIR = 1,
    OPT_CONFFILE,
    OPT_CAPACITY,
  };
  static struct option options[] = {
      {"help", no_argument, 0, 'h'},
      {"install-dir", required_argument, 0, OPT_INSTALLDIR},
      {"conf-file", required_argument, 0, OPT_CONFFILE},
      {"taildrop", no_argument, 0, 't'},
      {"direct-port-forward", no_argument, 0, 'd'},
      {"dpdk-marker", no_argument, 0, 'm'},
      {"capacity", required_argument, 0, OPT_CAPACITY},
      {NULL, 0, NULL, 0}   /* Required at end of array.*/
  };

  while (1) {
    int c = getopt_long(argc, argv, "h", options, &option_index);

    if (c == -1) {
      break;
    }
    switch (c) {
      case OPT_INSTALLDIR:
        switchd_ctx->install_dir = strdup(optarg);
        printf("Install Dir: %s\n", switchd_ctx->install_dir);
        break;
      case OPT_CONFFILE:
        switchd_ctx->conf_file = strdup(optarg);
        printf("Conf-file: %s\n", switchd_ctx->conf_file);
        break;
      case 't':
        printf("Using taildrop");
        bfrt::elte::ppv_egress_demo_marker::taildrop_mode = true;
        bfrt::elte::ppv_egress_demo_marker::qid_l4s = 0;
        bfrt::elte::ppv_egress_demo_marker::qid_cl = 0;
        break;
      case 'd':
        printf("Port forward set to direct");
        bfrt::elte::ppv_egress_demo_marker::isDirectPortFwd = true;
        break;
      case 'm':
        printf("Using DPDK marker");
        bfrt::elte::ppv_egress_demo_marker::isDpdkMarkerMode = true;
        break;
      case OPT_CAPACITY:
        bfrt::elte::ppv_egress_demo_marker::config_capacity(atof(optarg));
        printf("Capacity: %f\n", bfrt::elte::ppv_egress_demo_marker::capacityGbps);
        break;
      case 'h':
      case '?':
        printf("Ctrl plane for ppvwc_single \n");
        printf(
            "Usage : ppv-ctrl --install-dir <path to where the SDE is "
            "installed> --conf-file <full path to the conf file "
            "(ppvwc_single.conf)> [--taildrop]"
            "[--direct-port-forward]"
            "[--dpdk-marker]"
            "--capacity <capacity in Gb/s>"
            "\n");
        exit(c == 'h' ? 0 : 1);
        break;
      default:
        printf("Invalid option\n");
        exit(0);
        break;
    }
  }
  if (switchd_ctx->install_dir == NULL) {
    printf("ERROR : --install-dir must be specified\n");
    exit(0);
  }

  if (switchd_ctx->conf_file == NULL) {
    printf("ERROR : --conf-file must be specified\n");
    exit(0);
  }
}

static void
signal_load_policy(int signum)
{
  bfrt::elte::ppv_egress_demo_marker::load_policy_trigger = true;	
}

static void
signal_add_remove_policy(int signum)
{
}




int main(int argc, char **argv) {
  signal( SIGUSR1, signal_load_policy );
  bfrt::elte::ppv_egress_demo_marker::config_capacity();
  bfrt::elte::ppv_egress_demo_marker::f = NULL; //logfile

  bf_switchd_context_t *switchd_ctx;
  if ((switchd_ctx = (bf_switchd_context_t *)calloc(
           1, sizeof(bf_switchd_context_t))) == NULL) {
    printf("Cannot Allocate switchd context\n");
    exit(1);
  }
  parse_options(switchd_ctx, argc, argv);
  switchd_ctx->running_in_background = true;
  bf_status_t status = bf_switchd_lib_init(switchd_ctx);

  printf("Configuring switch ports...");
  fflush(stdout);
  std::this_thread::sleep_for(1s);
  //port-dis -/-	
  //port-del -/-
  bf_pal_front_port_handle_t hdl;
  hdl.conn_id = 2;
  hdl.chnl_id = 0;
  bf_pm_port_delete_all(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id);
  //port-add 2/0 10G NONE
  bf_pm_port_add(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, BF_SPEED_10G, BF_FEC_TYP_NONE);
  bf_pm_port_autoneg_set(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, PM_AN_FORCE_DISABLE);
  //port-add 2/1 10G NONE
  hdl.conn_id = 2;
  hdl.chnl_id = 1;
  bf_pm_port_add(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, BF_SPEED_10G, BF_FEC_TYP_NONE);
  bf_pm_port_autoneg_set(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, PM_AN_FORCE_DISABLE);
  //port-add 2/2 10G NONE
  hdl.conn_id = 2;
  hdl.chnl_id = 2;
  bf_pm_port_add(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, BF_SPEED_10G, BF_FEC_TYP_NONE);
  bf_pm_port_autoneg_set(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, PM_AN_FORCE_DISABLE);

  hdl.conn_id = 4;
  hdl.chnl_id = 0;
//  bf_pm_port_delete_all(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id);
  //port-add 4/- 40G NONE
  bf_pm_port_add(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, BF_SPEED_40G, BF_FEC_TYP_NONE);
  bf_pm_port_autoneg_set(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, PM_AN_FORCE_DISABLE);

  hdl.conn_id = 3;
  hdl.chnl_id = 0;
//  bf_pm_port_delete_all(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id);
  //port-add 3/- 40G NONE
  bf_pm_port_add(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, BF_SPEED_40G, BF_FEC_TYP_NONE);
  bf_pm_port_autoneg_set(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, PM_AN_FORCE_DISABLE);



  hdl.conn_id = 5;
  hdl.chnl_id = 0;
//  bf_pm_port_delete_all(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id);
  //port-add 5/- 100G RS
  bf_pm_port_add(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, BF_SPEED_100G, BF_FEC_TYP_RS);
  //port-add 6/- 100G RS
  hdl.conn_id = 6;
  hdl.chnl_id = 0;
  bf_pm_port_add(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, &hdl, BF_SPEED_100G, BF_FEC_TYP_RS);


  //port-enb -/-
  bf_pm_port_enable_all(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id);
  printf("Done.\n");


  printf("Setup TM and rate limiter on bottleneck port...");
  fflush(stdout);
  std::this_thread::sleep_for(1s);
  uint8_t qmap[2] = {0,1};
  p4_pd_tm_set_port_q_mapping(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 2, qmap);
  p4_pd_tm_set_q_sched_priority(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 0, 10);
  p4_pd_tm_set_q_sched_priority(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 1, 5);
//  if (bfrt::elte::ppv_egress_demo_marker::capacityGbps<100) {
  printf("BN Capacity: %f Gbps...", bfrt::elte::ppv_egress_demo_marker::capacityGbps);
  fflush(stdout);
	  p4_pd_tm_set_port_shaping_rate(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, false, 2*1548, int(1000400 * bfrt::elte::ppv_egress_demo_marker::capacityGbps )); //9216
//  }
  p4_pd_tm_enable_port_shaping(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5);
  if (bfrt::elte::ppv_egress_demo_marker::taildrop_mode) {
	  p4_pd_tm_set_q_guaranteed_min_limit(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 0, (int)(bfrt::elte::ppv_egress_demo_marker::vq_target[1]/80));
	  p4_pd_tm_set_q_guaranteed_min_limit(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 1, (int)(bfrt::elte::ppv_egress_demo_marker::vq_target[1]/80));
  }
  else {
  	p4_pd_tm_set_q_guaranteed_min_limit(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 0, 300000);
  	p4_pd_tm_set_q_guaranteed_min_limit(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 1, 300000);
  }
  p4_pd_tm_enable_q_tail_drop(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 0);
  p4_pd_tm_enable_q_tail_drop(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, PORT_5, 1);

  bf_drv_lrt_dr_timeout_set(bfrt::elte::ppv_egress_demo_marker::dev_tgt.dev_id, 1);
  printf("Done.\n");

  // Do initial set up
  bfrt::elte::ppv_egress_demo_marker::setUp();
  // Do table level set up
  bfrt::elte::ppv_egress_demo_marker::tableSetUp();
  // Do reset
  bfrt::elte::ppv_egress_demo_marker::reset_tables();

  bfrt::elte::ppv_egress_demo_marker::config_lpfs();

  bfrt::elte::ppv_egress_demo_marker::init_ctvs(PORT_5, 0, 0);

//  bfrt::elte::ppv_egress_demo_marker::set_portfwd();

  auto start_time = std::chrono::steady_clock::now();
  auto delta = std::chrono::milliseconds(int(bfrt::elte::ppv_egress_demo_marker::updateTimeInSec*1000)); // TODO: bound to updateTimeInSec
  auto ridx = 0;
  while(true) {
    auto now = std::chrono::steady_clock::now();

    //This call sync the histogram table, then
    //calculate the new histogram for the
    //digest callback's CTV calculation
    auto lastT = std::chrono::steady_clock::now();
    bfrt::elte::ppv_egress_demo_marker::update_pv();

    bfrt::elte::ppv_egress_demo_marker::hist_mtx.lock();
    bfrt::elte::ppv_egress_demo_marker::update_hist();
    bfrt::elte::ppv_egress_demo_marker::hist_mtx.unlock();

    auto histT = std::chrono::steady_clock::now();
    bfrt::elte::ppv_egress_demo_marker::log_hist_delta_max = std::max(bfrt::elte::ppv_egress_demo_marker::log_hist_delta_max, 1.0*std::chrono::duration_cast<std::chrono::milliseconds>(histT-lastT).count()/1000.0);
    bfrt::elte::ppv_egress_demo_marker::get_stats();
    if (ridx == 10) {
	    //bfrt::elte::ppv_egress_demo_marker::get_stats();
	    auto t2 = std::chrono::steady_clock::now();
	    ridx = 0;
	    std::cout << "Uptime: " << (now-start_time).count() << " hist.update: " << (t2-now).count() << std::endl;
    }

    std::this_thread::sleep_until(now + delta);
    ridx++;
    if (bfrt::elte::ppv_egress_demo_marker::load_policy_trigger)
	    bfrt::elte::ppv_egress_demo_marker::load_policy();
  }

  //auto end = std::chrono::steady_clock::now();
  //std::chrono::duration<double> elapsed_seconds = end-start;
  printf("Exit\n");

  return status;
}
