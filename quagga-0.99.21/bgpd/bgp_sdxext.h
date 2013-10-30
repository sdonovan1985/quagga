#ifndef __SDXEXT__
#define __SDXEXT__



#include "prefix.h"
#include "bgpd.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "str.h"
#include "log.h"
#include "routemap.h"
#include "buffer.h"
#include "sockunion.h"
#include "plist.h"
#include "thread.h"
#include "workqueue.h"
#include "bgp_table.h"
#include "bgp_advertise.h"
#include "bgp_aspath.h"
#include "bgp_attr.h"
#include "prefix.h"

#include <signal.h>
#include <time.h>
#include <pthread.h>


// #defines and globals
#define PROTOCOL_VERSION        1
#define SUPERSECRETLOGINSECRET  0xDFDFDFDF
#define NUM_CXNS 1
#define MISSED_KEEPALIVES 3
#define KEEPALIVE_TIMEOUT 10
#define PORTNUM 5555


// Enumerations

enum sdx_bgp_pdu_opcode
{
    SDX_BGP_LOGIN_REQUEST       = 0,
    SDX_BGP_LOGIN_RESPONSE      = 1,
    SDX_BGP_KEEPALIVE           = 2,
    SDX_BGP_REGISTER_AS         = 3,
    SDX_BGP_DEREGISTER_AS       = 4,
    SDX_BGP_REQUEST_ALL_ROUTES  = 5,
    SDX_BGP_UPDATE_LIST         = 6,

    // Still need the ones for sending new routes to server.
};

enum sdx_bgp_UD_or_WD
{
    SDX_BGP_UPDATE              = 0,
    SDX_BGP_WITHDRAWAL          = 1,
    SDX_BGP_CURRENT             = 2,
};


/* This is used down below, but is not something that's part of the PDU
 * structure, rather part of the "sdx_bgp_udpates" structure.
 */
struct sdx_bgp_update
{
    struct sdx_bgp_update* next;
    uint32_t as;
    // Should the source of the update be available? Should it be sent?
    enum sdx_bgp_UD_or_WD status;
    //uint32_t size_of_path;
    //char* path;        // don't forget to free this!
    struct attr* attr;
    struct prefix* prefix;
};

struct sdx_bgp_pdu
{
    enum sdx_bgp_pdu_opcode opcode;
    uint32_t send_sequence;
    uint32_t recv_sequence;
    uint32_t connection_id;
    uint32_t size;              // of the specifics below only!

    union
    {
        // Definitions follow
        struct sdx_bgp_login_request*       login_request;
        struct sdx_bgp_login_response*      login_response;
        struct sdx_bgp_keepalive*           keepalive;
        struct sdx_bgp_register_as*         register_as;
        struct sdx_bgp_deregister_as*       deregister_as;
        struct sdx_bgp_request_all_routes*  request_all_routes;
        struct sdx_bgp_update_list*         update_list;
    };
};

struct sdx_bgp_login_request
{
    uint32_t version;
    uint32_t secret;
};

struct sdx_bgp_login_response
{
    uint32_t version;
    uint32_t secret;
};

struct sdx_bgp_keepalive
{
    uint32_t ack_only;
};

struct sdx_bgp_register_as
{
    uint32_t as;
};

struct sdx_bgp_deregister_as
{
    uint32_t as;
};

struct sdx_bgp_request_all_routes
{
    uint32_t as;
};

struct sdx_bgp_update_list
{
    uint32_t size;
    struct sdx_bgp_update* update_list;

};

struct sdx_bgp_as_entry
{
    struct sdx_bgp_as_entry* prev;
    int entry;
    struct sdx_bgp_as_entry* next;
};

/*
 * Connection related structures
 */

struct sdx_bgp_connection
{
    uint32_t connection_id;
    uint32_t recv_sequence;
    uint32_t send_sequence;
    uint32_t version;
    int socket;
    // source IP?
    // dest IP?
    struct sockaddr remoteaddr;
    // source port?
    // dest port?
    // Socket Handle
    // connection secret
    // keepalive timer
    timer_t timer;
    // list of registered ASes?
    struct sdx_bgp_as_entry* as_list_head;
    struct sdx_bgp_as_entry* as_list_tail;
    // Watchlist of ASes being monitored
    // PDU pointer for outstanding message?
    // flags
    uint32_t secret;
    uint32_t missed_keepalives;
    struct sdx_bgp_pdu pdu_to_send;
    void* buffer_to_send;               // Allocated on demand based on pdu type
    void* update_list_to_send;          // Allocated when sending update lists
    int in_use;


};




/*
 * Logging function added to simplify display of routes
 */
void
sdxext_log_route (struct zlog* logger, struct prefix* p, char* hostname);

void
sdxext_log_peer (struct peer* peer, char* hostname);

/*
 * Initialization and handlers
 */

void
sdxext_init(void);

static void
sdxext_keepalive_timeout_handler(int sig, siginfo_t* si, void* uc);

void
sdxext_initialize_connections(void);

struct sdx_bgp_connection*
sdxext_handle_new_cxn(int socket, struct sockaddr* remoteaddr);

void
sdxext_new_route_received(char* route);

/*
 * Sending and receiving functions
 */


struct sdx_bgp_connection*
sdxext_lookup_connection(int socket);

struct sdx_bgp_connection*
sdxext_allocate_connection(void);

void
sdxext_free_connection(struct sdx_bgp_connection* cxn);

int
sdxext_restart_cxn_timer(struct sdx_bgp_connection* cxn);

int
sdxext_get_pdu_to_send_resources(struct sdx_bgp_connection* cxn,
                                 struct sdx_bgp_pdu* pdu,
                                 size_t pdu_specifics_size,
                                 void* pdu_specifics,
                                 size_t update_buffer_size,
                                 void* update_buffer);

int
sdxext_free_sent_pdu_resources(struct sdx_bgp_connection* cxn);


int
sdxext_receive_PDU(struct sdx_bgp_pdu* pdu, struct sdx_bgp_connection* cxn);

/*
 * AS list manipulation
 */

int
sdxext_register_AS(struct sdx_bgp_connection* cxn, int as);

int
sdxext_deregister_AS(struct sdx_bgp_connection* cxn, int as);

int
sdxext_is_AS_registered(struct sdx_bgp_connection* cxn, int as);

/*
 * PDU processing functions
 */
int
sdxext_process_login_request(struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu);

int
sdxext_process_keepalive (struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu);

int
sdxext_process_register_as (struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu);

int
sdxext_process_deregister_as (struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu);

int
sdxext_process_request_all_routes (struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu);



int
sdxext_build_and_send_login_response (struct sdx_bgp_connection* cxn);

int
sdxext_build_and_send_keepalive (struct sdx_bgp_connection* cxn,
                                 int ack_only);

int
sdxext_build_and_send_update_list (struct sdx_bgp_connection* cxn,
                                   struct sdx_bgp_update* update_list);

int
sdxext_send_packet(struct sdx_bgp_connection* cxn,
                   void* pointer_one, size_t size_of_pointer_one,
                   void* pointer_two, size_t size_of_pointer_two);

/*
 * Network thread
 */
void*
sdxext_network_thread(void* portnumvoid);

/*
 * Filtering functions
 */
int
sdxext_filter_does_cxn_care_about_route(struct sdx_bgp_connection* cxn,
                                        char* route);

int
sdxext_filter_from_assegment(struct sdx_bgp_connection* cxn,
                             struct assegment* segment);


/*
 * Fetching all the existing Routes
 */
int
sdxext_fetch_all_routes(struct sdx_bgp_connection* cxn,
                        struct sdx_bgp_update* update_list);

#endif // __SDXEXT__

