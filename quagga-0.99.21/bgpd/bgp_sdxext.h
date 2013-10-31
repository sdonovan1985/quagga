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
#define PROTOCOL_VERSION 1
#define NUM_CXNS 1
#define MISSED_KEEPALIVES 3
#define KEEPALIVE_TIMEOUT 10
#define PORTNUM 5555


// Enumerations



// Connection related structures

struct sdx_bgp_connection
{
    uint32_t in_use;
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
    uint32_t missed_keepalives;
    // list of registered ASes?
    // Watchlist of ASes being monitored
    // PDU pointer for outstanding message?
    // flags

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
sdxext_send_packet(struct sdx_bgp_connection* cxn,
                   void* data_ptr, size_t size_of_data_ptr);

/*
 * Network thread
 */
void*
sdxext_network_thread(void* portnumvoid);


#endif // __SDXEXT__

