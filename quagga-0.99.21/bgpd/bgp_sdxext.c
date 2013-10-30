
#include <zebra.h>
#include "bgp_sdxext.h"

static struct sdx_bgp_connection connection_array[NUM_CXNS];
static int connection_array_initialized = 0;
static pthread_t network_thread;
fd_set all_sockets;
fd_set read_fds;

extern struct bgp_master *bm;

// TODO - Need to add logs everywhere!

/* Static function to display route. */
// modified from route_vty_out_route()
void
sdxext_log_route (struct zlog* logger, struct prefix* p, char* hostname)
{
    char buf[BUFSIZ];

    zlog(logger, LOG_DEBUG,
         "%s - %s/%d", hostname,
         inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
         p->prefixlen);
}

void
sdxext_log_peer (struct peer* peer, char* hostname)
{
    zlog(peer->log, LOG_DEBUG,
         "  Peer AS %d - Local AS %d - Host %s",
         peer->as, peer->local_as, hostname);
    zlog(peer->log, LOG_DEBUG,
         "  Remote ID: %s",
         inet_ntoa(peer->remote_id));
    zlog(peer->log, LOG_DEBUG,
         "  Local  ID: %s",
         inet_ntoa(peer->local_id));
    zlog(peer->log, LOG_DEBUG,
         "  On interface %s",
         peer->ifname);
}

void
sdxext_init(void)
{
    int param = PORTNUM;
    // Initialze connections
    sdxext_initialize_connections();

    // Start up network thread
    pthread_create(&network_thread, NULL,
                   &sdxext_network_thread, (void*)(&param));
//TODO -- Quagga has their own threading library. May want to switch over to
//        that. Unfortunately, that would couple this a bit more than it is.


}

static void
sdxext_keepalive_timeout_handler(int sig, siginfo_t* si, void* uc)
{
    struct sdx_bgp_connection* cxn;

    // extract the connection from the siginfo_t structure
    cxn = (struct sdx_bgp_connection*)(si->si_value.sival_ptr);

    // increment the missed_keepalives
    cxn->missed_keepalives++;

    // if it's hit the MISSED_KEEPALIVE count, kill the connection.
    if (cxn->missed_keepalives >= MISSED_KEEPALIVES)
    {
        sdxext_free_connection(cxn);
        return;
    }

    // Restart timer.
    if (0 != sdxext_restart_cxn_timer(cxn))
    {
        sdxext_free_connection(cxn);
        return;
    }

    sdxext_restart_cxn_timer(cxn);
}

void
sdxext_initialize_connections(void)
{
    int i;
    for (i = 0; i < NUM_CXNS; i++)
    {
        struct sigevent sev;
        struct sigaction sa;
        memset((void*)&connection_array[i],
                0,
                sizeof(struct sdx_bgp_connection));
        connection_array[i].connection_id = i;

        // create timer
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = sdxext_keepalive_timeout_handler;
        sigemptyset(&sa.sa_mask);

        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIGRTMIN;
        sev.sigev_value.sival_ptr = &(connection_array[i]);

        timer_create(CLOCK_REALTIME, &sev, &(connection_array[i].timer));
    }
    connection_array_initialized = 1;
}

struct sdx_bgp_connection*
sdxext_handle_new_cxn(int socket, struct sockaddr* remoteaddr)
{
    struct sdx_bgp_connection* cxn;

    // allocate a new connection
    cxn = sdxext_allocate_connection();
    if (NULL == cxn)
        return NULL;

    // Fill in connection
    cxn->socket = socket;
    cxn->remoteaddr = *remoteaddr;
}

struct sdx_bgp_connection*
sdxext_lookup_connection(int socket)
{
    int i;
    struct sdx_bgp_connection* cxn = NULL;

    if (0 != connection_array_initialized)
    {
        for (i = 0; i < NUM_CXNS; i++)
        {
            if (socket == connection_array[i].socket)
            {
                cxn = &connection_array[i];
                break;
            }
        }
    }
    return cxn;
}



struct sdx_bgp_connection*
sdxext_allocate_connection(void)
{
    int i;
    struct sdx_bgp_connection* cxn = NULL;
    // initialize if they have not yet been initialized
    if (0 == connection_array_initialized)
    {
        sdxext_initialize_connections();
    }

    // find one that's not in use
    for (i = 0; i < NUM_CXNS; i++)
    {
        if (connection_array[i].in_use == 0)
        {
            cxn = &connection_array[i];
            cxn->in_use = 1;
            break;
        }
    }

    if (cxn == NULL)
        return NULL;

    // initialize sequences, version, etc.
    cxn->recv_sequence = 1;
    cxn->send_sequence = 1;
    cxn->version = PROTOCOL_VERSION;
    cxn->secret = SUPERSECRETLOGINSECRET;
    cxn->missed_keepalives = 0;
    cxn->buffer_to_send = NULL;
    cxn->update_list_to_send = NULL;

    return NULL;
}


void
sdxext_free_connection(struct sdx_bgp_connection* cxn)
{
    struct itimerspec zero_time;
    int local_socket = cxn->socket;

    if (NULL == cxn)
        return;
    // free up any allocated memory
    if (NULL != cxn->buffer_to_send)
    {
        free(cxn->buffer_to_send);
        cxn->buffer_to_send = NULL;
    }
    if (NULL != cxn->update_list_to_send)
    {
        free(cxn->update_list_to_send);
        cxn->update_list_to_send = NULL;
    }

    // stop any timer
    memset(&zero_time, 0, sizeof(struct itimerspec));
    timer_settime(cxn->timer, 0, &zero_time, NULL);

    // close socket, and zero so it cannot be looked up accidentally
    close(cxn->socket);
    cxn->socket = 0;

    // cleanup socket list
    FD_CLR(local_socket, &all_sockets);

    // set to free
    cxn->in_use = 0;

    // everything else will end up being reinitialized on allocation.
}

int
sdxext_restart_cxn_timer(struct sdx_bgp_connection* cxn)
{
    // Also, starts the timer, so two functions need not be written
    struct itimerspec zero_time;
    struct itimerspec interval_time;
    memset(&zero_time, 0, sizeof(struct itimerspec));
    memset(&interval_time, 0, sizeof(struct itimerspec));

    interval_time.it_value.tv_sec = KEEPALIVE_TIMEOUT;
    interval_time.it_interval.tv_sec = KEEPALIVE_TIMEOUT;

    // If running, stop it
    timer_settime(cxn->timer, 0, &zero_time, NULL);

    // Start it with the default timeout value
    timer_settime(cxn->timer, 0, &interval_time, NULL);
}

int
sdxext_get_pdu_to_send_resources(struct sdx_bgp_connection* cxn,
                                 struct sdx_bgp_pdu* pdu,
                                 size_t pdu_specifics_size,
                                 void* pdu_specifics,
                                 size_t update_buffer_size,
                                 void* update_buffer)
{
    if (NULL == cxn)
        return -1;
    // Set pdu pointer
    pdu = &(cxn->pdu_to_send);

    // initialize PDU
    memset(pdu, 0, sizeof(struct sdx_bgp_pdu));

    // Allocate pdu_specifics if there's a specified size
    if (0 != pdu_specifics_size)
    {
        pdu_specifics = malloc(pdu_specifics_size);
        if (NULL == pdu_specifics)
            return -2;
        memset(pdu, 0, pdu_specifics_size);
        // since they're in a union, doesn't matter which member it's set to
        pdu->login_request = pdu_specifics;
    }

    // Allocate update_buffer if there's a specified size

    if (0 != update_buffer_size)
    {
        update_buffer = malloc(update_buffer_size);
        if (NULL == update_buffer)
        {
            if (0 != pdu_specifics_size)
                free(pdu_specifics);
            return -3;
        }
    }
}

int
sdxext_free_sent_pdu_resources(struct sdx_bgp_connection* cxn)
{
    if (NULL == cxn)
        return -1;
    // free up any allocated memory
    if (NULL != cxn->buffer_to_send)
    {
        free(cxn->buffer_to_send);
        cxn->buffer_to_send = NULL;
    }
    if (NULL != cxn->update_list_to_send)
    {
        free(cxn->update_list_to_send);
        cxn->update_list_to_send = NULL;
    }
    return 0;
}

int
sdxext_register_AS(struct sdx_bgp_connection* cxn, int as)
{
    struct sdx_bgp_as_entry* as_entry;

    if (sdxext_is_AS_registered(cxn, as))
        return 1;

    if ((NULL == cxn->as_list_head) &&
        (NULL == cxn->as_list_tail))
    {
        cxn->as_list_head = malloc(sizeof(struct sdx_bgp_as_entry));
        as_entry = cxn->as_list_head;
        as_entry->prev = NULL;
        as_entry->next = NULL;
        as_entry->entry = as;
        cxn->as_list_tail = as_entry;
    }
    else
    {
        cxn->as_list_tail->next = malloc(sizeof(struct sdx_bgp_as_entry));
        as_entry = cxn->as_list_tail->next;
        as_entry->prev = cxn->as_list_tail;
        as_entry->next = NULL;
        as_entry->entry = as;
        cxn->as_list_tail = as_entry;
    }

    return 0;
}

int
sdxext_deregister_AS(struct sdx_bgp_connection* cxn, int as)
{
    struct sdx_bgp_as_entry* as_entry;

    if (NULL == cxn->as_list_head &&
        NULL == cxn->as_list_tail)
    {
        return 1;
    }

    as_entry = cxn->as_list_head;
    while (as_entry != NULL)
    {
        if (as == as_entry->entry)
        {
            struct sdx_bgp_as_entry* prev = as_entry->prev;
            struct sdx_bgp_as_entry* next = as_entry->next;
            prev->next = next;
            next->prev = prev;
            free(as_entry);
            return 0;
        }
        as_entry = as_entry->next;
    }
    return 2;
}

int
sdxext_is_AS_registered(struct sdx_bgp_connection* cxn, int as)
{
    struct sdx_bgp_as_entry* as_entry;

    as_entry = cxn->as_list_head;
    while (NULL != as_entry)
    {
        if (as == as_entry->entry)
        {
            return 1;
        }
        as_entry = as_entry->next;
    }
    return 0;
}



int
sdxext_receive_PDU(struct sdx_bgp_pdu* pdu, struct sdx_bgp_connection* cxn)
{
    int ret = 0;


    if (NULL == pdu)
        return -1;

    if (NULL == cxn)
        return -2;

    // verify correct connection_id
    if (pdu->connection_id != cxn->connection_id)
    {
        sdxext_free_connection(cxn);
        return -3;
    }

    // verify sequence and increment
    if (pdu->send_sequence == cxn->recv_sequence)
    {
        cxn->recv_sequence++;
    }
    else
    {
        sdxext_free_connection(cxn);
        return -4;
    }

    // Our sends - see if we can free up structures.
    if (pdu->recv_sequence == cxn->send_sequence)
    {
        sdxext_free_sent_pdu_resources(cxn);
        // If we've received something successfully, zero the missed count
        cxn->missed_keepalives = 0;
    }

    // Validate opcode and send to processing functions
    switch(pdu->opcode)
    {
        case SDX_BGP_LOGIN_REQUEST:
            ret = sdxext_process_login_request(cxn, pdu);
            break;
        case SDX_BGP_KEEPALIVE:
            ret = sdxext_process_keepalive(cxn, pdu);
            break;
        case SDX_BGP_REGISTER_AS:
            ret = sdxext_process_register_as(cxn, pdu);
            break;
        case SDX_BGP_DEREGISTER_AS:
            ret = sdxext_process_deregister_as(cxn, pdu);
            break;
        case SDX_BGP_REQUEST_ALL_ROUTES:
            ret = sdxext_process_request_all_routes(cxn, pdu);
            break;
        case SDX_BGP_LOGIN_RESPONSE: // should not be seen on server-side
        case SDX_BGP_UPDATE_LIST:    // should not be seen on server-side
        default:
            // assume the socket's sending garbage and close
            sdxext_free_connection(cxn);
            return -5;
    }
    // Close socket if there was a failure above or with cxn timer
    if (ret < 0 ||
        0 != sdxext_restart_cxn_timer(cxn))
    {
        sdxext_free_connection(cxn);
    }

    return ret;
}



/*
 * PDU processing functions
 */
int
sdxext_process_login_request(struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu)
{
    // check version
    if (cxn->version != pdu->login_request->version)
    {
        return -1;
    }

    // verify secret
    if (cxn->secret != pdu->login_request->secret)
    {
        return -2;
    }

    // build and send response
    sdxext_build_and_send_login_response(cxn);

    return 0;
}

int
sdxext_process_keepalive(struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu)
{
    // send ack if this is not an ack
    if (pdu->keepalive->ack_only == 0)
        return sdxext_build_and_send_keepalive(cxn, 1);
    return 0;
}

int
sdxext_process_register_as (struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu)
{
    // Add the AS to the watch list.
    if (sdxext_register_AS(cxn, pdu->register_as->as))
        return -1;
    // Send ack
    return sdxext_build_and_send_keepalive(cxn, 1);
}

int
sdxext_process_deregister_as (struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu)
{
    // Remove the AS from the watch list
    if (sdxext_deregister_AS(cxn, pdu->register_as->as))
        return -1;
    // Send ack
    return sdxext_build_and_send_keepalive(cxn, 1);
}

int
sdxext_process_request_all_routes (struct sdx_bgp_connection* cxn,
        struct sdx_bgp_pdu* pdu)
{
//TODO
    struct sdx_bgp_update* update_list = NULL;
    size_t datasize = 0;
    struct sdx_bgp_update* ul_ptr;
    char* payload;
    // Request all the routes
    sdxext_fetch_all_routes(cxn, update_list);

    // calculate output size
    ul_ptr = update_list;
    while (NULL != ul_ptr)
    {
        // for each update_list entry, sum up the size of all the parts


        ul_ptr = ul_ptr->next;
    }


    // package them up to be sent.


}

//SPDSPD

/*
 * BUILD AND SEND FUNCTIONS
 */


int
sdxext_build_and_send_login_response (struct sdx_bgp_connection* cxn)
{
    struct sdx_bgp_pdu* pdu = NULL;
    struct sdx_bgp_login_response* lr = NULL;
    // Allocate message on connection structure
    if (0 != sdxext_get_pdu_to_send_resources(cxn, pdu,
                                    sizeof(struct sdx_bgp_login_response),
                                    lr,
                                    0, NULL))
    {
        return -1;
    }

    // Set generic fields and increment correctly
    pdu->opcode = SDX_BGP_LOGIN_RESPONSE;
    pdu->send_sequence = cxn->send_sequence++;
    pdu->recv_sequence = cxn->recv_sequence;
    pdu->connection_id = cxn->connection_id;
    pdu->size = sizeof(struct sdx_bgp_login_response);

    // Set login response specific fields
    lr->version = cxn->version;
    lr->secret  = cxn->secret;

    // Send packet
    if (0 != sdxext_send_packet(cxn,
            (void*)pdu,
            sizeof(struct sdx_bgp_pdu) - sizeof(struct sdx_bgp_login_response*),
            lr,
            sizeof(struct sdx_bgp_login_response)))
    {
        return -2;
    }
}

int
sdxext_build_and_send_keepalive (struct sdx_bgp_connection* cxn,
                                 int ack_only)
{
    struct sdx_bgp_pdu* pdu = NULL;
    struct sdx_bgp_keepalive* ka = NULL;
    // Allocate message on connection structure
    if (0 != sdxext_get_pdu_to_send_resources(cxn, pdu,
                                              sizeof(struct sdx_bgp_keepalive),
                                              ka,
                                              0, NULL))
    {
        return -1;
    }
    // Set generic fields and increment correctly
    pdu->opcode = SDX_BGP_KEEPALIVE;
    pdu->send_sequence = cxn->send_sequence++;
    pdu->recv_sequence = cxn->recv_sequence;
    pdu->connection_id = cxn->connection_id;
    pdu->size = sizeof(struct sdx_bgp_keepalive);

    // Set keepalive specific fields
    if (0 != ack_only)
        ka->ack_only = (uint32_t)0xFFFFFFFF;
    else
        ka->ack_only = (uint32_t)0x00000000;

    // Send packet
        if (0 != sdxext_send_packet(cxn,
            (void*)pdu,
            sizeof(struct sdx_bgp_pdu) - sizeof(struct sdx_bgp_keepalive*),
            ka,
            sizeof(struct sdx_bgp_keepalive)))
    {
        return -2;
    }

}

int
sdxext_build_and_send_update_list (struct sdx_bgp_connection* cxn,
                                   struct sdx_bgp_update* update_list)
{
//TODO




    // Allocate message on connection structure

    // Set generic fields

    // Set update list specific fields

    // Build payload

    // Send packet header

    // Send payload



}

int
sdxext_send_packet(struct sdx_bgp_connection* cxn,
                   void* pointer_one, size_t size_of_pointer_one,
                   void* pointer_two, size_t size_of_pointer_two)

{
    size_t nbytes = 0;
    // Send the first part
    while (nbytes < size_of_pointer_one)
    {
        send(cxn->socket, pointer_one + nbytes,
             size_of_pointer_one - nbytes, 0);
    }

    // if there is a second part, send it
    nbytes = 0;
    while (nbytes < size_of_pointer_two)
    {
        send(cxn->socket, pointer_two + nbytes,
             size_of_pointer_two - nbytes, 0);
    }
}


void*
sdxext_network_thread(void* portnumvoid)
{
    int portnum;
    int fdmax;

    int listener;
    int newfd;
    struct sockaddr_storage remoteaddr; //client address
    socklen_t addrlen;
    struct addrinfo hints, *ai, *p;
//    char remoteIP[INET6_ADDRSTRLEN];
    int yes = 1;

    *(int*)portnum = (int*)portnumvoid; // Oh, the ugly!

    // Credit: http://beej.us/guide/bgnet/output/html/multipage/advanced.html#select
    // Create listening socket

    FD_ZERO(&all_sockets);
    FD_ZERO(&read_fds);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo(NULL, portnum, &hints, &ai);

    for (p = ai; p != NULL; p = p->ai_next)
    {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0)
            continue;

        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0)
        {
            close(listener);
            continue;
        }
        break;
    }
    // TODO: ignoring lots of error handling here!

    freeaddrinfo(ai);

    FD_SET(listener, &all_sockets);
    fdmax = listener; // init

    // Select loop (a glorious infinite loop! For now, should change this)
    while(1)
    {
        int i;
        read_fds = all_sockets;
        select(fdmax+1, &read_fds, NULL, NULL, NULL);

        for (i = 0; i <= fdmax; i++)
        {
            if (FD_ISSET(i, &read_fds))
            {
                if (i == listener)
                {
                    // Handle new connections
                    addrlen = sizeof(remoteaddr);
                    newfd = accept(listener,
                                   (struct sockaddr *)&remoteaddr,
                                   &addrlen);
                    if (newfd == -1)
                    {
                        // TODO: error! no handler
                    }
                    else
                    {
                        struct sdx_bgp_connection* cxn;
                        FD_SET(newfd, &all_sockets);
                        if (newfd > fdmax)
                            fdmax = newfd;
                        //got a new connection! save in the CXN structure?
                        cxn = sdxext_handle_new_cxn(newfd, &remoteaddr);
                        if (NULL == cxn)
                        {
                            close(newfd);
                        }
                    }
                }
                else
                {
                    // We've got data.
                    int nbytes = 0;
                    int headersize = sizeof(struct sdx_bgp_pdu) - sizeof(struct sdx_bgp_login_response*);
                    int bodysize;
                    char headerbuff[sizeof(struct sdx_bgp_pdu)];
                    struct sdx_bgp_pdu* pdu;
                    struct sdx_bgp_connection* cxn;
                    char* bodybuff;

                    cxn = sdxext_lookup_connection(i);
                    // receive data
                    nbytes = recv(i, &headerbuff, headersize, 0);
                    if (0 >= nbytes)
                    {
                        // error, close the connection
                        sdxext_free_connection(cxn);
                    }
                    else
                    {
                        // Receive header
                        while (nbytes < headersize)
                        {
                            nbytes += recv(i, &headerbuff + nbytes,
                                           headersize - nbytes, 0);
                        }

                        // Receive body
                        pdu = (struct sdx_bgp_pdu*)&headerbuff;
                        bodysize = pdu->size;
                        bodybuff = malloc(bodysize);
                        nbytes = 0;

                        while (nbytes < bodysize)
                        {
                            nbytes += recv(i, bodybuff + nbytes,
                                           bodysize - nbytes, 0);
                        }
                        pdu->login_request = (struct sdx_bgp_login_request*)bodybuff;

                        // send to receive parsing function
                        sdxext_receive_PDU(pdu, cxn);

                        // free allocated resources
                        free(bodybuff);
                    } // Receive data

                } // i == listener
            } // FD_ISSET
        } // for i<fdmax
    } // while (1)
    // TODO: error handling and cleanup. Right now, it's super ugly.
}


int
sdxext_filter_does_cxn_care_about_route(struct sdx_bgp_connection* cxn,
                                        char* route)
{
    // TODO - What does a route look like? I'm just going with a char* for the
    // time being just as a place holder.
    char as_str[12]; // if they're longer than this....
    int as_str_len;
    int route_str_len;
    struct sdx_bgp_as_entry* as_entry;

    route_str_len = strlen(route);
    as_entry = cxn->as_list_head;
    while (NULL != as_entry)
    {
        // look to see if one of the ones we care about is at the end of the
        // route
        as_str_len = sprintf(as_str, " %i", as_entry->entry);

        if (0 == strncmp(as_str,
                         route + route_str_len - as_str_len,
                         as_str_len))
         {
             return 1;
         }

        as_entry = as_entry->next;
    }
    return 0;
}

int
sdxext_filter_from_assegment(struct sdx_bgp_connection* cxn,
                             struct assegment* segment)
{
    // TODO - What does a route look like? I'm just going with a char* for the
    // time being just as a place holder.
    struct sdx_bgp_as_entry* as_entry;
    struct assegment* tempseg = segment;

    if (NULL == segment)
        return 0;

    // Get to the end of the assegment list
    while (NULL != tempseg->next)
    {
        tempseg = tempseg->next;
    }

    // go through all the as_entries that are associated with this connection
    as_entry = cxn->as_list_head;
    while (NULL != as_entry)
    {
        // If the one at the end of the segment is one we care about, return 1
        if (tempseg->as == as_entry->entry)
            return 1;

        as_entry = as_entry->next;
    }
    return 0;
}


void
sdxext_new_route_received(char* route)
{
    // TODO - What does a route look like? I'm just going with a char* for the
    // time being just as a place holder.
    int i;

    for (i = 0; i < NUM_CXNS; i++)
    {
        if (connection_array[i].in_use)
        {
            if(sdxext_filter_does_cxn_care_about_route(&connection_array[i],
                                                       route))
            {
                struct sdx_bgp_update update;
                // TODO - put together update

                // send it on the current connection
                sdxext_build_and_send_update_list(&connection_array[i],
                                                  &update);
            }
        }
    }
}

int
sdxext_fetch_all_routes(struct sdx_bgp_connection* cxn,
                        struct sdx_bgp_update* update_list)
{

    // based upon, among other functions, peer_lookup(), peer_adj_routes(),
    // show_adj_routes(), route_vty_out_tmp()
    struct listnode* bgpnode;
    struct listnode* nbgpnode;
    //struct peer* peer;
    struct bgp* bgp;
    struct bgp_table* table;
    struct bgp_node* rn;
    struct bgp_adj_in* ain;
    struct prefix* p;
    struct attr* attr;
    afi_t afi = AFI_IP;
    safi_t safi = SAFI_UNICAST;
    struct sdx_bgp_update* curr_update;



    for (ALL_LIST_ELEMENTS (bm->bgp, bgpnode, nbgpnode, bgp))
    {
        table = bgp->rib[afi][safi];

        for (rn = bgp_table_top(table); NULL == rn; rn = bgp_route_next(rn))
        {
            for (ain = rn->adj_in; ain; ain = ain->next)
            {
                p = &(rn->p);
                attr = ain->attr;

                // See if it is something we care about
                if (sdxext_filter_from_assegment(cxn, attr->aspath->segments))
                {
                    struct assegment* segment;
                    // allocate a new structure and add to list
                    if (NULL == update_list)
                    {
                        update_list = malloc(sizeof(struct sdx_bgp_update));
                        curr_update = update_list;
                    }
                    else
                    {
                        curr_update->next =
                                    malloc(sizeof(struct sdx_bgp_update));
                        curr_update = curr_update->next;
                    }

                    // fill in structure
                    curr_update->next = NULL;
                    segment = attr->aspath->segments;
                    while (NULL != segment->next)
                    {
                        segment = segment->next;
                    }
                    curr_update->as = segment->as;
                    curr_update->status = SDX_BGP_CURRENT;
                    curr_update->attr = attr;
                    curr_update->prefix = p;
                }
            }
        }
    } // for all BGP sessions(?)

}
