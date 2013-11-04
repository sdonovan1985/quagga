
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
    cxn->missed_keepalives = 0;

    return NULL;
}


void
sdxext_free_connection(struct sdx_bgp_connection* cxn)
{
    struct itimerspec zero_time;
    int local_socket = cxn->socket;

    if (NULL == cxn)
        return;

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
sdxext_send_packet(struct sdx_bgp_connection* cxn,
		   void* header_ptr, size_t size_of_header_ptr,
                   void* data_ptr, size_t size_of_data_ptr)
{
    size_t nbytes = 0;
    while (nbytes < size_of_header_ptr)
    {
	// typecast is to be sure the pointer math works correctly
	send(cxn->socket, (char*)header_ptr + nbytes,
             size_of_header_ptr - nbytes, 0);
    }
    nbytes = 0;
    while (nbytes < size_of_data_ptr)
    {
	// typecast is to be sure the pointer math works correctly
	send(cxn->socket, (char*)data_ptr + nbytes,
             size_of_data_ptr - nbytes, 0);
    }
}

int
sdxext_recv_packet(struct sdx_bgp_connection* cxn,
		   void* header_ptr, size_t size_of_header_ptr,
                   void* data_ptr, size_t* size_of_data_ptr)
{
    size_t nbytes = 0;
    while (nbytes < size_of_header_ptr)
    {
	// typecast is to be sure the pointer math works correctly
	recv(cxn->socket, (char*)header_ptr + nbytes,
             size_of_header_ptr - nbytes, 0);
    }

    *size_of_data_ptr = *((size_t*)header_ptr);
    data_ptr = malloc(*size_of_data_ptr);
    nbytes = 0;

    while (nbytes < (*size_of_data_ptr))
    {
	// typecast is to be sure the pointer math works correctly
	recv(cxn->socket, (char*)data_ptr + nbytes,
	     (*size_of_data_ptr) - nbytes, 0);
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
/* THIS NEEDS TO BE REWRITTEN. 
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
*/
    // TODO: error handling and cleanup. Right now, it's super ugly.
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
	    /* NEED TO REDO
	    if(sdxext_filter_does_cxn_care_about_route(&connection_array[i],
                                                       route))
            {
	        struct sdx_bgp_update update;
                // TODO - put together update

                // send it on the current connection
                sdxext_build_and_send_update_list(&connection_array[i],
                                                  &update);
            }
	    */
        }
    }
}

int
sdxext_bgp_update_bypass(struct peer* peer, struct prefix* p, struct attr* attr,
			 afi_t afi, safi_t safi, int type, int sub_type,
			 struct prefix_rd* prd, u_char* tag, int soft_reconfig)
{
    zlog(peer->log, LOG_DEBUG,
	 "%s SPD - In %s", peer->host, __FUNCTION__);

    // encode and sent this over to the SDX


    // Parse out what's returned by the SDX


    // Call with the updated information, if the SDX wants us to
    if (1)
	bgp_update_rsclients_bypass(peer, p, attr, afi, safi, type, sub_type, prd, 
				    tag, soft_reconfig);

    return 1;
}
