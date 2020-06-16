#include "uchat.h"

static int connect_client_loop(struct addrinfo *peer_address) {
    int numsec;
    int sock;
    int enable = 1;

    for (numsec = 1; numsec <= MAXSLEEP; numsec <<= 1) {
        if ((sock = socket(peer_address->ai_family, peer_address->ai_socktype,
                           peer_address->ai_protocol)) < 0) {
            freeaddrinfo(peer_address);
            return -1;
        }
        setsockopt(sock, IPPROTO_TCP, SO_KEEPALIVE, &enable, sizeof(int));
        if ((connect(sock, peer_address->ai_addr,
                     peer_address->ai_addrlen)) == 0)
            return sock;
        printf("not connect\n");
        close(sock);
        if (numsec <= MAXSLEEP / 2)
            sleep(numsec);
    }
    return -1;
}



int mx_connect_client(t_client_info *info) {
    struct addrinfo hints;
    struct addrinfo *peer_address = NULL;
    int sock;
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if ((err = getaddrinfo(info->ip, info->argv[2],
                           &hints, &peer_address)) != 0) {
        fprintf(stderr, "getaddrinfo() failed. (%s)\n", gai_strerror(err));
        return -1;
    }
    if ((sock = connect_client_loop(peer_address)) == -1)
        return -1;
    printf("connect to server cocket %d\n", sock);
    return sock;
}


static void mx_report_tls_client(struct tls * tls_ctx, char * host) {
    time_t t;
    const char *ocsp_url;

    fprintf(stderr, "\nTLS handshake negotiated %s/%s with host %s\n",
            tls_conn_version(tls_ctx), tls_conn_cipher(tls_ctx), host);
    fprintf(stderr, "Peer name: %s\n", host);
    if (tls_peer_cert_subject(tls_ctx))
        fprintf(stderr, "Subject: %s\n",
                tls_peer_cert_subject(tls_ctx));
    if (tls_peer_cert_issuer(tls_ctx))
        fprintf(stderr, "Issuer: %s\n",
                tls_peer_cert_issuer(tls_ctx));
    if ((t = tls_peer_cert_notbefore(tls_ctx)) != -1)
        fprintf(stderr, "Valid From: %s", ctime(&t));
    if ((t = tls_peer_cert_notafter(tls_ctx)) != -1)
        fprintf(stderr, "Valid Until: %s", ctime(&t));
    if (tls_peer_cert_hash(tls_ctx))
        fprintf(stderr, "Cert Hash: %s\n",
                tls_peer_cert_hash(tls_ctx));
    ocsp_url = tls_peer_ocsp_url(tls_ctx);
    if (ocsp_url != NULL)
        fprintf(stderr, "OCSP URL: %s\n", ocsp_url);
    switch (tls_peer_ocsp_response_status(tls_ctx)) {
        case TLS_OCSP_RESPONSE_SUCCESSFUL:
            fprintf(stderr, "OCSP Stapling: %s\n",
                    tls_peer_ocsp_result(tls_ctx) == NULL ?  "" :
                    tls_peer_ocsp_result(tls_ctx));
            fprintf(stderr,
                    "  response_status=%d cert_status=%d crl_reason=%d\n",
                    tls_peer_ocsp_response_status(tls_ctx),
                    tls_peer_ocsp_cert_status(tls_ctx),
                    tls_peer_ocsp_crl_reason(tls_ctx));
            t = tls_peer_ocsp_this_update(tls_ctx);
            fprintf(stderr, "  this update: %s",
                    t != -1 ? ctime(&t) : "\n");
            t =  tls_peer_ocsp_next_update(tls_ctx);
            fprintf(stderr, "  next update: %s",
                    t != -1 ? ctime(&t) : "\n");
            t =  tls_peer_ocsp_revocation_time(tls_ctx);
            fprintf(stderr, "  revocation: %s",
                    t != -1 ? ctime(&t) : "\n");
            break;
        case -1:
            break;
        default:
            fprintf(stderr, "OCSP Stapling:  failure - response_status %d (%s)\n",
                    tls_peer_ocsp_response_status(tls_ctx),
                    tls_peer_ocsp_result(tls_ctx) == NULL ?  "" :
                    tls_peer_ocsp_result(tls_ctx));
            break;

    }
}

static void clean_client(t_client_info *info) {
    tls_close(info->tls_client);
    tls_free(info->tls_client);
    close(info->socket);
}

int mx_start_client(t_client_info *info) {
    pthread_t thread_input;
    pthread_attr_t attr;
    int tc;

    if (mx_tls_config_client(info))  // conf tls
        return 1;
    info->socket = mx_connect_client(info);
    if(info->socket == -1)
        return 1;
    if (mx_make_tls_connect_client(info)) // tls connect and handshake
        return 1;

    mx_report_tls_client(info->tls_client, "uchat");

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED); // #
    tc = pthread_create(&thread_input, &attr, mx_process_input_from_server, info);
    if (tc != 0)
        printf("pthread_create error = %s\n", strerror(tc));
    mx_login(info);
    pthread_cancel(thread_input);
    clean_client(info);
    return 0;
}

