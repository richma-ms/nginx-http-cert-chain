#ifndef _NGX_HTTP_CERT_CHAIN_H_INCLUDED_
#define _NGX_HTTP_CERT_CHAIN_H_INCLUDED_

#define NGX_HTTP_AUTH_DIGEST_USERNOTFOUND 1000

// the module conf
typedef struct {
  ngx_http_complex_value_t realm;
  time_t timeout;
  time_t expires;
  time_t drop_time;
  time_t evasion_time;
  ngx_int_t replays;
  ngx_int_t maxtries;
  ngx_http_complex_value_t user_file;
  ngx_str_t cache_dir;
} ngx_http_auth_digest_loc_conf_t;

// contents of the request's authorization header
typedef struct {
  ngx_str_t auth_scheme;
  ngx_str_t username;
  ngx_str_t realm;
  ngx_str_t nonce;
  ngx_str_t nc;
  ngx_str_t uri;
  ngx_str_t qop;
  ngx_str_t cnonce;
  ngx_str_t response;
  ngx_str_t opaque;
  ngx_int_t stale;
} ngx_http_auth_digest_cred_t;

// the nonce as an issue-time/random-num pair
typedef struct {
  ngx_uint_t rnd;
  time_t t;
} ngx_http_auth_digest_nonce_t;

// nonce entries in the rbtree
typedef struct {
  ngx_rbtree_node_t node; // the node's .key is derived from the nonce val
  time_t expires;         // time at which the node should be evicted
  time_t drop_time;
  char nc[0]; // bitvector of used nc values to prevent replays
} ngx_http_auth_digest_node_t;

// evasion entries in the rbtree
typedef struct {
  ngx_rbtree_node_t node; // the node's .key is derived from the source address
  time_t drop_time;
  ngx_int_t failcount;
  struct sockaddr src_addr;
  socklen_t src_addrlen;
} ngx_http_auth_digest_ev_node_t;

// the main event
static ngx_int_t ngx_http_auth_digest_handler(ngx_http_request_t *r);

// module plumbing
static void *ngx_http_auth_digest_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_digest_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                                 void *child);
static ngx_int_t ngx_http_auth_digest_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_digest_worker_init(ngx_cycle_t *cycle);

// module datastructures
static ngx_command_t ngx_http_auth_digest_commands[] = {
    {ngx_string("auth_digest"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
     ngx_http_auth_digest_set_realm, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_digest_loc_conf_t, realm), NULL},
    {ngx_string("auth_digest_user_file"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
     ngx_http_auth_digest_set_user_file, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_digest_loc_conf_t, user_file), NULL},
    {ngx_string("auth_digest_timeout"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF |
                                            NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_digest_loc_conf_t, timeout), NULL},
    {ngx_string("auth_digest_expires"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF |
                                            NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_digest_loc_conf_t, expires), NULL},
    {ngx_string("auth_digest_drop_time"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_digest_loc_conf_t, drop_time), NULL},
    {ngx_string("auth_digest_evasion_time"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_digest_loc_conf_t, evasion_time), NULL},
    {ngx_string("auth_digest_replays"), NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF |
                                            NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_digest_loc_conf_t, replays), NULL},
    {ngx_string("auth_digest_maxtries"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_digest_loc_conf_t, maxtries), NULL},
    {ngx_string("auth_digest_shm_size"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
     ngx_http_auth_digest_set_shm_size, 0, 0, NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_cert_chain_module_ctx = {
    NULL,                      /* preconfiguration */
    ngx_http_auth_digest_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_auth_digest_create_loc_conf, /* create location configuration */
    ngx_http_auth_digest_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_cert_chain_module = {
    NGX_MODULE_V1,
    &ngx_http_cert_chain_module_ctx, /* module context */
    ngx_http_auth_digest_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    ngx_http_auth_digest_worker_init, /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING};

#endif
