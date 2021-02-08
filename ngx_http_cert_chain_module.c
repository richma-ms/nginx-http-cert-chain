#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>

#include "ngx_http_cert_chain_module.h"

static void *ngx_http_auth_digest_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_auth_digest_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_digest_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->timeout = NGX_CONF_UNSET_UINT;
  conf->expires = NGX_CONF_UNSET_UINT;
  conf->drop_time = NGX_CONF_UNSET_UINT;
  conf->replays = NGX_CONF_UNSET_UINT;
  conf->evasion_time = NGX_CONF_UNSET_UINT;
  conf->maxtries = NGX_CONF_UNSET_UINT;
  return conf;
}

static char *ngx_http_auth_digest_merge_loc_conf(ngx_conf_t *cf, void *parent,
                                                 void *child) {
  ngx_http_auth_digest_loc_conf_t *prev = parent;
  ngx_http_auth_digest_loc_conf_t *conf = child;

  ngx_conf_merge_sec_value(conf->timeout, prev->timeout, 60);
  ngx_conf_merge_sec_value(conf->expires, prev->expires, 10);
  ngx_conf_merge_sec_value(conf->drop_time, prev->drop_time, 300);
  ngx_conf_merge_value(conf->replays, prev->replays, 20);
  ngx_conf_merge_sec_value(conf->evasion_time, prev->evasion_time, 300);
  ngx_conf_merge_value(conf->maxtries, prev->maxtries, 5);

  if (conf->user_file.value.len == 0) {
    conf->user_file = prev->user_file;
  }

  if (conf->realm.value.len == 0) {
    conf->realm = prev->realm;
  }

  return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_digest_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;
  ngx_str_t *shm_name;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_digest_handler;

  ngx_http_auth_digest_cleanup_timer =
      ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
  if (ngx_http_auth_digest_cleanup_timer == NULL) {
    return NGX_ERROR;
  }

  shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
  shm_name->len = sizeof("auth_digest");
  shm_name->data = (unsigned char *)"auth_digest";

  if (ngx_http_auth_digest_shm_size == 0) {
    ngx_http_auth_digest_shm_size = 4 * 256 * ngx_pagesize; // default to 4mb
  }

  ngx_http_auth_digest_shm_zone =
      ngx_shared_memory_add(cf, shm_name, ngx_http_auth_digest_shm_size,
                            &ngx_http_cert_chain_module);
  if (ngx_http_auth_digest_shm_zone == NULL) {
    return NGX_ERROR;
  }
  ngx_http_auth_digest_shm_zone->init = ngx_http_auth_digest_init_shm_zone;

  return NGX_OK;
}

static ngx_int_t ngx_http_auth_digest_worker_init(ngx_cycle_t *cycle) {
  if (ngx_process != NGX_PROCESS_WORKER) {
    return NGX_OK;
  }

  // create a cleanup queue big enough for the max number of tree nodes in the
  // shm
  ngx_http_auth_digest_cleanup_list =
      ngx_array_create(cycle->pool, NGX_HTTP_AUTH_DIGEST_CLEANUP_BATCH_SIZE,
                       sizeof(ngx_rbtree_node_t *));

  if (ngx_http_auth_digest_cleanup_list == NULL) {
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "Could not allocate shared memory for auth_digest");
    return NGX_ERROR;
  }

  ngx_connection_t *dummy;
  dummy = ngx_pcalloc(cycle->pool, sizeof(ngx_connection_t));
  if (dummy == NULL)
    return NGX_ERROR;
  dummy->fd = (ngx_socket_t)-1;
  dummy->data = cycle;

  ngx_http_auth_digest_cleanup_timer->log = ngx_cycle->log;
  ngx_http_auth_digest_cleanup_timer->data = dummy;
  ngx_http_auth_digest_cleanup_timer->handler = ngx_http_auth_digest_cleanup;
  ngx_add_timer(ngx_http_auth_digest_cleanup_timer,
                NGX_HTTP_AUTH_DIGEST_CLEANUP_INTERVAL);
  return NGX_OK;
}

static ngx_int_t ngx_http_auth_digest_handler(ngx_http_request_t *r) {
  off_t offset;
  ssize_t n;
  ngx_fd_t fd;
  ngx_int_t rc;
  ngx_err_t err;
  ngx_str_t user_file, passwd_line, realm;
  ngx_file_t file;
  ngx_uint_t i, begin, tail, idle;
  ngx_http_auth_digest_loc_conf_t *alcf;
  ngx_http_auth_digest_cred_t *auth_fields;
  u_char buf[NGX_HTTP_AUTH_DIGEST_BUF_SIZE];
  u_char line[NGX_HTTP_AUTH_DIGEST_BUF_SIZE];
  u_char *p;

  if (r->internal) {
    return NGX_DECLINED;
  }

  // if digest auth is disabled for this location, bail out immediately
  alcf = ngx_http_get_module_loc_conf(r, ngx_http_cert_chain_module);

  if (alcf->realm.value.len == 0) {
    return NGX_DECLINED;
  }

  if (ngx_http_complex_value(r, &alcf->realm, &realm) != NGX_OK) {
    return NGX_ERROR;
  }

  if (realm.len == 0 || alcf->user_file.value.len == 0) {
    return NGX_DECLINED;
  }

  if (ngx_strcmp(realm.data, "off") == 0) {
    return NGX_DECLINED;
  }

  if (ngx_http_auth_digest_evading(r, alcf)) {
    return NGX_HTTP_UNAUTHORIZED;
  }
  // unpack the Authorization header (if any) and verify that it contains all
  // required fields. otherwise send a challenge
  auth_fields = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_digest_cred_t));
  rc = ngx_http_auth_digest_check_credentials(r, auth_fields);
  if (rc == NGX_DECLINED) {
    return ngx_http_auth_digest_send_challenge(r, &realm, 0);
  } else if (rc == NGX_ERROR) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  // check for the existence of a passwd file and attempt to open it
  if (ngx_http_complex_value(r, &alcf->user_file, &user_file) != NGX_OK) {
    return NGX_ERROR;
  }
  fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
  if (fd == NGX_INVALID_FILE) {
    ngx_uint_t level;
    err = ngx_errno;

    if (err == NGX_ENOENT) {
      level = NGX_LOG_ERR;
      rc = NGX_HTTP_FORBIDDEN;

    } else {
      level = NGX_LOG_CRIT;
      rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(level, r->connection->log, err,
                  ngx_open_file_n " \"%s\" failed", user_file.data);
    return rc;
  }
  ngx_memzero(&file, sizeof(ngx_file_t));
  file.fd = fd;
  file.name = user_file;
  file.log = r->connection->log;

  // step through the passwd file and find the individual lines, then pass them
  // off
  // to be compared against the values in the authorization header
  passwd_line.data = line;
  offset = begin = tail = 0;
  idle = 1;
  ngx_memzero(buf, NGX_HTTP_AUTH_DIGEST_BUF_SIZE);
  ngx_memzero(passwd_line.data, NGX_HTTP_AUTH_DIGEST_BUF_SIZE);
  while (1) {
    n = ngx_read_file(&file, buf + tail, NGX_HTTP_AUTH_DIGEST_BUF_SIZE - tail,
                      offset);
    if (n == NGX_ERROR) {
      ngx_http_auth_digest_close(&file);
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    begin = 0;
    for (i = 0; i < n + tail; i++) {
      if (buf[i] == '\n' || buf[i] == '\r') {
        if (!idle &&
            i - begin >
                36) { // 36 is the min length with a single-char name and realm
          p = ngx_cpymem(passwd_line.data, &buf[begin], i - begin);
          p[0] = '\0';
          passwd_line.len = i - begin;
          rc = ngx_http_auth_digest_verify_user(r, auth_fields, &passwd_line);

          if (rc == NGX_HTTP_AUTH_DIGEST_USERNOTFOUND) {
            rc = NGX_DECLINED;
          }

          if (rc != NGX_DECLINED) {
            ngx_http_auth_digest_close(&file);
            ngx_http_auth_digest_evasion_tracking(
                r, alcf, NGX_HTTP_AUTH_DIGEST_STATUS_SUCCESS);
            return rc;
          }
        }
        idle = 1;
        begin = i;
      } else if (idle) {
        idle = 0;
        begin = i;
      }
    }

    if (!idle) {
      tail = n + tail - begin;
      if (n == 0 && tail > 36) {
        p = ngx_cpymem(passwd_line.data, &buf[begin], tail);
        p[0] = '\0';
        passwd_line.len = i - begin;
        rc = ngx_http_auth_digest_verify_user(r, auth_fields, &passwd_line);
        if (rc == NGX_HTTP_AUTH_DIGEST_USERNOTFOUND) {
          rc = NGX_DECLINED;
        }
        if (rc != NGX_DECLINED) {
          ngx_http_auth_digest_close(&file);
          ngx_http_auth_digest_evasion_tracking(
              r, alcf, NGX_HTTP_AUTH_DIGEST_STATUS_SUCCESS);
          return rc;
        }
      } else {
        ngx_memmove(buf, &buf[begin], tail);
      }
    }

    if (n == 0) {
      break;
    }

    offset += n;
  }

  ngx_http_auth_digest_close(&file);

  // log only wrong username/password,
  // not expired hash
  int nc = ngx_hextoi(auth_fields->nc.data, auth_fields->nc.len);
  if (nc == 1) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "invalid username or password for %*s",
                  auth_fields->username.len, auth_fields->username.data);
  }

  ngx_http_auth_digest_evasion_tracking(r, alcf,
                                        NGX_HTTP_AUTH_DIGEST_STATUS_FAILURE);

  // since no match was found based on the fields in the authorization header,
  // send a new challenge and let the client retry
  return ngx_http_auth_digest_send_challenge(r, &realm, auth_fields->stale);
}
