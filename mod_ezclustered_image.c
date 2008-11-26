/**
 * Copyright [2008] [Jérôme Renard jerome.renard@gmail.com] 
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 *
 * You may obtain a copy of the License at 
 *
 * http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 *
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 *
 * Please read INSTALL to learn how to install this module
 **/

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_dbd.h"
#include "util_time.h"
#include "mod_dbd.h"
#include "apr_strings.h"

/* {{{ static int ezclustered_image_handler(request_rec *r) */
static int ezclustered_image_handler(request_rec *r)
{
    ap_dbd_t *dbd       = ap_dbd_acquire(r);
    char *path_prefix   = "var";
    const char *real_filename = NULL;

    const char *prepared_statement_label   = "ezdbfile_sql";
    apr_dbd_prepared_t *prepared_statement = NULL;

    apr_int16_t select_error_code  = -1;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t     *row = NULL;

    /* image metadata */
    const char *datatype  = NULL;
    const char *name_hash = NULL;
    time_t  mtime;
    apr_time_t ansi_time;

    /* image contents */
    apr_bucket_brigade *bb;

    if(!r->handler || strcmp(r->handler, "ezclustered_image")) {
        return DECLINED;
    }

    if(r->method_number != M_GET) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    if(dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to acquire mod_dbd connection "
                      "is mod_dbd loaded and mysql running ?");
        return DECLINED;
    }

    if( !r->path_info || strlen(r->path_info) <= 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No file to fetch");
        return HTTP_NOT_FOUND;
    }

    real_filename = apr_pstrcat(r->pool, path_prefix, r->path_info, NULL);

#ifdef DEBUG_ENABLED
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Path INFO : %s",
                  r->path_info);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "real_filename : %s",
                  real_filename);
#endif

    prepared_statement = apr_hash_get(dbd->prepared, prepared_statement_label, APR_HASH_KEY_STRING);

    if (prepared_statement == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "A prepared statement could not be found for "
                      "with the key '%s'", prepared_statement_label);
        return DECLINED;
    }

    select_error_code = apr_dbd_pvselect(dbd->driver, r->pool,
                                         dbd->handle, &res,
                                         prepared_statement, 0,
                                         real_filename, NULL);

    if (select_error_code != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Query execution error looking up '%s' "
                      "in database", real_filename);
        return HTTP_NOT_FOUND;
    }

    if(apr_dbd_get_row(dbd->driver, r->pool, res, &row, 1) == -1) {
        return HTTP_NOT_FOUND;
    }
    
    /* {{{ Fetching datatype, mtime, name_hash cols */
    datatype  = apr_dbd_get_entry(dbd->driver, row, 0);
    mtime     = (time_t)atoi(apr_dbd_get_entry(dbd->driver, row, 1));
    name_hash = apr_dbd_get_entry(dbd->driver, row, 4);
    /* }}} */
    
    /* {{{ Expires header
     *
     * The image never expires.
     * As it is a content image, whenever it is updated a new version
     * is created so it is safe to cache it forever
     *
     *
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.21
     *
     * To mark a response as "never expires," an origin server sends 
     * an Expires date approximately one year from the time the response is sent. 
     * HTTP/1.1 servers SHOULD NOT send Expires dates more than one year in the future.
     *
     * image mtime + 1 year
     */ 
    char *expires_date;
    mtime = mtime + 31536000;
    apr_time_ansi_put(&ansi_time, mtime);

    expires_date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(expires_date, ansi_time);

    apr_table_setn(r->headers_out, "Expires", expires_date);
    /* }}} */

    /* {{{ Etag header */
    /*
     * The image name_hash should be strong enough
     * to ensure unicity
     */
    apr_table_setn(r->headers_out, "Etag", name_hash);
    /* }}} */

    /* {{{ Last-Modified header, disabled for instance */
    /*
    char *last_modified_date;
    apr_time_ansi_put(&ansi_time, mtime);

    last_modified_date = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(last_modified_date, ansi_time);


    apr_table_setn(r->headers_out, "Last-Modified", last_modified_date);
    */
    /* }}} */

    /* {{{ Additional headers */
    apr_table_setn(r->headers_out, "Accept-Ranges", "bytes");
    /* Will trigger an X-Pad header */
    /* apr_table_setn(r->headers_out, "Connection", "close"); */
    /* }}} */

    /* {{{ Image contents */
    /* image/png|gif|jpg */
    ap_set_content_type(r, datatype);

    do {

        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        apr_dbd_datum_get(dbd->driver, row, 3, APR_DBD_TYPE_BLOB, bb);
        ap_pass_brigade(r->output_filters, bb);

    } while( apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1) == 0);
    /* }}} */

    return OK;
}
/* }}} */

/* {{{ static void ezclustered_image_register_hooks(apr_pool_t *p) */
static void ezclustered_image_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(ezclustered_image_handler, 
                    NULL, 
                    NULL, 
                    APR_HOOK_MIDDLE);
}
/* }}} */

/* {{{ module AP_MODULE_DECLARE_DATA ezclustered_image_module */
module AP_MODULE_DECLARE_DATA ezclustered_image_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    ezclustered_image_register_hooks  /* register hooks           */
};
/* }}} */

/* 
 * vim600: sw=4 ts=4 fdm=marker
 */
