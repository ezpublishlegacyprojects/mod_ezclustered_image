/*
**  mod_ezclustered_image.c -- Apache sample ezclustered_image module
**  [Autogenerated via ``apxs -n ezclustered_image -g'']
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory
**  by running:
**
**    $ apxs -c -i mod_ezclustered_image.c
**
**  Then activate it in Apache's httpd.conf file for instance
**  for the URL /ezclustered_image in as follows:
**
**    #   httpd.conf

**  LoadModule ezclustered_image_module modules/mod_ezclustered_image.so
**  
**  DBDriver mysql
**  DBDParams "host=localhost port=3306 user=<user> pass=<pass> dbname=<dbname>"
**  DBDPrepareSQL "SELECT datatype, mtime, size, filedata, offset FROM ezdbfile, ezdbfile_data WHERE ezdbfile.name_hash = ezdbfile_data.name_hash AND ezdbfile.name_hash = MD5( %s ) AND scope = 'image' ORDER BY offset;" ezdbfile_sql
**  
**  <LocationMatch "/var/([^/]+/)?storage/(images|images-versioned)+/.*">
**      SetHandler ezclustered_image
**  </LocationMatch>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**/

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "apr_strings.h"

static int ezclustered_image_handler(request_rec *r)
{
    ap_dbd_t *dbd       = ap_dbd_acquire(r);
    char *path_prefix   = "var";
    const char *real_filename = NULL;

    const char *prepared_statement_label   = "ezdbfile_sql";
    apr_dbd_prepared_t *prepared_statement = NULL;

    int select_error_code  = -1;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t     *row = NULL;
    apr_status_t rv;

    /* image metadata */
    const char *datatype = NULL;
    const char *mtime = NULL;
    /* const char *size = NULL; */

    /* image contents */
    apr_bucket_brigade *file_data;

    /* apr_time_exp_t *date_format = NULL; */
    
    if (strcmp(r->handler, "ezclustered_image")) {
        return DECLINED;
    }

    if(dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unable to acquire mod_dbd connection "
                      "is mod_dbd loaded and mysql running ?");
        return DECLINED;
    }

    if( !r->path_info || strlen(r->path_info) <= 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No file to fetch");
        return DECLINED;
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
        return DECLINED;
    }

    if(apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1) == -1) {
        return DECLINED;
    }

    datatype = apr_dbd_get_entry(dbd->driver, row, 0);
    mtime    = apr_dbd_get_entry(dbd->driver, row, 1);

    /* apr_table_setn(r->headers_out, "Last-Modified", TODO); */
    /* apr_table_setn(r->headers_out, "Expires", TODO); */
    apr_table_setn(r->headers_out, "Accept-Ranges", "bytes");
    apr_table_setn(r->headers_out, "Connection", "close");

    ap_set_content_type(r, datatype);

    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {

        file_data = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        
        if(apr_dbd_datum_get(dbd->driver, row, 3, APR_DBD_TYPE_BLOB, file_data) != APR_SUCCESS)
        {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Unable to fetch file data");
            apr_brigade_destroy(file_data);
            return DECLINED;
        }

        apr_brigade_destroy(file_data);
    }

    return OK;
}

static void ezclustered_image_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(ezclustered_image_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA ezclustered_image_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    ezclustered_image_register_hooks  /* register hooks                      */
};

