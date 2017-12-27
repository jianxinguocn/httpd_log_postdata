/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Jianxin 2017-12-27
 *
 * Usage: 
 *
 * LoadModule logpost_module modules/mod_logpost.so
 *
 * LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %{SESSION}E \"%Z\"" combined
 *
 * #The max post data to be dumpped into apache log
 * LogPostMaxSize 512
 * # Mark the value of following data in *
 * HidePostKeys password checkPassword
 *
 * */

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "mod_log_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_request.h"

#include "http_log.h" 

module AP_MODULE_DECLARE_DATA logpost_module;

static const char logpost_filter_name[] = "LOG_POSTDATA";


#define DEFAULT_MAX_SIZE 1024
#define min(a,b) (a)<(b)?(a):(b)

/*
 * Logging of input and output config...
 */

typedef struct logpost_dirconf_t {
	apr_pool_t *pool;
    apr_size_t max_size;
	apr_array_header_t *hide_names;
} logpost_dirconf_t;

typedef struct logpost_req_t {
	apr_pool_t *mp;
    int log_size;
    int log_is_full;
    char *buffer;
} logpost_req_t;

static void logit(request_rec *r, apr_bucket *b, char *buf, apr_size_t *current_size);
static const char *log_post(request_rec *r, char *a);
static const char *logpost_set_max_size(cmd_parms *cmd, void *_cfg, const char *arg);
static const char *logpost_set_hiden_keys(cmd_parms *cmd, void *_cfg, const char *arg);

static const char *log_encrypt_cookie(request_rec *r, char *a)
{
    const char *cookies_entry;

    if ((cookies_entry = apr_table_get(r->headers_in, "Cookie"))) {
        char *cookie, *last1, *last2;
        char *cookies = apr_pstrdup(r->pool, cookies_entry);

        while ((cookie = apr_strtok(cookies, ";", &last1))) {
            char *name = apr_strtok(cookie, "=", &last2);
            /* last2 points to the next char following an '=' delim,
               or the trailing NUL char of the string */
            char *value = last2;
            if (name && *name &&  value && *value) {
                char *last = value - 2; 
                /* Move past leading WS */
                name += strspn(name, " \t");
                while (last >= name && apr_isspace(*last)) {
                    *last = '\0';
                    --last;
                }    

                if (!strcasecmp(name, a)) {
                    /* last1 points to the next char following the ';' delim,
                       or the trailing NUL char of the string */
                    last = last1 - (*last1 ? 2 : 1);
                    /* Move past leading WS */
                    value += strspn(value, " \t");

                    unsigned int b = 378551;
                    unsigned int a = 63689;
                    unsigned int hash = 0; 
                         
                    while (*value != '\0' && !apr_isspace(*value))
                    {    
                       hash = hash * a + (*value++);
                       a *= b;
                    }    
                    hash = hash & 0x7FFFFFFF;
                    //return apr_pstrdup(r->pool, value);
                    return apr_off_t_toa(r->pool, hash);
                }    
            }    
            /* Iterate the remaining tokens using apr_strtok(NULL, ...) */
            cookies = NULL;
        }    
    }    
    return NULL;
}


/** Only log the text format data */
static apr_status_t logpost_in_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    logpost_dirconf_t *cfg = (logpost_dirconf_t *) ap_get_module_config(f->r->per_dir_config, &logpost_module);
    logpost_req_t *rconf = ap_get_module_config(f->r->request_config, &logpost_module);
	request_rec *r = f->r;
	const char *content_type=r->content_type;

    if (!content_type || (strstr(content_type, "text")==NULL) || !strcmp(content_type, "application/x-www-form-urlencoded") || !strcmp(content_type, "application/json")) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "skipped the content-type is %s", content_type);
	   	return ap_get_brigade(f->next, bb, mode, block, readbytes);
	}

    apr_bucket *b;
    apr_status_t ret;
    if (rconf == NULL) {
		rconf = apr_pcalloc(f->r->pool, sizeof(logpost_req_t));
		rconf->buffer = apr_pcalloc(f->r->pool, cfg->max_size + 1);
        rconf->log_size = 0;
        rconf->log_is_full = 0;

		ap_set_module_config(f->r->request_config, &logpost_module, rconf);
    }

    char *buf = rconf->buffer;
    apr_size_t buf_len = rconf->log_size;

    if ((ret = ap_get_brigade(f->next, bb, mode, block, readbytes)) != APR_SUCCESS)
        return ret;

    /* log the body  */
    for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
        if (!rconf->log_is_full && buf_len < cfg->max_size)
            logit(f->r, b, buf + buf_len, &buf_len);

    if (buf_len && !rconf->log_is_full) {
        buf_len = min(buf_len, cfg->max_size);
        rconf->log_size = buf_len;

        if (rconf->log_size >= cfg->max_size){
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r, "body limit reach %d", rconf->log_size);
            rconf->log_is_full = 1;
        }
    }
    return ret;
}

static int logpost_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    static APR_OPTIONAL_FN_TYPE(ap_register_log_handler) *log_pfn_register;

    log_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_log_handler);

    if (log_pfn_register) {
        log_pfn_register(p, "Z", log_post, 0);
        log_pfn_register(p, "E", log_encrypt_cookie, 0);
    }

    return OK;
}

static void logpost_insert_filter(request_rec * r)
{
    logpost_dirconf_t *conf = ap_get_module_config(r->per_dir_config,
                                                 &logpost_module);
	ap_add_input_filter(logpost_filter_name, NULL, r, r->connection);
}

static void *create_logpost_dirconf (apr_pool_t *p, char *dummy)
{
    logpost_dirconf_t *cfg =
        (logpost_dirconf_t *) apr_pcalloc(p, sizeof(logpost_dirconf_t));
    cfg->max_size = DEFAULT_MAX_SIZE;
	cfg->pool=p;
    return cfg;
}


static const command_rec logpost_cmds[] = {
    AP_INIT_TAKE1("LogPostMaxSize", logpost_set_max_size, NULL,  RSRC_CONF, "Set maximum data size"),
    AP_INIT_RAW_ARGS("HidePostKeys", logpost_set_hiden_keys, NULL,  RSRC_CONF, "Hide keys with *"),
    {NULL}
};


static void register_hooks(apr_pool_t *p)
{
    static const char *pre[] = { "mod_log_config.c", NULL };

    ap_hook_pre_config(logpost_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);

    ap_register_input_filter(logpost_filter_name, logpost_in_filter, NULL,
                             AP_FTYPE_CONTENT_SET);

    ap_hook_insert_filter(logpost_insert_filter, NULL, NULL, APR_HOOK_LAST);
}

AP_DECLARE_MODULE(logio) =
{
    STANDARD20_MODULE_STUFF,
    create_logpost_dirconf,       /* create per-dir config */ 
    NULL,                       /* merge per-dir config */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    logpost_cmds,                 /* command apr_table_t */
    register_hooks              /* register hooks */
};

static void logit(request_rec *r, apr_bucket *b, char *buf, apr_size_t *current_size) {

    logpost_dirconf_t *cfg = (logpost_dirconf_t *) ap_get_module_config(r->per_dir_config, &logpost_module);

    if (*current_size < cfg->max_size && !(APR_BUCKET_IS_METADATA(b))) {
        const char * ibuf;
        apr_size_t nbytes;
        if (apr_bucket_read(b, &ibuf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
            if (nbytes) {
                nbytes = min(nbytes, cfg->max_size - *current_size);
                strncpy(buf, ibuf, nbytes);
                *current_size += nbytes;
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "error reading data");
        }
    } else {
        if (APR_BUCKET_IS_EOS(b)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "EOS bucket detected for request %s", r->the_request);
        }
    }
}

static const char *log_post(request_rec *r, char *a) {
    logpost_dirconf_t *cfg = (logpost_dirconf_t *) ap_get_module_config(r->per_dir_config, &logpost_module);
	logpost_req_t *rconf = ap_get_module_config(r->request_config, &logpost_module);
    if (rconf == NULL || rconf->log_size == 0) return "";
    rconf->buffer[rconf->log_size] = 0;

	/* Rewrite the value of key to * */
	char *buf = rconf->buffer; 
	char **names_ptr = NULL; 
	int num_names = 0;

    if (cfg->hide_names) {
        names_ptr = (char **)cfg->hide_names->elts;
        num_names = cfg->hide_names->nelts;
    }

	if (num_names==0 || names_ptr == NULL) {
		return ap_escape_logitem(r->pool, rconf->buffer);
	}else{
		for (; num_names; ++names_ptr, --num_names) {
			char *name_ptr = *names_ptr;
			char *p=strstr(buf, name_ptr);
			if (p != NULL) {
				p += strlen(name_ptr);
				while (*p != '\0' && *p!= '&' && *p != ' ' && *p != '\t') {
					*p = '*';
					p ++;
				}
			}
		}
		return ap_escape_logitem(r->pool, rconf->buffer);
	}
}

static const char *logpost_set_max_size(cmd_parms *cmd, void *_cfg, const char *arg) {
    logpost_dirconf_t *cfg = (logpost_dirconf_t *) _cfg; //ap_get_module_config(cmd->server->module_config, &logpost_module);
    cfg->max_size = atoi(arg);
    if (cfg->max_size == 0)
        cfg->max_size = DEFAULT_MAX_SIZE;
    return NULL;
}

static const char *logpost_set_hiden_keys(cmd_parms *cmd, void *_cfg, const char *arg) {
    logpost_dirconf_t *cfg = (logpost_dirconf_t *) _cfg; 

    const char *t, *w; 

    if (!cfg->hide_names) {
        cfg->hide_names = apr_array_make(cmd->pool, 1, sizeof(char *));
    }   

    t = arg;
    while ((w = ap_getword_conf(cmd->pool, &t)) && w[0]) {
        *(const char **)apr_array_push(cfg->hide_names) = w;
    }   

    return NULL;
}
