/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:    This file provides the implemenation for KAE engine digests 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sec_digests.h"
#include "sec_digests_soft.h"
#include "sec_digests_wd.h"

#include "engine_utils.h"
#include "engine_types.h"
#include "engine_log.h"

struct digest_info {
    int nid;
    EVP_MD *digest;
};
static struct digest_info g_sec_digests_info[] = { 
    { NID_sm3, NULL },
};

#define DIGESTS_COUNT (BLOCKSIZES_OF(g_sec_digests_info))
static int g_known_digest_nids[DIGESTS_COUNT] = {
    NID_sm3,
};

#define SEC_DIGESTS_RETURN_FAIL_IF(cond, mesg, ret) \
        if (unlikely(cond)) {\
            US_ERR(mesg); \
            return (ret); \
        }\

static int sec_digests_init(EVP_MD_CTX *ctx);
static int sec_digests_update(EVP_MD_CTX *ctx, const void *data, size_t data_len);
static int sec_digests_final(EVP_MD_CTX *ctx, unsigned char *digest);
static int sec_digests_cleanup(EVP_MD_CTX *ctx);
static int sec_digests_dowork(sec_digest_priv_t *md_ctx);

static int sec_digests_get_alg(int nid)
{
    int d_alg = 0;
    switch (nid) {
        case NID_sm3:
            d_alg = WCRYPTO_SM3;
            break;
        default:
            US_WARN("nid=%d don't support by sec engine.", nid);
            break;
    }
    return d_alg;
}

int sec_digests_init(EVP_MD_CTX *ctx)
{
    sec_digest_priv_t *md_ctx = NULL;
    if (unlikely(ctx == NULL)) {
        return OPENSSL_FAIL;
    }

    md_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(ctx);
    if (unlikely(md_ctx == NULL)) {
        return OPENSSL_FAIL;
    }

    int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));

    md_ctx->d_alg = sec_digests_get_alg(nid);
    md_ctx->state = SEC_DIGEST_INIT;
    
    return OPENSSL_SUCCESS;
}

static int sec_digests_update_inner(sec_digest_priv_t *md_ctx, size_t data_len, const void *data)
{
    int ret = OPENSSL_FAIL; 
    size_t left_len = data_len;
    const unsigned char* tmpdata = (const unsigned char *)data;
    while (md_ctx->last_update_bufflen + left_len > INPUT_CACHE_SIZE) {      
        int copy_to_bufflen = INPUT_CACHE_SIZE - md_ctx->last_update_bufflen;
        kae_memcpy(md_ctx->last_update_buff + md_ctx->last_update_bufflen, tmpdata, copy_to_bufflen);
        md_ctx->last_update_bufflen = INPUT_CACHE_SIZE;
        left_len -= copy_to_bufflen;
        tmpdata  += copy_to_bufflen;
        
        if (md_ctx->state == SEC_DIGEST_INIT) {
            md_ctx->state = SEC_DIGEST_FIRST_UPDATING;
        } else if (md_ctx->state == SEC_DIGEST_FIRST_UPDATING) {
            md_ctx->state = SEC_DIGEST_DOING;
        } else {
            (void)md_ctx->state;
        }

        ret = sec_digests_dowork(md_ctx);
        if (ret != KAE_SUCCESS) {
            US_WARN("do sec digest failed, switch to soft digest");
            goto do_soft_digest;
        }

        md_ctx->last_update_bufflen = 0;
        if (left_len <= INPUT_CACHE_SIZE) {
            md_ctx->last_update_bufflen = left_len;
            kae_memcpy(md_ctx->last_update_buff, tmpdata, md_ctx->last_update_bufflen);
            break;    
        }
    }
       
    return OPENSSL_SUCCESS;

do_soft_digest:
    if (md_ctx->state == SEC_DIGEST_FIRST_UPDATING
        && md_ctx->last_update_buff
        && md_ctx->last_update_bufflen != 0) {
        md_ctx->switch_flag = 1;
        sec_digests_soft_init(md_ctx->soft_ctx);
        ret = sec_digests_soft_update(md_ctx->soft_ctx, md_ctx->last_update_buff, md_ctx->last_update_bufflen);
        ret &= sec_digests_soft_update(md_ctx->soft_ctx, tmpdata, left_len);
        
        return ret;
    } else {
        US_ERR("do sec digest failed");
        return OPENSSL_FAIL;
    }
}

static int sec_digests_update(EVP_MD_CTX *ctx, const void *data, 
                              size_t data_len)
{
    SEC_DIGESTS_RETURN_FAIL_IF(unlikely(!ctx || !data),   "ctx is NULL.", OPENSSL_FAIL);
    sec_digest_priv_t *md_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(ctx);
    SEC_DIGESTS_RETURN_FAIL_IF(unlikely(md_ctx == NULL),   "md_ctx is NULL.", OPENSSL_FAIL);
    
    if (md_ctx->soft_ctx == NULL) {
        md_ctx->soft_ctx = EVP_MD_CTX_new();
    }
       
    if (md_ctx->switch_flag) {
        return sec_digests_soft_update(md_ctx->soft_ctx, data, data_len);
    }

    if (md_ctx->last_update_buff == NULL) {
        md_ctx->last_update_buff = (unsigned char *)kae_malloc(INPUT_CACHE_SIZE);
        if (md_ctx->last_update_buff == NULL) {
            US_WARN("NO MEM to alloc ctx->in");
            return OPENSSL_FAIL;
        }
    }

    int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));
    md_ctx->d_alg = sec_digests_get_alg(nid);
    unsigned char digest[HASH_LEN] = {0};
    md_ctx->out = digest;

    if (md_ctx->last_update_bufflen + data_len <= INPUT_CACHE_SIZE) {
        kae_memcpy(md_ctx->last_update_buff + md_ctx->last_update_bufflen, data, data_len);
        md_ctx->last_update_bufflen += data_len;
        return OPENSSL_SUCCESS;
    }

    return sec_digests_update_inner(md_ctx, data_len, data);
}

static int sec_digests_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
    int ret = KAE_FAIL;

    SEC_DIGESTS_RETURN_FAIL_IF(!ctx || !digest, "ctx is NULL.", OPENSSL_FAIL);
    sec_digest_priv_t *md_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(ctx);
    SEC_DIGESTS_RETURN_FAIL_IF(unlikely(md_ctx == NULL), "md_ctx is NULL.", OPENSSL_FAIL);
    
    if (md_ctx->switch_flag) {
        ret = sec_digests_soft_final(md_ctx->soft_ctx, digest);
        goto end;
    }

    if (md_ctx->last_update_bufflen == 0) {
        US_WARN("no data input, swich to soft digest");
        goto do_soft_digest;
    }

    if (md_ctx->last_update_buff && md_ctx->last_update_bufflen != 0) {
        if (md_ctx->state == SEC_DIGEST_INIT && md_ctx->last_update_bufflen < MIN_DIGEST_LEN) {
            US_WARN_LIMIT("small package offload, switch to soft digest");
            goto do_soft_digest;
        }
        
        uint32_t tmp = md_ctx->state;
        md_ctx->state = SEC_DIGEST_FINAL;

        md_ctx->out = digest;
        ret = sec_digests_dowork(md_ctx);
        if (ret != KAE_SUCCESS) {
            US_WARN("do sec digest failed, switch to soft digest");
            md_ctx->state = tmp;
            goto do_soft_digest;
        }
    } 

    ret = sec_digests_cleanup(ctx);
    if (ret == OPENSSL_SUCCESS) {
        US_DEBUG("do digest success. ctx=%p", md_ctx);
    } else {
        US_DEBUG("digest cleanup fail. ctx=%p", md_ctx);
    }
    
    return ret;    

do_soft_digest:
    if (md_ctx->state == SEC_DIGEST_INIT) {
        sec_digests_soft_work(md_ctx, md_ctx->last_update_bufflen, digest);
        ret = OPENSSL_SUCCESS;
    } else {
        US_ERR("do sec digest failed");
        ret = OPENSSL_FAIL;
    }
end:
    ret = sec_digests_cleanup(ctx);

    return ret;
}

static void sec_digests_update_md_ctx(sec_digest_priv_t* md_ctx)
{
    if (md_ctx->do_digest_len == 0) {
        return;
    }
    
    md_ctx->in += md_ctx->do_digest_len;
}

static int sec_digests_dowork(sec_digest_priv_t *md_ctx)
{
    SEC_DIGESTS_RETURN_FAIL_IF(md_ctx == NULL,   "md_ctx is NULL.", KAE_FAIL);

    if (md_ctx->e_digest_ctx == NULL) {
        md_ctx->e_digest_ctx = wd_digests_get_engine_ctx(md_ctx);
        if (md_ctx->e_digest_ctx == NULL) {
            US_WARN("failed to get engine ctx, switch to soft digest");
            return KAE_FAIL;
        }
    }

    digest_engine_ctx_t *e_digest_ctx = md_ctx->e_digest_ctx;
    md_ctx->in = md_ctx->last_update_buff;
    uint32_t leftlen = md_ctx->last_update_bufflen;
    while (leftlen != 0) {
        md_ctx->do_digest_len = wd_digests_get_do_digest_len(e_digest_ctx, leftlen);

        wd_digests_set_input_data(e_digest_ctx);
        
        int ret = wd_digests_doimpl(e_digest_ctx);
        if (ret != KAE_SUCCESS) {
            return ret;
        }
        
        wd_digests_get_output_data(e_digest_ctx);
        sec_digests_update_md_ctx(md_ctx);
        leftlen -= md_ctx->do_digest_len;
    }

    US_DEBUG("sec do digest success.");

    if (e_digest_ctx != NULL && md_ctx->state == SEC_DIGEST_FINAL) {
        (void)wd_digests_put_engine_ctx(e_digest_ctx);
        md_ctx->e_digest_ctx = NULL;
    }
    
    return KAE_SUCCESS;
}

static int sec_digests_cleanup(EVP_MD_CTX *ctx)
{
    sec_digest_priv_t *md_ctx = NULL;
    
    if (ctx == NULL) {
        return OPENSSL_FAIL;    
    }

    md_ctx = (sec_digest_priv_t *)EVP_MD_CTX_md_data(ctx);
    if (md_ctx == NULL) {
        return OPENSSL_FAIL;    
    }

    if (md_ctx->last_update_buff != NULL) {
        kae_free(md_ctx->last_update_buff);
    }

    if (md_ctx->e_digest_ctx != NULL) {
        (void)wd_digests_put_engine_ctx(md_ctx->e_digest_ctx);
        md_ctx->e_digest_ctx = NULL;
    }

    if (md_ctx->soft_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx->soft_ctx);
        md_ctx->soft_ctx = NULL;
    }

    return OPENSSL_SUCCESS;
}

/**
 * desc:bind digest func as hardware function
 * @return
 */
static EVP_MD *sec_set_digests_methods(struct digest_info digestinfo)
{
    const EVP_MD *default_digest = NULL;
    if (digestinfo.digest == NULL) {
        switch (digestinfo.nid) {
            case NID_sm3:
                default_digest = EVP_sm3();	
                digestinfo.digest = (EVP_MD *)EVP_MD_meth_dup(default_digest);
                if (digestinfo.digest == NULL) {
                    US_ERR("dup digest failed!");
                    return NULL;
                }
            break;
            default:
                return NULL;
        }
    }
    EVP_MD_meth_set_init(digestinfo.digest, sec_digests_init);
    EVP_MD_meth_set_update(digestinfo.digest, sec_digests_update);
    EVP_MD_meth_set_final(digestinfo.digest, sec_digests_final);
    EVP_MD_meth_set_cleanup(digestinfo.digest, sec_digests_cleanup);
    EVP_MD_meth_set_app_datasize(digestinfo.digest, sizeof(sec_digest_priv_t));
    return digestinfo.digest;
}

static void sec_create_digests(void)
{
    unsigned int i = 0;
    for (i = 0; i < DIGESTS_COUNT; i++) {
        if (g_sec_digests_info[i].digest == NULL) {
            g_sec_digests_info[i].digest = sec_set_digests_methods(g_sec_digests_info[i]);
        }
    }
}

/******************************************************************************
* function:
*         sec_engine_digests(ENGINE *e,
*                     const EVP_digest **digest,
*                     const int **nids,
*                     int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param digest [IN] - digest structure pointer
* @param nids   [IN] - digest function nids
* @param nid    [IN] - digest operation id
*
* description:
*   kae engine digest operations registrar
******************************************************************************/
int sec_engine_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    UNUSED(e);
    unsigned int i = 0;

    if ((nids == NULL) && ((digest == NULL) || (nid < 0))) {
        US_ERR("sec_engine_digests invalid input param.");
        if (digest != NULL) {
            *digest = NULL;
        }
        return OPENSSL_FAIL;
    }

    /* No specific digest => return a list of supported nids ... */
        /* No specific digest => return a list of supported nids ... */
    if (digest == NULL) {
        if (nids != NULL) {
            *nids = g_known_digest_nids;;
        }
        return BLOCKSIZES_OF(g_sec_digests_info);
    }
    for (i = 0; i < DIGESTS_COUNT; i++) {
        if (g_sec_digests_info[i].nid == nid) {
            if (g_sec_digests_info[i].digest == NULL) {
                sec_create_digests();
            }
            
            *digest = g_sec_digests_info[i].digest;
            return OPENSSL_SUCCESS;
        }
    }
    
    US_WARN("nid = %d not support.", nid);
    *digest = NULL;

    return OPENSSL_FAIL;
}

void sec_digests_free_methods(void)
{
    unsigned int i = 0;

    for (i = 0; i < DIGESTS_COUNT; i++) {
        if (g_sec_digests_info[i].digest != NULL) {
            EVP_MD_meth_free(g_sec_digests_info[i].digest);
            g_sec_digests_info[i].digest = NULL;
        }
    }
}

int digest_module_init(void)
{
    wd_digests_init_qnode_pool();
    sec_create_digests();
    return 1;
}
