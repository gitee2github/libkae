/*
 * Copyright (C) 2019. Huawei Technologies Co.,Ltd.All rights reserved.
 * 
 * Description:  This file provides the implemenation for switch to soft digests
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

#include <asm/byteorder.h>
#include "sec_digests_soft.h"
#include "engine_opensslerr.h"
#include "engine_log.h"

int sec_digests_soft_init(EVP_MD_CTX *ctx)
{
    const EVP_MD *sm3_md = EVP_sm3();
    int ctx_len = EVP_MD_meth_get_app_datasize(sm3_md);
    if (ctx->md_data == NULL) {
        ctx->md_data = OPENSSL_malloc(ctx_len);
    }
    if (!ctx->md_data) {
        KAEerr(KAE_F_SM3_SOFT_INIT, KAE_R_MALLOC_FAILURE);
        US_ERR("malloc md_data failed");
        return 0;
    }
    
    return EVP_MD_meth_get_init (sm3_md)(ctx);
}

int sec_digests_soft_update(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
    const EVP_MD *sm3_md = EVP_sm3();
    return EVP_MD_meth_get_update (sm3_md)(ctx, data, data_len);
}

int sec_digests_soft_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
    US_WARN_LIMIT("call sec_sm3_soft_final");
    const EVP_MD *sm3_md = EVP_sm3();
    int ret = EVP_MD_meth_get_final(sm3_md)(ctx, digest);
    if (ctx->md_data) {
        OPENSSL_free(ctx->md_data);
    }
    
    return ret;
}

void sec_digests_soft_work(sec_digest_priv_t *md_ctx, int len, unsigned char *digest)
{
    if (md_ctx->soft_ctx == NULL) {
        md_ctx->soft_ctx = EVP_MD_CTX_new();
    }
    if (md_ctx->last_update_buff == NULL) {
        md_ctx->last_update_buff = (unsigned char *)kae_malloc(len * sizeof(unsigned char));
        if (md_ctx->last_update_buff == NULL) {
            goto end;
        }
    }

    sec_digests_soft_init(md_ctx->soft_ctx);
    sec_digests_soft_update(md_ctx->soft_ctx, md_ctx->last_update_buff, len);
    sec_digests_soft_final(md_ctx->soft_ctx, digest);

end:    
    if (md_ctx->soft_ctx != NULL) {
        EVP_MD_CTX_free(md_ctx->soft_ctx);
        md_ctx->soft_ctx = NULL;
    }
    
    if (md_ctx->last_update_buff != NULL) {
        kae_free(md_ctx->last_update_buff);
    }

    return;
}

