//
// Created by Francesco Laurita on 6/3/16.
//

#include <sstream>
#include "MD5Util.h"

#if defined(__linux__)
#include <openssl/evp.h>
#include <openssl/md5.h>
#elif defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <CommonCrypto/CommonDigest.h>
#endif

std::string MD5Util::hexDigest(const std::string &str) {
    unsigned char digest[MD5_DIGEST_LENGTH];

#if defined(__linux__)
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_md5();

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, str.c_str(), str.size());
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);
#elif defined(__APPLE__)
    CC_MD5_CTX ctx;
    CC_MD5_Init(&ctx);
    CC_MD5_Update(&ctx, str.c_str(), (CC_LONG)str.size());
    CC_MD5_Final(digest, &ctx);
#endif

    char hexDigest[33] = {'\0'};
    for (int i = 0; i < 16; i++)
        std::sprintf(&hexDigest[i * 2], "%02x", (unsigned int)digest[i]);

    return std::string(hexDigest);
}
