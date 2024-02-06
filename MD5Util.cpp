//
// Created by Francesco Laurita on 6/3/16.
//

#include <sstream>
#include "MD5Util.h"
#include <openssl/evp.h>
#include <openssl/md5.h>

std::string MD5Util::hexDigest(const std::string &str) {
  unsigned char digest[MD5_DIGEST_LENGTH];

  EVP_MD_CTX *mdctx;
  const EVP_MD *md = EVP_md5();

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, str.c_str(), str.size());
  EVP_DigestFinal_ex(mdctx, digest, NULL);
  EVP_MD_CTX_free(mdctx);

  char hexDigest[33] = {'\0'};
  for (int i = 0; i < 16; i++)
    std::sprintf(&hexDigest[i * 2], "%02x", (unsigned int)digest[i]);

  return std::string(hexDigest);
}
