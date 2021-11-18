// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/pureheader.h>

#include <hash.h>
#include <arith_uint256.h>
#include <crypto/scrypt/hash_scrypt.h>
#include <crypto/x11/hash_x11.h>
#include <util/strencodings.h>

uint256 CPureBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CPureBlockHeader::GetPoWHash(int algo) const
{
    switch (algo) {
    case ALGO_SHA256D:
        return GetHash();
    case ALGO_SCRYPT:
    {
        uint256 thash;
        scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
        return thash;
    }
    case ALGO_X11:
        return HashX11(BEGIN(nVersion), END(nNonce));
    case ALGO_UNKNOWN:
        return ArithToUint256(~arith_uint256(0));
    }
    assert(false);
    return GetHash();
}

void CPureBlockHeader::SetBaseVersion(int32_t nBaseVersion, int32_t nChainId)
{
    // assert(nBaseVersion >= 1 && nBaseVersion < VERSION_AUXPOW);
    assert(!IsAuxpow());
    nVersion = nBaseVersion | (nChainId * VERSION_CHAIN_START);
}

int GetAlgo(int nVersion)
{
    switch (nVersion & BLOCK_VERSION_ALGO) {
    case BLOCK_VERSION_SHA256D:
        return ALGO_SHA256D;
    case BLOCK_VERSION_SCRYPT:
        return ALGO_SCRYPT;
    case BLOCK_VERSION_X11:
        return ALGO_X11;
    }
    return ALGO_UNKNOWN;
}
