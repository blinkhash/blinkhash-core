// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, int algo)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.fPowLimit).GetCompact();

    // Genesis block
    if (pindexLast == nullptr)
        return nProofOfWorkLimit;

    if (params.fPowAllowMinDifficultyBlocks) {
        /* khal's port of this code from Blinkhash to the old blinkhashd
           has a bug:  Comparison of block times is done by an unsigned
           difference.  Consequently, the minimum difficulty is also
           applied if the block's timestamp is earlier than the preceding
           block's.  Reproduce this.  */
        if (pblock->GetBlockTime() < pindexLast->GetBlockTime())
            return nProofOfWorkLimit;

        // Special difficulty rule for testnet:
        // If the new block's timestamp is more than 2 minutes
        // then allow mining of a min-difficulty block.
        if (pblock->nTime > pindexLast->nTime + params.nMultiAlgoTargetSpacing * 2)
            return nProofOfWorkLimit;
        else {
            // Return the last non-special-min-difficulty-rules-block
            const CBlockIndex* pindex = pindexLast;
            while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                pindex = pindex->pprev;
            return pindex->nBits;
        }
    }

    // find first block in averaging interval
  	// Go back by what we want to be nAveragingInterval blocks per algo
  	const CBlockIndex* pindexFirst = pindexLast;
  	for (int i = 0; pindexFirst && i < NUM_ALGOS * params.nAveragingInterval; i++) {
  		  pindexFirst = pindexFirst->pprev;
  	}

    const CBlockIndex* pindexPrevAlgo = GetLastBlockIndexForAlgo(pindexLast, algo);
  	if (pindexPrevAlgo == nullptr || pindexFirst == nullptr) {
  		return nProofOfWorkLimit;
  	}

    // Limit adjustment step
  	// Use medians to prevent time-warp attacks
  	int64_t nActualTimespan = pindexLast->GetMedianTimePast() - pindexFirst->GetMedianTimePast();
    int64_t nAveragingTargetTimespan = params.nAveragingInterval * params.nMultiAlgoTargetSpacing;
  	nActualTimespan = nAveragingTargetTimespan + (nActualTimespan - nAveragingTargetTimespan)/4;
    int64_t nMinActualTimespan = nAveragingTargetTimespan * (100 - params.nMaxAdjustUp) / 100;
    int64_t nMaxActualTimespan = nAveragingTargetTimespan * (100 + params.nMaxAdjustDown) / 100;

    if (nActualTimespan < nMinActualTimespan)
  		nActualTimespan = nMinActualTimespan;
  	if (nActualTimespan > nMaxActualTimespan)
  		nActualTimespan = nMaxActualTimespan;

    // Global retargeting
  	arith_uint256 bnNew;
  	bnNew.SetCompact(pindexPrevAlgo->nBits);
  	bnNew *= nActualTimespan;
  	bnNew /= nAveragingTargetTimespan;

    // Algorithmic retargeting
  	int nAdjustments = pindexPrevAlgo->nHeight + NUM_ALGOS - 1 - pindexLast->nHeight;
  	if (nAdjustments > 0) {
        for (int i = 0; i < nAdjustments; i++) {
      			bnNew *= 100;
      			bnNew /= (100 + params.nLocalTargetAdjustment);
      	}
    }
    else if (nAdjustments < 0) {
        for (int i = 0; i < -nAdjustments; i++){
            bnNew *= (100 + params.nLocalTargetAdjustment);
            bnNew /= 100;
        }
    }

    if (bnNew > UintToArith256(params.fPowLimit)) {
        bnNew = UintToArith256(params.fPowLimit);
    }

    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4)
        nActualTimespan = params.nPowTargetTimespan / 4;
    if (nActualTimespan > params.nPowTargetTimespan * 4)
        nActualTimespan = params.nPowTargetTimespan * 4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.fPowLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.fPowLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
