# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Pattern rule to print variables, e.g. make print-top_srcdir
print-%: FORCE
	@echo '$*'='$($*)'

DIST_SUBDIRS = secp256k1

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(HARDENED_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS) $(GPROF_CXXFLAGS) $(SANITIZER_CXXFLAGS)
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) $(HARDENED_CPPFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
PTHREAD_FLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
EXTRA_LIBRARIES =

BLINKHASH_INCLUDES=-I$(builddir) -I$(srcdir)/$(MINISKETCH_INCLUDE_DIR_INT) -I$(srcdir)/secp256k1/include -I$(srcdir)/$(UNIVALUE_INCLUDE_DIR_INT) $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS)

LIBBLINKHASH_SERVER=libblinkhash_server.a
LIBBLINKHASH_COMMON=libblinkhash_common.a
LIBBLINKHASH_CONSENSUS=libblinkhash_consensus.a
LIBBLINKHASH_CLI=libblinkhash_cli.a
LIBBLINKHASH_UTIL=libblinkhash_util.a
LIBBLINKHASH_CRYPTO_BASE=crypto/libblinkhash_crypto_base.a
LIBBLINKHASHQT=qt/libblinkhashqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

if ENABLE_ZMQ
LIBBLINKHASH_ZMQ=libblinkhash_zmq.a
endif
if BUILD_BLINKHASH_LIBS
LIBBLINKHASHCONSENSUS=libblinkhashconsensus.la
endif
if ENABLE_WALLET
LIBBLINKHASH_WALLET=libblinkhash_wallet.a
LIBBLINKHASH_WALLET_TOOL=libblinkhash_wallet_tool.a
endif

LIBBLINKHASH_CRYPTO= $(LIBBLINKHASH_CRYPTO_BASE)
if ENABLE_SSE41
LIBBLINKHASH_CRYPTO_SSE41 = crypto/libblinkhash_crypto_sse41.a
LIBBLINKHASH_CRYPTO += $(LIBBLINKHASH_CRYPTO_SSE41)
endif
if ENABLE_AVX2
LIBBLINKHASH_CRYPTO_AVX2 = crypto/libblinkhash_crypto_avx2.a
LIBBLINKHASH_CRYPTO += $(LIBBLINKHASH_CRYPTO_AVX2)
endif
if ENABLE_SHANI
LIBBLINKHASH_CRYPTO_SHANI = crypto/libblinkhash_crypto_shani.a
LIBBLINKHASH_CRYPTO += $(LIBBLINKHASH_CRYPTO_SHANI)
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*.h) $(wildcard secp256k1/src/*.c) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBBLINKHASH_CRYPTO) \
  $(LIBBLINKHASH_UTIL) \
  $(LIBBLINKHASH_COMMON) \
  $(LIBBLINKHASH_CONSENSUS) \
  $(LIBBLINKHASH_SERVER) \
  $(LIBBLINKHASH_CLI) \
  $(LIBBLINKHASH_IPC) \
  $(LIBBLINKHASH_WALLET) \
  $(LIBBLINKHASH_WALLET_TOOL) \
  $(LIBBLINKHASH_ZMQ)

lib_LTLIBRARIES = $(LIBBLINKHASHCONSENSUS)
noinst_LTLIBRARIES =

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BLINKHASHD
  bin_PROGRAMS += blinkhashd
endif

if BUILD_BLINKHASH_NODE
  bin_PROGRAMS += blinkhash-node
endif

if BUILD_BLINKHASH_CLI
  bin_PROGRAMS += blinkhash-cli
endif

if BUILD_BLINKHASH_TX
  bin_PROGRAMS += blinkhash-tx
endif

if ENABLE_WALLET
if BUILD_BLINKHASH_WALLET
  bin_PROGRAMS += blinkhash-wallet
endif
endif

if BUILD_BLINKHASH_UTIL
  bin_PROGRAMS += blinkhash-util
endif

.PHONY: FORCE check-symbols check-security
# blinkhash core #
BLINKHASH_CORE_H = \
  addrdb.h \
  addrman.h \
  addrman_impl.h \
  attributes.h \
  auxpow.h \
  banman.h \
  base58.h \
  bech32.h \
  blockencodings.h \
  blockfilter.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  common/bloom.h \
  compat.h \
  compat/assumptions.h \
  compat/byteswap.h \
  compat/cpuid.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/tx_check.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  dbwrapper.h \
  deploymentinfo.h \
  deploymentstatus.h \
  external_signer.h \
  flatfile.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  i2p.h \
  index/base.h \
  index/blockfilterindex.h \
  index/coinstatsindex.h \
  index/disktxpos.h \
  index/txindex.h \
  indirectmap.h \
  init.h \
  init/common.h \
  interfaces/chain.h \
  interfaces/echo.h \
  interfaces/handler.h \
  interfaces/init.h \
  interfaces/ipc.h \
  interfaces/node.h \
  interfaces/wallet.h \
  key.h \
  key_io.h \
  logging.h \
  logging/timer.h \
  mapport.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_permissions.h \
  net_processing.h \
  net_types.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  node/blockstorage.h \
  node/coin.h \
  node/coinstats.h \
  node/context.h \
  node/minisketchwrapper.h \
  node/psbt.h \
  node/transaction.h \
  node/ui_interface.h \
  node/utxo_snapshot.h \
  noui.h \
  outputtype.h \
  policy/feerate.h \
  policy/fees.h \
  policy/packages.h \
  policy/policy.h \
  policy/rbf.h \
  policy/settings.h \
  pow.h \
  protocol.h \
  psbt.h \
  random.h \
  randomenv.h \
  reverse_iterator.h \
  rpc/auxpow_miner.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/mining.h \
  rpc/net.h \
  rpc/protocol.h \
  rpc/rawtransaction.h \
  rpc/rawtransaction_util.h \
  rpc/register.h \
  rpc/request.h \
  rpc/server.h \
  rpc/util.h \
  scheduler.h \
  script/descriptor.h \
  script/keyorigin.h \
  script/sigcache.h \
  script/sign.h \
  script/signingprovider.h \
  script/standard.h \
  shutdown.h \
  signet.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadinterrupt.h \
  threadsafety.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  txorphanage.h \
  txrequest.h \
  undo.h \
  util/asmap.h \
  util/bip32.h \
  util/bytevectorhash.h \
  util/check.h \
  util/epochguard.h \
  util/error.h \
  util/fees.h \
  util/getuniquepath.h \
  util/golombrice.h \
  util/hash_type.h \
  util/hasher.h \
  util/macros.h \
  util/message.h \
  util/moneystr.h \
  util/rbf.h \
  util/readwritefile.h \
  util/serfloat.h \
  util/settings.h \
  util/sock.h \
  util/spanparsing.h \
  util/string.h \
  util/syscall_sandbox.h \
  util/system.h \
  util/thread.h \
  util/threadnames.h \
  util/time.h \
  util/tokenpipe.h \
  util/trace.h \
  util/translation.h \
  util/types.h \
  util/ui_change_type.h \
  util/url.h \
  util/vector.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/bdb.h \
  wallet/coincontrol.h \
  wallet/coinselection.h \
  wallet/context.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/dump.h \
  wallet/external_signer_scriptpubkeyman.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/ismine.h \
  wallet/load.h \
  wallet/receive.h \
  wallet/rpcwallet.h \
  wallet/salvage.h \
  wallet/scriptpubkeyman.h \
  wallet/spend.h \
  wallet/sqlite.h \
  wallet/transaction.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/wallettool.h \
  wallet/walletutil.h \
  walletinitinterface.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  zmq/zmqrpc.h \
  zmq/zmqutil.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh "$(abs_top_builddir)/src/obj/build.h" \
	  "$(abs_top_srcdir)"
libblinkhash_util_a-clientversion.$(OBJEXT): obj/build.h

ipc/capnp/libblinkhash_ipc_a-ipc.$(OBJEXT): $(libblinkhash_ipc_mpgen_input:=.h)

# server: shared between blinkhashd and blinkhash-qt
# Contains code accessing mempool and chain state that is meant to be separated
# from wallet and gui code (see node/README.md). Shared code should go in
# libblinkhash_common or libblinkhash_util libraries, instead.
libblinkhash_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(NATPMP_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libblinkhash_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libblinkhash_server_a_SOURCES = \
  addrdb.cpp \
  addrman.cpp \
  banman.cpp \
  blockencodings.cpp \
  blockfilter.cpp \
  chain.cpp \
  consensus/tx_verify.cpp \
  dbwrapper.cpp \
  deploymentstatus.cpp \
  flatfile.cpp \
  httprpc.cpp \
  httpserver.cpp \
  i2p.cpp \
  index/base.cpp \
  index/blockfilterindex.cpp \
  index/coinstatsindex.cpp \
  index/txindex.cpp \
  init.cpp \
  mapport.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  node/blockstorage.cpp \
  node/coin.cpp \
  node/coinstats.cpp \
  node/context.cpp \
  node/interfaces.cpp \
  node/minisketchwrapper.cpp \
  node/psbt.cpp \
  node/transaction.cpp \
  node/ui_interface.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/packages.cpp \
  policy/rbf.cpp \
  policy/settings.cpp \
  pow.cpp \
  rest.cpp \
  rpc/auxpow_miner.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  shutdown.cpp \
  signet.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  txorphanage.cpp \
  txrequest.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(BLINKHASH_CORE_H)

if ENABLE_WALLET
libblinkhash_server_a_SOURCES += wallet/init.cpp
endif
if !ENABLE_WALLET
libblinkhash_server_a_SOURCES += dummywallet.cpp
endif

if ENABLE_ZMQ
libblinkhash_zmq_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES) $(ZMQ_CFLAGS)
libblinkhash_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libblinkhash_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp \
  zmq/zmqutil.cpp
endif


# wallet: shared between blinkhashd and blinkhash-qt, but only linked
# when wallet enabled
libblinkhash_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES) $(SQLITE_CFLAGS)
libblinkhash_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libblinkhash_wallet_a_SOURCES = \
  wallet/coincontrol.cpp \
  wallet/context.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/dump.cpp \
  wallet/external_signer_scriptpubkeyman.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/interfaces.cpp \
  wallet/load.cpp \
  wallet/receive.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/scriptpubkeyman.cpp \
  wallet/spend.cpp \
  wallet/transaction.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/walletutil.cpp \
  wallet/coinselection.cpp \
  $(BLINKHASH_CORE_H)

if USE_SQLITE
libblinkhash_wallet_a_SOURCES += wallet/sqlite.cpp
endif
if USE_BDB
libblinkhash_wallet_a_SOURCES += wallet/bdb.cpp wallet/salvage.cpp
endif

libblinkhash_wallet_tool_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
libblinkhash_wallet_tool_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libblinkhash_wallet_tool_a_SOURCES = \
  wallet/wallettool.cpp \
  $(BLINKHASH_CORE_H)

# crypto primitives library
crypto_libblinkhash_crypto_base_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libblinkhash_crypto_base_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libblinkhash_crypto_base_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha_poly_aead.h \
  crypto/chacha_poly_aead.cpp \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/common.h \
  crypto/hkdf_sha256_32.cpp \
  crypto/hkdf_sha256_32.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/poly1305.h \
  crypto/poly1305.cpp \
  crypto/muhash.h \
  crypto/muhash.cpp \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha3.cpp \
  crypto/sha3.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/siphash.cpp \
  crypto/siphash.h

if USE_ASM
crypto_libblinkhash_crypto_base_a_SOURCES += crypto/sha256_sse4.cpp
endif

crypto_libblinkhash_crypto_sse41_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libblinkhash_crypto_sse41_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libblinkhash_crypto_sse41_a_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libblinkhash_crypto_sse41_a_CPPFLAGS += -DENABLE_SSE41
crypto_libblinkhash_crypto_sse41_a_SOURCES = crypto/sha256_sse41.cpp

crypto_libblinkhash_crypto_avx2_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libblinkhash_crypto_avx2_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libblinkhash_crypto_avx2_a_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libblinkhash_crypto_avx2_a_CPPFLAGS += -DENABLE_AVX2
crypto_libblinkhash_crypto_avx2_a_SOURCES = crypto/sha256_avx2.cpp

crypto_libblinkhash_crypto_shani_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
crypto_libblinkhash_crypto_shani_a_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libblinkhash_crypto_shani_a_CXXFLAGS += $(SHANI_CXXFLAGS)
crypto_libblinkhash_crypto_shani_a_CPPFLAGS += -DENABLE_SHANI
crypto_libblinkhash_crypto_shani_a_SOURCES = crypto/sha256_shani.cpp

# consensus: shared between all executables that validate any consensus rules.
libblinkhash_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
libblinkhash_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libblinkhash_consensus_a_SOURCES = \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/amount.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/tx_check.cpp \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/pureheader.cpp \
  primitives/pureheader.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/blinkhashconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  span.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  util/strencodings.cpp \
  util/strencodings.h \
  version.h \
	crypto/scrypt/scrypt.cpp \
	crypto/scrypt/scrypt_sse2.cpp \
	crypto/scrypt/sha256.cpp \
	crypto/scrypt/sha256.h \
	crypto/scrypt/hash_scrypt.h \
	crypto/x11/aes_helper.c \
	crypto/x11/blake.c \
	crypto/x11/bmw.c \
	crypto/x11/cubehash.c \
	crypto/x11/echo.c \
	crypto/x11/groestl.c \
	crypto/x11/jh.c \
	crypto/x11/keccak.c \
	crypto/x11/luffa.c \
	crypto/x11/shavite.c \
	crypto/x11/simd.c \
	crypto/x11/skein.c \
	crypto/x11/sph_blake.h \
	crypto/x11/sph_bmw.h \
	crypto/x11/sph_cubehash.h \
	crypto/x11/sph_echo.h \
	crypto/x11/sph_groestl.h \
	crypto/x11/sph_jh.h \
	crypto/x11/sph_keccak.h \
	crypto/x11/sph_luffa.h \
	crypto/x11/sph_shavite.h \
	crypto/x11/sph_simd.h \
	crypto/x11/sph_skein.h \
	crypto/x11/sph_types.h \
	crypto/x11/hash_x11.h

# common: shared between blinkhashd, and blinkhash-qt and non-server tools
libblinkhash_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
libblinkhash_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libblinkhash_common_a_SOURCES = \
  auxpow.cpp \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  common/bloom.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  deploymentinfo.cpp \
  external_signer.cpp \
  init/common.cpp \
  key.cpp \
  key_io.cpp \
  merkleblock.cpp \
  net_types.cpp \
  netaddress.cpp \
  netbase.cpp \
  net_permissions.cpp \
  outputtype.cpp \
  policy/feerate.cpp \
  policy/policy.cpp \
  protocol.cpp \
  psbt.cpp \
  rpc/rawtransaction_util.cpp \
  rpc/external_signer.cpp \
  rpc/util.cpp \
  scheduler.cpp \
  script/descriptor.cpp \
  script/sign.cpp \
  script/signingprovider.cpp \
  script/standard.cpp \
  warnings.cpp \
  $(BLINKHASH_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# sanity checks are linked.
libblinkhash_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
libblinkhash_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libblinkhash_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  interfaces/echo.cpp \
  interfaces/handler.cpp \
  interfaces/init.cpp \
  logging.cpp \
  random.cpp \
  randomenv.cpp \
  rpc/request.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util/asmap.cpp \
  util/bip32.cpp \
  util/bytevectorhash.cpp \
  util/error.cpp \
  util/fees.cpp \
  util/getuniquepath.cpp \
  util/hasher.cpp \
  util/sock.cpp \
  util/system.cpp \
  util/message.cpp \
  util/moneystr.cpp \
  util/rbf.cpp \
  util/readwritefile.cpp \
  util/settings.cpp \
  util/thread.cpp \
  util/threadnames.cpp \
  util/serfloat.cpp \
  util/spanparsing.cpp \
  util/strencodings.cpp \
  util/string.cpp \
  util/syscall_sandbox.cpp \
  util/time.cpp \
  util/tokenpipe.cpp \
  $(BLINKHASH_CORE_H)

if USE_LIBEVENT
libblinkhash_util_a_SOURCES += util/url.cpp
endif

# cli: shared between blinkhash-cli and blinkhash-qt
libblinkhash_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
libblinkhash_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libblinkhash_cli_a_SOURCES = \
  compat/stdin.h \
  compat/stdin.cpp \
  rpc/client.cpp \
  $(BLINKHASH_CORE_H)

nodist_libblinkhash_util_a_SOURCES = $(srcdir)/obj/build.h
#

# blinkhashd & blinkhash-node binaries #
blinkhash_daemon_sources = blinkhashd.cpp
blinkhash_bin_cppflags = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
blinkhash_bin_cxxflags = $(AM_CXXFLAGS) $(PIE_FLAGS)
blinkhash_bin_ldflags = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
blinkhash_daemon_sources += blinkhashd-res.rc
endif

blinkhash_bin_ldadd = \
  $(LIBBLINKHASH_SERVER) \
  $(LIBBLINKHASH_WALLET) \
  $(LIBBLINKHASH_COMMON) \
  $(LIBBLINKHASH_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBBLINKHASH_ZMQ) \
  $(LIBBLINKHASH_CONSENSUS) \
  $(LIBBLINKHASH_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

blinkhash_bin_ldadd += $(BOOST_LIBS) $(BDB_LIBS) $(MINIUPNPC_LIBS) $(NATPMP_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(SQLITE_LIBS)

blinkhashd_SOURCES = $(blinkhash_daemon_sources) init/blinkhashd.cpp
blinkhashd_CPPFLAGS = $(blinkhash_bin_cppflags)
blinkhashd_CXXFLAGS = $(blinkhash_bin_cxxflags)
blinkhashd_LDFLAGS = $(blinkhash_bin_ldflags)
blinkhashd_LDADD = $(LIBBLINKHASH_SERVER) $(blinkhash_bin_ldadd)

blinkhash_node_SOURCES = $(blinkhash_daemon_sources) init/blinkhash-node.cpp
blinkhash_node_CPPFLAGS = $(blinkhash_bin_cppflags)
blinkhash_node_CXXFLAGS = $(blinkhash_bin_cxxflags)
blinkhash_node_LDFLAGS = $(blinkhash_bin_ldflags)
blinkhash_node_LDADD = $(LIBBLINKHASH_SERVER) $(blinkhash_bin_ldadd) $(LIBBLINKHASH_IPC) $(LIBMULTIPROCESS_LIBS)

# blinkhash-cli binary #
blinkhash_cli_SOURCES = blinkhash-cli.cpp
blinkhash_cli_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES) $(EVENT_CFLAGS)
blinkhash_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
blinkhash_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
blinkhash_cli_SOURCES += blinkhash-cli-res.rc
endif

blinkhash_cli_LDADD = \
  $(LIBBLINKHASH_CLI) \
  $(LIBUNIVALUE) \
  $(LIBBLINKHASH_UTIL) \
  $(LIBBLINKHASH_CRYPTO)

blinkhash_cli_LDADD += $(BOOST_LIBS) $(EVENT_LIBS)
#

# blinkhash-tx binary #
blinkhash_tx_SOURCES = blinkhash-tx.cpp
blinkhash_tx_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
blinkhash_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
blinkhash_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
blinkhash_tx_SOURCES += blinkhash-tx-res.rc
endif

blinkhash_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBBLINKHASH_COMMON) \
  $(LIBBLINKHASH_UTIL) \
  $(LIBBLINKHASH_CONSENSUS) \
  $(LIBBLINKHASH_CRYPTO) \
  $(LIBSECP256K1)

blinkhash_tx_LDADD += $(BOOST_LIBS)
#

# blinkhash-wallet binary #
blinkhash_wallet_SOURCES = blinkhash-wallet.cpp
blinkhash_wallet_SOURCES += init/blinkhash-wallet.cpp
blinkhash_wallet_CPPFLAGS = $(blinkhash_bin_cppflags)
blinkhash_wallet_CXXFLAGS = $(blinkhash_bin_cxxflags)
blinkhash_wallet_LDFLAGS = $(blinkhash_bin_ldflags)
blinkhash_wallet_LDADD = $(LIBBLINKHASH_WALLET_TOOL) $(blinkhash_bin_ldadd)

if TARGET_WINDOWS
blinkhash_wallet_SOURCES += blinkhash-wallet-res.rc
endif
#

# blinkhash-util binary #
blinkhash_util_SOURCES = blinkhash-util.cpp
blinkhash_util_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
blinkhash_util_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
blinkhash_util_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
blinkhash_util_SOURCES += blinkhash-util-res.rc
endif

blinkhash_util_LDADD = \
  $(LIBBLINKHASH_COMMON) \
  $(LIBBLINKHASH_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBBLINKHASH_CONSENSUS) \
  $(LIBBLINKHASH_CRYPTO) \
  $(LIBSECP256K1)

blinkhash_util_LDADD += $(BOOST_LIBS)
#

# blinkhashconsensus library #
if BUILD_BLINKHASH_LIBS
include_HEADERS = script/blinkhashconsensus.h
libblinkhashconsensus_la_SOURCES = support/cleanse.cpp $(crypto_libblinkhash_crypto_base_a_SOURCES) $(libblinkhash_consensus_a_SOURCES)

libblinkhashconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libblinkhashconsensus_la_LIBADD = $(LIBSECP256K1)
libblinkhashconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_BLINKHASH_INTERNAL
libblinkhashconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crc32c/src/*.gcda crc32c/src/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += index/*.gcda index/*.gcno
CLEANFILES += interfaces/*.gcda interfaces/*.gcno
CLEANFILES += node/*.gcda node/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += rpc/*.gcda rpc/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += util/*.gcda util/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

EXTRA_DIST = $(CTAES_DIST)


config/blinkhash-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/blinkhash-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/blinkhash-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/blinkhash-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
	@echo "Running symbol and dynamic library checks..."
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

libblinkhash_ipc_mpgen_input = \
  ipc/capnp/echo.capnp \
  ipc/capnp/init.capnp
EXTRA_DIST += $(libblinkhash_ipc_mpgen_input)
%.capnp:

if BUILD_MULTIPROCESS
LIBBLINKHASH_IPC=libblinkhash_ipc.a
libblinkhash_ipc_a_SOURCES = \
  ipc/capnp/context.h \
  ipc/capnp/init-types.h \
  ipc/capnp/protocol.cpp \
  ipc/capnp/protocol.h \
  ipc/context.h \
  ipc/exception.h \
  ipc/interfaces.cpp \
  ipc/process.cpp \
  ipc/process.h \
  ipc/protocol.h
libblinkhash_ipc_a_CPPFLAGS = $(AM_CPPFLAGS) $(BLINKHASH_INCLUDES)
libblinkhash_ipc_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(LIBMULTIPROCESS_CFLAGS)

include $(MPGEN_PREFIX)/include/mpgen.mk
libblinkhash_ipc_mpgen_output = \
  $(libblinkhash_ipc_mpgen_input:=.c++) \
  $(libblinkhash_ipc_mpgen_input:=.h) \
  $(libblinkhash_ipc_mpgen_input:=.proxy-client.c++) \
  $(libblinkhash_ipc_mpgen_input:=.proxy-server.c++) \
  $(libblinkhash_ipc_mpgen_input:=.proxy-types.c++) \
  $(libblinkhash_ipc_mpgen_input:=.proxy-types.h) \
  $(libblinkhash_ipc_mpgen_input:=.proxy.h)
nodist_libblinkhash_ipc_a_SOURCES = $(libblinkhash_ipc_mpgen_output)
CLEANFILES += $(libblinkhash_ipc_mpgen_output)
endif

include Makefile.minisketch.include

include Makefile.crc32c.include
include Makefile.leveldb.include

include Makefile.test_util.include
include Makefile.test_fuzz.include

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif

include Makefile.univalue.include
