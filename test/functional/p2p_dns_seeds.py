#!/usr/bin/env python3
# Copyright (c) 2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test ThreadDNSAddressSeed logic for querying DNS seeds."""

import itertools

from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework


class P2PDNSSeeds(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-dnsseed=1"]]

    def run_test(self):
        self.init_arg_tests()

    def init_arg_tests(self):
        fakeaddr = "fakenodeaddr.fakedomain.invalid."

        self.log.info("Check that setting -connect disables -dnsseed by default")
        self.nodes[0].stop_node()
        with self.nodes[0].assert_debug_log(expected_msgs=["DNS seeding disabled"]):
            self.start_node(0, [f"-connect={fakeaddr}"])

        self.log.info("Check that running -forcednsseed and -dnsseed=0 throws an error.")
        self.nodes[0].stop_node()
        self.nodes[0].assert_start_raises_init_error(
            expected_msg="Error: Cannot set -forcednsseed to true when setting -dnsseed to false.",
            extra_args=["-forcednsseed=1", "-dnsseed=0"],
        )

        self.log.info("Check that running -forcednsseed and -connect throws an error.")
        # -connect soft sets -dnsseed to false, so throws the same error
        self.nodes[0].stop_node()
        self.nodes[0].assert_start_raises_init_error(
            expected_msg="Error: Cannot set -forcednsseed to true when setting -dnsseed to false.",
            extra_args=["-forcednsseed=1", f"-connect={fakeaddr}"],
        )

        # Restore default bitcoind settings
        self.restart_node(0)

if __name__ == '__main__':
    P2PDNSSeeds().main()
