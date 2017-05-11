# -*- coding: utf-8 -*-

import unittest
from dnsResolveTester import DnsTestManager, pktType


class TestDnsResolve(unittest.TestCase):
    # def __init__(self):
        # self.dnsTester = None

    def setUp(self):
        self.dnsTester = DnsTestManager(ipTargetStr='172.31.81.137', cliIp='172.31.81.222', domainStr='www.u17.com', timeOutInt=50)

    def tearDown(self):
        del self.dnsTester

    def test_RecursionStr(self):
        self.dnsTester.testRecursionStr()

    def test_ErrorFormat(self):
        self.dnsTester.testErrorFormat()


if __name__ == '__main__':
    unittest.main()
    __author__ = 'admin'
