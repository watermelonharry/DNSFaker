# -*- coding: utf-8 -*-

import unittest
from dnsResolveTester import DnsTestManager, pktType


class TestDnsResolve(unittest.TestCase):
    def setUp(self):
        self.dnsTester = DnsTestManager(ipTargetStr='172.31.81.137', cliIp='172.31.81.222', domainStr='www.u17.com', timeOutInt=500)


    def tearDown(self):
        del self.dnsTester

    #正常用例
    def test_RecursionStr(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testRecursionStr()

    def test_RecursionMultiPtr(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testRecursionMultiPtr()

    def test_RecursionStrPtr(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testRecursionStrPtr()

    def testNoRecurStr(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testNoRecurStr()

    def testNoRecurStrPtr(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testNoRecurStrPtr()

    def testNoRecurMultiPtr(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testNoRecurMultiPtr()

    #异常用例
    def test_ErrorFormat(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testErrorFormat()

    def test_ErrorTC(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testErrorTC()

    def testErrorServerFailure(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testErrorServerFailure()

    def testErrorWrongName(self):
        #todo 正常为DNS请求， 重发请求也行？
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testErrorWrongName()

    def testErrorUnsupport(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testErrorUnsupport()

    def testErrorRefused(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testErrorRefused()

    def testErrorReserved(self):
        raw_input(u'按回车开始运行下一个测试用例')
        self.dnsTester.testErrorReserved()

if __name__ == '__main__':
    unittest.main()
    __author__ = 'admin'
