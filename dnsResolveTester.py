# -*- coding: utf-8 -*-

class testTypeDict():
    """
    测试类型字典
    """

    def __init__(self):
        self.RECURSION_STR = 1
        self.RECURSION_STR_PTR = 2
        self.RECURSION_MUTI_PTR = 3

        self.NO_RECUR_STR = 4
        self.NO_RECUR_STR_PTR = 5
        self.NO_RECUR_MUTI_PTR = 6

        self.ERROR_TC = 11
        self.ERROR_FORMAT = 12
        self.ERROR_SERVER_FAILURE = 13
        self.ERROR_WRONG_NAME = 14
        self.ERROR_UNSUPPORT = 15
        self.ERROR_REFUSED = 16
        self.ERROR_RESERVED = 17


pktType = testTypeDict()

from scapy.all import *
import binascii
import socket


class DnsTesterClass(object):
    """
    不同测试类型共有的参数
    """

    def __init__(self,
                 etherDst=None, etherSrc=None,
                 ipDst=None, ipSrc=None,
                 portDst=None, portSrc=None,
                 domainTarget=None,
                 iface='lan'):
        self.domainName = domainTarget
        self.iface = iface
        self.dnsQueryPkt = None
        self.type = None
        self.dnsReplyPkt = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0',53))

    def monitorDnsQuery(self,
                        iface=None,
                        senderIP=None, receiverIp=None,
                        domainTarget=None):
        """
        监控具有特定字段的的DNS查询报文
        :param iface:
        :param senderIP:
        :param receiverIp:
        :param domainTarget:
        :return: 符合要求的第一个DNS查询包
        """
        # todo:加入iface和ip的筛选
        if domainTarget is None:
            sniffResult = sniff(filter='dns',
                                stop_filter=lambda x: (x.haslayer('DNS') and
                                                       x['DNS'].qr == 0 and
                                                       x['DNS'].qd is not None),
                                prn=lambda x:x.summary())
        else:
            sniffResult = sniff(filter='dns',
                                stop_filter=lambda x: (x.haslayer('DNS') and
                                                       x['DNS'].qr == 0 and
                                                       x['DNS'].qd is not None and
                                                       domainTarget in x['DNS'].qd.qname),
                                prn=lambda x: x.summary())
        self.dnsQueryPkt = sniffResult[-1]
        return self.dnsQueryPkt

    def domainToHex(self, domainStr='www.baidu.com'):
        """
        将域名转换为标签序列的hexstr表示
        :param domainStr:
        :return: 标签序列， hexstr表示，eg- '03e1e2e305e1e2e3e4e500'
        """
        try:
            domainNameList = domainStr.split('.')
            hexStr = ''
            for label in domainNameList:
                hexStr += ('00' + hex(len(label))[2:])[-2:]
                hexStr += binascii.hexlify(label)
            return hexStr + '00'

        except Exception as e:
            print('error in domainToHex:' + e.message)
            return None

    def replaceWithPtr(self, oriHexStr, targetHexStr):
        """
        替换原始hexStr中的第二个targetHexStr为标签序列指针
        :param oriHexStr:
        :param targetHexStr:
        :return: 指针替换后的hexStr
        """
        #todo: 增加部分替换，嵌套替换
        oriSplit = oriHexStr.split(targetHexStr)
        if len(oriSplit) == 3:
            editHexStr = oriSplit[0] + targetHexStr + oriSplit[1]
            editHexStr += 'c0' + ('00' + hex(editHexStr.find(targetHexStr) / 2)[2:])[-2:]
            editHexStr += oriSplit[2]
            return editHexStr
        else:
            return oriHexStr

    def createReply(self,
                    etherDst=None, etherSrc=None,
                    ipDst=None, ipSrc=None,
                    portDst=None, portSrc=None,
                    dnsQuery = None):
        """
        构造DNS回复报文
        :param etherDst:
        :param etherSrc:
        :param ipDst:
        :param ipSrc:
        :param portDst:
        :param portSrc:
        :param dnsQuery:
        :return:
        """
        pkt = dnsQuery
        fakeDnsPkt = DNS(qr=1,
                          id=pkt['DNS'].id,
                          qd=pkt['DNS'].qd,
                          rd=pkt['DNS'].rd,
                          tc=0,
                          ra=1,
                          rcode=0,
                          ancount=2,
                          an=(DNSRR(rrname=pkt['DNS'].qd.qname,
                                    type='CNAME',
                                    rclass='IN',
                                    ttl=45678,
                                    rdata='test.yy.yy') /
                              DNSRR(rrname='test.yy.yy',
                                    type='A',
                                    rclass='IN',
                                    ttl=45678,
                                    rdata='192.168.1.99')
                              )
                          )
        return str(fakeDnsPkt)



if __name__ == '__main__':
    dnsTester = DnsTesterClass()
    dnsTester.monitorDnsQuery(domainTarget= 'www.qaz.com')