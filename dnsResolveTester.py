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
from socket import *


class DnsTesterClass(object):
    """
    不同测试类型共有的参数
    """

    def __init__(self,
                 etherDst=None, etherSrc=None,
                 ipDst=None, ipSrc=None,
                 portDst=None, portSrc=None,
                 domainTarget=None,
                 ipTarget = '192.168.1.250',
                 clientIp = '192.168.1.222',
                 iface='lan',
                 timeOut = 5):
        self.clientIp = clientIp
        self.domainName = domainTarget
        self.iface = iface
        self.dnsQueryPkt = None
        self.type = None
        self.dnsReplyPkt = None
        self.timeout = timeOut
        self.ipTarget = ipTarget
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 53))
        self.ptrNameHexStr = None

    def monitorDnsQuery(self,
                        iface=None,
                        senderIp=None, receiverIp=None,
                        domainTarget=None):
        """
        监控具有特定字段的的DNS查询报文
        :param iface:
        :param senderIP:
        :param receiverIp:
        :param domainTarget:
        :return: 符合要求的第一个DNS查询包 / None
        """
        # todo:加入iface和ip的筛选
        if domainTarget is None:
            sniffResult = sniff(stop_filter=lambda x: (x.haslayer('IP') and
                                                       x['IP'].src == senderIp and
                                                       x.haslayer('DNS') and
                                                       x['DNS'].qr == 0 and
                                                       x['DNS'].qd is not None),
                                # prn=lambda x:x.summary(),
                                timeout=self.timeout)
        else:
            sniffResult = sniff(stop_filter=lambda x: (x.haslayer('IP') and
                                                       x['IP'].src == senderIp and
                                                       x.haslayer('DNS') and
                                                       x['DNS'].qr == 0 and
                                                       x['DNS'].qd is not None and
                                                       domainTarget in x['DNS'].qd.qname),
                                # prn=lambda x: x.summary(),
                                timeout=self.timeout)
        try:
            tarPkt = sniffResult[-1]
            if tarPkt.haslayer('DNS') and tarPkt['DNS'].qr == 0 and tarPkt['DNS'].qd is not None:
                self.dnsQueryPkt = tarPkt
                print('[*] DNS pkt caught.')
                return self.dnsQueryPkt
            else:
                print('[*] error in monitorDnsQuery: no DNS pkt caught.')
                return None
        except Exception as e:
            print('[*] error in monitorDnsQuery:'+str(e))

    def monitorTcpPkt(self,
                      iface = None,
                      senderIp = None, receiverIp = None):
        """
        监控TCP 请求
        :param iface:
        :param senderIp:
        :param receiverIp:
        :return: 符合要求的TCP包 / None
        """
        # todo:加入iface和ip的筛选
        try:
            sniffPkt =  sniff(stop_filter=lambda x:(x.haslayer('TCP') and
                                                      x['IP'].src == senderIp and
                                                      x['IP'].dst == receiverIp),
                                 timeout = self.timeout)[-1]
            if sniffPkt.haslayer('TCP') and sniffPkt['IP'].dst == receiverIp and sniffPkt['IP'].src == senderIp:
                print('[*] required TCP pkt caught.')
                return sniffPkt
            else:
                return None
        except Exception as e:
            print('[*] error in monitorTcpPkt:' + str(e))


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
        oriHexStr = binascii.hexlify(oriHexStr)
        oriSplit = oriHexStr.split(targetHexStr)
        if len(oriSplit) >= 3:
            editHexStr = oriSplit[0] + targetHexStr + oriSplit[1]
            editHexStr += 'c0' + ('00' + hex(editHexStr.find(targetHexStr) / 2)[2:])[-2:]
            editHexStr += oriSplit[2]
            for i in range(3, len(oriSplit)):
                editHexStr += targetHexStr
                editHexStr += oriSplit[i]
            return binascii.unhexlify(editHexStr)
        else:
            return binascii.unhexlify(oriHexStr)

    def confirmAssert(self,
                      pktType = 'DNS',
                      tarDomain = None,
                      ipSrc = None, ipDst = None,):
        """
        确认客户机解析后做出正确的回应
        :param pktType:
        :param tarDomain:
        :param ipSrc:
        :param ipDst:
        :return:
        """
        if pktType == 'DNS':
            #todo 检测DNS包重新请求
            pkt = self.monitorDnsQuery(senderIp = ipSrc, receiverIp=ipDst,domainTarget=tarDomain)
            assert pkt is not None, 'no DNS pkt caught, test fail'

        if pktType == 'TCP':
            #todo 检测TCP包重新请求
            pkt = self.monitorTcpPkt(senderIp=ipSrc, receiverIp=ipDst)
            assert pkt is not None, 'no TCP pkt caught, test fail'

    def sendBySock(self, replyPkt = None, queryPkt = None):
        if queryPkt is not None and replyPkt is not None:
            try:
                self.sock.sendto(str(replyPkt), (queryPkt['IP'].src, queryPkt['UDP'].sport))
                print('[*] pack send: ' + str(binascii.hexlify(str(replyPkt))))
                return True
            except Exception as e:
                print('[*] error in sendBySock:'+str(e))
                return False
        else:
            return False

    def sendByScapy(self, replyPkt = None, queryPkt = None):
        if queryPkt is not None and replyPkt is not None:
            try:
                sendp(Ether()/IP(src=queryPkt['IP'].dst, dst=queryPkt['IP'].src)/UDP(sport=queryPkt['UDP'].dport, dport=queryPkt['UDP'].sport)/replyPkt)
                print('[*] pack send: ' + str(binascii.hexlify(replyPkt)))
                return True
            except Exception as e:
                print('[*] error in sendByScapy:'+str(e))
                return False
        else:
            return False

    def clearPkt(self):
        self.dnsQueryPkt = None
        self.dnsReplyPkt = None

    def createReply(self,
                    etherDst=None, etherSrc=None,
                    ipDst=None, ipSrc=None,
                    portDst=None, portSrc=None,
                    dnsQuery = None, testType = pktType.RECURSION_STR):
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
        if pkt is None:
            print('[*] error in createReply: no pkt found')
            return None

        #造回复
        if testType == pktType.RECURSION_STR:
            #递归 有回答 无指针
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=0,
                ra=1,
                rcode=0,
                ancount=1,
                an=(DNSRR(rrname=pkt['DNS'].qd.qname,
                        type='A',
                        rclass='IN',
                        ttl=45678,
                        rdata=self.ipTarget)
                    )
            )

        elif testType == pktType.RECURSION_STR_PTR:
            #递归 有回答 单个指针
            dnsRply = DNS(qr=1,
                      id=pkt['DNS'].id,
                      qd=pkt['DNS'].qd,
                      rd=pkt['DNS'].rd,
                      tc=0,
                      ra=1,
                      rcode=0,
                      ancount=1,
                      an=(DNSRR(rrname=pkt['DNS'].qd.qname,
                                type='A',
                                rclass='IN',
                                ttl=45678,
                                rdata=self.ipTarget)
                          ))
            dnsRply = self.replaceWithPtr(oriHexStr=str(dnsRply), targetHexStr=self.domainToHex(pkt['DNS'].qd.qname))

        elif testType == pktType.RECURSION_MUTI_PTR:
            #todo 递归 嵌套指针
            dnsRply = DNS(qr=1,
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
                                rdata='testprefix.' + pkt['DNS'].qd.qname) /
                          DNSRR(rrname='testprefix.' + pkt['DNS'].qd.qname,
                                type='A',
                                rclass='IN',
                                ttl=45678,
                                rdata=self.ipTarget)
                          ))
            dnsRply = self.replaceWithPtr(oriHexStr=str(dnsRply), targetHexStr=self.domainToHex(pkt['DNS'].qd.qname))
            dnsRply = self.replaceWithPtr(oriHexStr=str(dnsRply), targetHexStr=self.domainToHex(pkt['DNS'].qd.qname))
            dnsRply = self.replaceWithPtr(oriHexStr=str(dnsRply), targetHexStr=self.domainToHex('testprefix')+'c00c')

        elif testType == pktType.NO_RECUR_STR:
            #迭代回复 无指针
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=0,
                ra=0,
                rcode=0,
                ancount=1,
                an=(DNSRR(rrname=pkt['DNS'].qd.qname,
                        type='A',
                        rclass='IN',
                        ttl=45678,
                        rdata=self.ipTarget)
                    )
            )

        elif testType == pktType.NO_RECUR_STR_PTR:
            #迭代回复 有回答 单个指针
            dnsRply = DNS(qr=1,
                      id=pkt['DNS'].id,
                      qd=pkt['DNS'].qd,
                      rd=pkt['DNS'].rd,
                      tc=0,
                      ra=0,
                      rcode=0,
                      ancount=1,
                      an=(DNSRR(rrname=pkt['DNS'].qd.qname,
                                type='A',
                                rclass='IN',
                                ttl=45678,
                                rdata=self.ipTarget)
                          ))
            dnsRply = self.replaceWithPtr(oriHexStr=str(dnsRply), targetHexStr=self.domainToHex(pkt['DNS'].qd.qname))

        elif testType == pktType.NO_RECUR_MUTI_PTR:
            #todo 迭代回复 嵌套指针
            dnsRply = DNS(qr=1,
                      id=pkt['DNS'].id,
                      qd=pkt['DNS'].qd,
                      rd=pkt['DNS'].rd,
                      tc=0,
                      ra=0,
                      rcode=0,
                      ancount=2,
                      an=(DNSRR(rrname=pkt['DNS'].qd.qname,
                                type='CNAME',
                                rclass='IN',
                                ttl=45678,
                                rdata='testprefix.' + pkt['DNS'].qd.qname) /
                          DNSRR(rrname='testprefix.' + pkt['DNS'].qd.qname,
                                type='A',
                                rclass='IN',
                                ttl=45678,
                                rdata=self.ipTarget)
                          ))
            dnsRply = self.replaceWithPtr(oriHexStr=str(dnsRply), targetHexStr=self.domainToHex(pkt['DNS'].qd.qname))
            dnsRply = self.replaceWithPtr(oriHexStr=str(dnsRply), targetHexStr=self.domainToHex(pkt['DNS'].qd.qname))
            dnsRply = self.replaceWithPtr(oriHexStr=str(dnsRply), targetHexStr=self.domainToHex('testprefix')+'c00c')

        elif testType == pktType.ERROR_TC:
            #截断 递归 有回答 无指针
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=1,
                ra=1,
                rcode=0,
                ancount=1,
                an=(DNSRR(rrname=pkt['DNS'].qd.qname,
                        type='A',
                        rclass='IN',
                        ttl=45678,
                        rdata=self.ipTarget)
                    )
            )

        elif testType == pktType.ERROR_FORMAT:
            #报文格式错误
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=0,
                ra=1,
                rcode=1,
                ancount=0)


        elif testType == pktType.ERROR_SERVER_FAILURE:
            #服务器故障
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=0,
                ra=1,
                rcode=2,
                ancount=0)

        elif testType == pktType.ERROR_WRONG_NAME:
            #域名不存在
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=0,
                ra=1,
                rcode=3,
                ancount=0)

        elif testType == pktType.ERROR_UNSUPPORT:
            #不支持的查询
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=0,
                ra=1,
                rcode=4,
                ancount=0)

        elif testType == pktType.ERROR_REFUSED:
            #拒绝服务
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=0,
                ra=1,
                rcode=5,
                ancount=0)

        elif testType == pktType.ERROR_RESERVED:
            #拒绝服务
            dnsRply = DNS(qr=1,
                id=pkt['DNS'].id,
                qd=pkt['DNS'].qd,
                rd=pkt['DNS'].rd,
                tc=0,
                ra=1,
                rcode=6,
                ancount=0)
        else:
            dnsRply = None
        return dnsRply



class DnsTestManager(DnsTesterClass):
    def __init__(self,
                 domainStr=None,
                 ipTargetStr = '192.168.1.250',
                 cliIp = '192.168.1.222',
                 ifaceStr='lan',
                 timeOutInt = 5):
        super(DnsTestManager, self).__init__(domainTarget=domainStr,
                                             ipTarget = ipTargetStr,
                                             clientIp = cliIp,
                                             iface=ifaceStr,
                                             timeOut=timeOutInt)

    def testRecursionStr(self):
        self.monitorDnsQuery(senderIp= self.clientIp, domainTarget=self.domainName )
        reply = self.createReply(dnsQuery=self.dnsQueryPkt, testType=pktType.RECURSION_STR)
        self.sendBySock(replyPkt=reply, queryPkt=self.dnsQueryPkt)
        self.confirmAssert(pktType='TCP', ipSrc=self.dnsQueryPkt['IP'].src, ipDst=self.ipTarget)

    def testErrorFormat(self):
        self.monitorDnsQuery(senderIp= self.clientIp, domainTarget=self.domainName)
        reply = self.createReply(dnsQuery=self.dnsQueryPkt, testType=pktType.ERROR_FORMAT)
        self.sendBySock(replyPkt=reply, queryPkt=self.dnsQueryPkt)
        self.confirmAssert(pktType= 'DNS', ipSrc=self.clientIp, ipDst=self.dnsQueryPkt['IP'].dst, tarDomain=self.dnsQueryPkt['DNS'].qd.qname)

if __name__ == '__main__':
    dnsTester = DnsTestManager(ipTargetStr='172.31.81.137', cliIp='172.31.81.222', domainStr='www.u17.com', timeOutInt=50)
    dnsTester.testErrorFormat()
    dnsTester.testRecursionStr()