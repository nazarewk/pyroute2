import socket
from utils import require_user
from pyroute2 import IPRoute
from pyroute2.netlink.iproute import RTM_NEWQDISC
from pyroute2.netlink.iproute import RTM_NEWTFILTER
from pyroute2.netlink.iproute import RTM_NEWTCLASS
from pyroute2.netlink.iproute import TC_H_INGRESS


class BasicTest(object):

    def setup(self):
        require_user('root')
        self.ip = IPRoute()
        self.ip.link('add',
                     index=0,
                     ifname='dummyX',
                     linkinfo={'attrs': [['IFLA_INFO_KIND', 'dummy']]})
        self.interface = self.ip.link_lookup(ifname='dummyX')[0]

    def teardown(self):
        self.ip.link('delete', index=self.interface)
        self.ip.release()

    def get_qdiscs(self):
        return [x for x in self.ip.get_qdiscs() if
                x['index'] == self.interface]

    def get_qdisc(self):
        # get qdiscs list and filter out our interface
        qds = self.get_qdiscs()
        if qds:
            return qds[0]
        else:
            return None


class TestIngress(BasicTest):

    def test_simple(self):
        self.ip.tc(RTM_NEWQDISC, 'ingress', self.interface, 0xffff0000)
        qds = self.get_qdisc()
        # assert the list is not empty
        assert qds
        # assert there is the ingress queue
        assert qds.get_attr('TCA_KIND') == 'ingress'
        # assert it has proper handle and parent
        assert qds['handle'] == 0xffff0000
        assert qds['parent'] == TC_H_INGRESS

    def test_filter(self):
        self.test_simple()
        self.ip.tc(RTM_NEWTFILTER, 'u32', self.interface, 0,
                   protocol=socket.AF_INET,
                   parent=0xffff0000,
                   action='drop',
                   target=0x1,
                   rate='10kbit',
                   burst=10240,
                   limit=0,
                   prio=50,
                   keys=['0x0/0x0+12'])
        fls = self.ip.get_filters(index=self.interface, parent=0xffff0000)
        # assert there are filters
        assert fls
        # assert there is one police rule:
        prs = [x for x in fls
               if x.get_attr('TCA_OPTIONS') is not None and
               x.get_attr('TCA_OPTIONS').get_attr('TCA_U32_POLICE')
               is not None][0]
        # assert the police rule has specified parameters
        options = prs.get_attr('TCA_OPTIONS')
        police_u32 = options.get_attr('TCA_U32_POLICE')
        police_tbf = police_u32.get_attr('TCA_POLICE_TBF')
        assert police_tbf['rate'] == 1250
        assert police_tbf['mtu'] == 2040


class TestSfq(BasicTest):

    def test_sfq(self):
        self.ip.tc(RTM_NEWQDISC, 'sfq', self.interface, 0, perturb=10)
        qds = self.get_qdisc()
        assert qds
        assert qds.get_attr('TCA_KIND') == 'sfq'
        assert qds.get_attr('TCA_OPTIONS')['perturb_period'] == 10


class TestTbf(BasicTest):

    def test_tbf(self):
        self.ip.tc(RTM_NEWQDISC, 'tbf', self.interface, 0,
                   rate='220kbit',
                   latency='50ms',
                   burst=1540)
        qds = self.get_qdisc()
        assert qds
        assert qds.get_attr('TCA_KIND') == 'tbf'
        parms = qds.get_attr('TCA_OPTIONS').get_attr('TCA_TBF_PARMS')
        assert parms
        assert parms['rate'] == 27500


class TestHtb(BasicTest):

    def test_htb(self):
        # 8<-----------------------------------------------------
        # root queue
        self.ip.tc(RTM_NEWQDISC, 'htb', self.interface, 0x10000,
                   default=0x200000)

        qds = self.get_qdiscs()
        assert len(qds) == 1
        assert qds[0].get_attr('TCA_KIND') == 'htb'

        # 8<-----------------------------------------------------
        # classes
        self.ip.tc(RTM_NEWTCLASS, 'htb', self.interface, 0x10001,
                   parent=0x10000,
                   rate='256kbit',
                   burst=1024 * 6)
        self.ip.tc(RTM_NEWTCLASS, 'htb', self.interface, 0x10010,
                   parent=0x10001,
                   rate='192kbit',
                   burst=1024 * 6,
                   prio=1)
        self.ip.tc(RTM_NEWTCLASS, 'htb', self.interface, 0x10020,
                   parent=0x10001,
                   rate='128kbit',
                   burst=1024 * 6,
                   prio=2)
        cls = self.ip.get_classes(index=self.interface)
        assert len(cls) == 3

        # 8<-----------------------------------------------------
        # leaves
        self.ip.tc(RTM_NEWQDISC, 'sfq', self.interface, 0x100000,
                   parent=0x10010,
                   perturb=10)
        self.ip.tc(RTM_NEWQDISC, 'sfq', self.interface, 0x200000,
                   parent=0x10020,
                   perturb=10)
        qds = self.get_qdiscs()
        types = set([x.get_attr('TCA_KIND') for x in qds])
        assert types == set(('htb', 'sfq'))

        # 8<-----------------------------------------------------
        # filters
        self.ip.tc(RTM_NEWTFILTER, 'u32', self.interface, 0,
                   parent=0x10000,
                   prio=10,
                   protocol=socket.AF_INET,
                   target=0x10010,
                   keys=['0x0006/0x00ff+8', '0x0000/0xffc0+2'])
        self.ip.tc(RTM_NEWTFILTER, 'u32', self.interface, 0,
                   parent=0x10000,
                   prio=10,
                   protocol=socket.AF_INET,
                   target=0x10020,
                   keys=['0x5/0xf+0', '0x10/0xff+33'])
        # 2 filters + 2 autogenerated
        fls = self.ip.get_filters(index=self.interface)
        assert len(fls) == 4