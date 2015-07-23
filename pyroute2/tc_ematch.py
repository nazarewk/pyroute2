from pyroute2.netlink.rtnl.tcmsg import tcmsg
from pyroute2.netlink.rtnl.tcf_basic_msg import ematch, tcf_basic, LAYERS, \
    em_cmp, em_u32, transform_align, transform_layer, em_base


class Q(object):
    def __init__(self, kind_q_msg=0, invert=False, simple=False, match=None,
                 **kwargs):

        # Create from message
        if isinstance(kind_q_msg, tcmsg):
            if kind_q_msg.get_attr('TCA_KIND') != 'basic':
                raise TypeError
            else:
                kind_q_msg = kind_q_msg.get_attr('TCA_OPTIONS')

        if isinstance(kind_q_msg, tcf_basic):
            kind_q_msg = kind_q_msg.get_attr('TCA_BASIC_EMATCH_TREE')
        if isinstance(kind_q_msg, tcf_basic.ematch_tree):
            kind_q_msg = kind_q_msg.get_attr('TCA_EMATCH_TREE_LIST')
        if isinstance(kind_q_msg, tcf_basic.ematch_tree.ematch_tree_list):
            kind_q_msg = [
                (type, data)
                for type, data in kind_q_msg['attrs']
                if type == 'EMATCH']

        # if we have list, just use it and exit
        if isinstance(kind_q_msg, list):
            if isinstance(kind_q_msg[0], dict):
                self._list = [
                    ('EMATCH', item)
                    for item in kind_q_msg]
            else:
                self._list = [
                    ('EMATCH', item)
                    for _, item in kind_q_msg]
            return

        data = {
            'matchid': 0,
            'kind': ematch.kinds['container'],
            'relation': ematch.relations['END'],
            'invert': invert,
            'simple': simple,
            'pad': 0,
            'match': {}
        }
        self._list = [
            ['EMATCH', data]
        ]
        if isinstance(kind_q_msg, Q):
            self._list.extend(kind_q_msg._list)
            return
        if not isinstance(kind_q_msg, int):
            data['kind'] = ematch.kinds[kind_q_msg]
        else:
            data['kind'] = kind_q_msg

        if match:
            data['match'].update(match)
        if kwargs:
            data['match'].update(kwargs)

        match_cls = ematch.kind_to_class[data['kind']]
        assert issubclass(match_cls, em_base)
        match_cls.setdefaults(data['match'])
        match_cls.transform(data['match'])

        if not data['match']:
            data['match'] = None

    @property
    def list(self):
        return self._list

    def __iter__(self):
        for _, data in self._list:
            yield data

    def __getitem__(self, idx):
        if not isinstance(idx, int):
            raise TypeError
        return self._list[idx][1]

    def __invert__(self):
        self[0]['invert'] = not self[0]['invert']

    def get_last(self):
        for i in range(len(self._list)):
            item = self[-(i + 1)]
            if item['kind'] == ematch.kinds['container']:
                if item['relation'] == ematch.relations['END']:
                    return item
                break
        return self[-1]

    def __and__(self, q):
        if not isinstance(q, Q):
            raise TypeError('Right hand side must be of type `%s`' % Q)
        last = self.get_last()
        self._list.extend(q._list)
        last['relation'] = ematch.relations['AND']

    def __or__(self, q):
        if not isinstance(q, Q):
            raise TypeError('Right hand side must be of type `%s`' % Q)
        last = self.get_last()
        self._list.extend(q._list)
        last['relation'] = ematch.relations['OR']

    def __str__(self):
        pieces = []
        rel_stack = []
        for item in self:
            kind = item['kind']
            relation = item['relation']
            txt_kind = ematch.kinds[kind]
            if item['invert']:
                pieces.append('NOT')
            if txt_kind == 'container':
                pieces.append('(')
                rel_stack.append(ematch.relations[relation])
            else:
                parser = getattr(
                    self,
                    'dumps_%s' % ematch.kinds[item['kind']],
                    str)
                pieces.append(parser(item['match']))
                if relation:
                    pieces.append(ematch.relations[relation])

            if rel_stack and relation == ematch.Flag.REL_END:
                pieces.append(') %s' % rel_stack.pop())

        return ' '.join(pieces)

    def dumps_cmp(self, cmp):
        align = cmp['align'] * 8
        mask = cmp['mask']
        trans = cmp.get('trans', False)

        attrs = ['layer %s' % LAYERS[cmp['layer']]]
        if mask:
            attrs.append('mask 0x%%0%dx' % (align / 4) % mask)
        if trans:
            attrs.append('trans')

        args = '%(align)s at %(offset)d %(attrs)s %(operand)s %(val)d' % {
            'align': 'u%d' % align,
            'offset': cmp.get('offset', 0),
            'attrs': ' '.join(attrs),
            'operand': em_cmp.OPERANDS[cmp['operand']],
            'val': cmp['val'],
        }
        return 'cmp(%s)' % args

    def dumps_nbyte(self, nbyte):
        needle = '0x%(hex_needle)s "%(needle)s"' % {
            'hex_needle': ''.join(hex(c)[2:] for c in nbyte['needle']),
            'needle': str(nbyte['needle'])[2:-1].replace('"', '\\"'),
        }
        return 'nbyte(%(needle)s at %(offset)d layer %(layer)s))' % {
            'needle': needle,
            'offset': nbyte['offset'],
            'layer': nbyte['layer'],
        }

    def dumps_u32(self, u32):
        nexthdr = ('nexthdr+'
                   if u32['offset_mask'] == em_u32.NEXTHDR_MASK else
                   '')
        return 'u32(%(val)08x/%(mask)08x at %(nexthdr)s%(offset)d)' % {
            'val': u32['val'],
            'mask': u32['value_mask'],
            'nexthdr': nexthdr,
            'offset': u32['offset']
        }
