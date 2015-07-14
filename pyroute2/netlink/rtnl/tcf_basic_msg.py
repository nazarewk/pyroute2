from pyroute2.netlink import nla, nlmsg

LAYERS = {
    0: 'link',
    1: 'network',
    2: 'transport',
}


class em_base(nlmsg):
    header = None
    fields = ()

    def __init__(self, buf=None, length=None, parent=None, debug=False,
                 init=None):
        length = length or self.get_size()
        nlmsg.__init__(self, buf, length, parent, debug, init)


class em_cmp(em_base):
    fields = (
        ('value', 'I'),
        ('mask', 'I'),
        ('offset', 'H'),
        ('align_flags', 'B'),  # 4b FLAGS, 4b ALIGN
        ('layer_opnd', 'B'),  # 4b OPND, 4b LAYER
    )

    OPERANDS = {
        0: 'eq',
        1: 'gt',
        2: 'lt',
    }

    class Flag:
        TRANS = 1

    def decode(self):
        em_base.decode(self)

        self['align'] = self['align_flags'] & 0x0F
        self['flags'] = self['align_flags'] >> 4
        self['layer'] = self['layer_opnd'] & 0x0F
        self['operand'] = self['layer_opnd'] >> 4

        del self['align_flags']
        del self['layer_opnd']

    def encode(self):
        self['align_flags'] = (self['flags'] << 4 +
                               self['align'])
        self['layer_opnd'] = (self['operand'] << 4 +
                              self['layer'])
        em_base.encode(self)

    def get_trans(self):
        return self['flags'] & self.Flag.TRANS

    def set_trans(self, val):
        self['flags'] &= ~self.Flag.TRANS | (val & self.Flag.TRANS)

    def __str__(self):
        align = self['align'] * 8

        attrs = ['layer %s' % LAYERS[self['layer']]]
        if self['mask']:
            attrs.append('mask 0x%%0%dx' % (align / 4) % self['mask'])
        if self.get_trans():
            attrs.append('trans')

        args = '%(align)s at %(offset)d %(attrs)s %(operand)s %(value)d' % {
            'align': 'u%d' % align,
            'offset': self['offset'],
            'attrs': ' '.join(attrs),
            'operand': self.OPERANDS[self['operand']],
            'value': self['value'],
        }
        return 'cmp(%s)' % args


class em_nbyte(em_base):
    fields = (
        ('offset', 'H'),
        ('layer_len', 'H'),
        # ('needle', '%ss' % self['length']),  # added dynamically
    )

    def decode(self):
        em_base.decode(self)
        self['layer'] = self['layer_len'] >> 12
        length = self['length'] = self['layer_len'] & 0x0FFF
        self.length += length
        del self['layer_len']

        self['needle'] = self.buf.read(length)

    def encode(self):
        self['layer_len'] = self['layer'] << 12 | self['length']
        self.fields = self.fields + (
            ('needle', '%ss' % self['length']),
        )
        em_base.encode(self)

    def __str__(self):
        needle = '0x%(hex_needle)s "%(needle)s"' % {
            'hex_needle': ''.join(hex(c)[2:] for c in self['needle']),
            'needle': str(self['needle'])[2:-1].replace('"', '\\"'),
        }
        return 'nbyte(%(needle)s at %(offset)d layer %(layer)s))' % {
            'needle': needle,
            'offset': self['offset'],
            'layer': self['layer'],
        }

class em_u32(em_base):
    NEXTHDR_MASK = -1
    fields = (
        ('value_mask', '>i'),
        ('value', '>i'),
        ('offset', 'i'),
        ('offset_mask', 'i'),
    )

    def is_nexthdr(self):
        return self['offset_mask'] == self.NEXTHDR_MASK


class tcf_basic(nla):
    nla_map = (
        ('TCA_BASIC_UNSPEC', 'none'),
        ('TCA_BASIC_CLASSID', 'uint32'),
        ('TCA_BASIC_EMATCH_TREE', 'ematch_tree'),
    )

    def __str__(self):
        return str(self.get_attr('TCA_BASIC_EMATCH_TREE'))

    class ematch_tree(nla):
        nla_map = (
            ('TCA_EMATCH_TREE_UNSPEC', 'none'),
            ('TCA_EMATCH_TREE_HDR', 'tcf_ematch_tree_hdr'),
            ('TCA_EMATCH_TREE_LIST', 'ematch_tree_list'),
        )

        def __str__(self):
            return str(self.get_attr('TCA_EMATCH_TREE_LIST'))

        class tcf_ematch_tree_hdr(nla):
            fields = (
                ('nmatches', 'H'),
                ('progid', 'H'),
            )

        class ematch_tree_list(nla):
            nla_map = (
                ('EMPTY', 'none'),
            )

            def __init__(self, buf=None, length=None, parent=None,
                         debug=False, init=None):
                if parent:
                    header = parent.get_attr('TCA_EMATCH_TREE_HDR')
                    self.nla_map = list(self.nla_map)
                    for i in range(header['nmatches'] + 1):
                        self.nla_map.append(
                            ('ITEM', 'ematch')
                        )
                nla.__init__(self, buf, length, parent, debug, init)

            def __str__(self):
                pieces = []
                rel_stack = []
                for item in self.get_attrs('ITEM'):
                    if item['kind'] == item.Kind.CONTAINER:
                        if item.get_inverted():
                            pieces.append('NOT')
                        pieces.append('(')
                        rel_stack.append(item.relations[item.get_relation()])
                    else:
                        pieces.append(str(item))

                    if rel_stack and item.get_relation() == item.Flag.REL_END:
                        pieces.append(') %s' % rel_stack.pop())

                return ' '.join(pieces)

            class ematch(nla):
                fields = (
                    ('matchid', 'H'),
                    ('kind', 'H'),
                    ('flags', 'H'),
                    ('pad', 'H'),
                )
                TCF_EM_KIND = {
                    # 0: em_container,  # doesn't need handling
                    1: em_cmp,
                    2: em_nbyte,
                    3: em_u32,
                    # 4: em_meta,
                    # 5: em_text,  # not implemented in iproute2
                    # 6: em_vlan,  # not implemented in iproute2
                    # 7: em_canid,
                    # 8: em_ipset,#
                }

                def get_match_cls(self):
                    kind = self['kind']
                    if kind in self.TCF_EM_KIND:
                        return self.TCF_EM_KIND[kind]
                    return self.hex

                def decode(self):
                    nla.decode(self)
                    seek = self.buf.tell()
                    cls = self.get_match_cls()
                    self['match'] = cls(self.buf, cls.get_size(), self)
                    self['match'].decode()
                    self.buf.seek(seek)

                def encode(self):
                    nla.encode(self)
                    if self['match']:
                        self['match'].encode()

                class Flag:
                    REL_END = 0
                    REL_AND = 1 << 0
                    REL_OR = 1 << 1
                    INVERT = 1 << 2
                    SIMPLE = 1 << 3
                    REL_MASK = REL_AND | REL_OR

                class Kind:
                    CONTAINER = 0
                    CMP = 1
                    NBYTE = 2
                    U32 = 3
                    META = 4
                    TEXT = 5
                    VLAN = 6
                    CANID = 7
                    IPSET = 8

                relations = {
                    0: '',
                    1: 'AND',
                    2: 'OR',
                    3: 'INVALID'
                }

                def get_relation(self):
                    return self['flags'] & self.Flag.REL_MASK

                def set_relation(self, value):
                    mask = self.Flag.REL_MASK
                    self['flags'] &= ~mask | (value & mask)

                def get_inverted(self):
                    return self['flags'] & self.Flag.INVERT

                def set_inverted(self, value):
                    mask = self.Flag.INVERT
                    self['flags'] &= ~mask | (value & mask)

                def get_simple(self):
                    return self['flags'] & self.Flag.SIMPLE

                def set_simple(self, value):
                    mask = self.Flag.SIMPLE
                    self['flags'] &= ~mask | (value & mask)

                def __str__(self):
                    if not self.get('match'):
                        return ''
                    s = [str(self['match'])]
                    if self.get_inverted():
                        s.insert(0, 'NOT')
                    rel = self.get_relation()
                    if rel:
                        s.append(self.relations[rel])
                    return ' '.join(s)
