from pyroute2.netlink import nla, nlmsg, NLA_F_NESTED

LAYERS = {
    0: 'link',
    1: 'network',
    2: 'transport',
}

for key, value in list(LAYERS.items()):
    LAYERS[value] = key


def get_basic_parameters(kwargs):
    classid = kwargs.get('target')
    ematches = getattr(kwargs.get('ematches', None), 'list', [])
    nmatches = len(ematches)

    return {
        'attrs': [
            ['TCA_BASIC_CLASSID', classid],
            ['TCA_BASIC_EMATCH_TREE', {
                'attrs': [
                    ['TCA_EMATCH_TREE_HDR', {
                        'nmatches': nmatches,
                        'progid': 0,
                    }],
                    ['TCA_EMATCH_TREE_LIST', {
                        'attrs': ematches
                    }]
                ]}]
        ]
    }


def transform_layer(item, key='layer'):
    if isinstance(item[key], str):
        item[key] = LAYERS[item[key]]


def transform_align(item, key='align'):
    if isinstance(item[key], str):
        align = item[key][1:]
        assert item[key][0] == 'u' and align.isnumeric()
        item[key] = int(int(align) / 8)


class em_base(nlmsg):
    header = None
    fields = ()
    defaults = ()

    def __init__(self, buf=None, length=None, parent=None, debug=False,
                 init=None):
        length = length or self.get_size()
        nlmsg.__init__(self, buf, length, parent, debug, init)
        self.setdefaults(self)

    @classmethod
    def setdefaults(cls, item):
        for name, value in cls.defaults:
            item.setdefault(name, value)

    def transform(self):
        pass


class em_cmp(em_base):
    fields = (
        ('val', 'I'),
        ('mask', 'I'),
        ('offset', 'H'),
        ('_align_flags', 'B'),  # 4b FLAGS, 4b ALIGN
        ('_layer_opnd', 'B'),  # 4b OPND, 4b LAYER
    )

    OPERANDS = {
        0: 'eq',
        1: 'gt',
        2: 'lt',
    }
    for key, value in list(OPERANDS.items()):
        OPERANDS[value] = key

    defaults = (
        ('align', 1),
        ('val', 0),  # `value` looks like a reserved field name
        ('mask', 0),
        ('trans', False),
        ('layer', LAYERS['link']),
        ('operand', OPERANDS['eq']),
    )

    class Flag:
        TRANS = 1

    def decode(self):
        em_base.decode(self)

        self['align'] = self['_align_flags'] & 0x0F
        self['trans'] = bool(self['_align_flags'] >> 4 & self.Flag.TRANS)
        self['layer'] = self['_layer_opnd'] & 0x0F
        self['operand'] = self['_layer_opnd'] >> 4

        del self['_align_flags']
        del self['_layer_opnd']

    def transform(self):
        transform_align(self)
        transform_layer(self)

        if isinstance(self['operand'], str):
            self['operand'] = em_cmp.OPERANDS[self['operand']]

    def encode(self):
        em_cmp.transform(self)
        flags = 0
        if self['trans']:
            flags |= self.Flag.TRANS

        self['_align_flags'] = (flags << 4) | (self['align'] & 0x0F)
        self['_layer_opnd'] = (self['operand'] << 4) | (self['layer'] & 0x0F)
        em_base.encode(self)

        del self['_align_flags']
        del self['_layer_opnd']


class em_nbyte(em_base):
    fields = [
        ('offset', 'H'),
        ('_layer_len', 'H'),
        # ('needle', '%ss' % self['length']),  # added dynamically
    ]

    defaults = (
        ('offset', 0),
        ('layer', 0),
        ('length', 0),
        ('needle', ''),
    )

    def decode(self):
        em_base.decode(self)
        self['layer'] = self['_layer_len'] >> 12
        length = self['length'] = self['_layer_len'] & 0x0FFF
        self.length += length
        del self['_layer_len']

        self['needle'] = self.buf.read(length)

    def transform(self):
        transform_layer(self)

    def encode(self):
        self['length'] = len(self['needle'])
        self['_layer_len'] = (self['layer'] << 12) | (self['length'] & 0x0fff)
        if self.fields[-1][0] != 'needle':
            self.fields.append(
                ('needle', '%ds' % self['length']),
            )
        else:
            self.fields[-1] = ('needle', '%ds' % self['length'])
        em_base.encode(self)
        del self['_layer_len']


class em_u32(em_base):
    NEXTHDR_MASK = -1
    fields = (
        ('val_mask', 'I'),
        ('val', 'I'),  # `value` looks like a reserved field name
        ('offset', 'i'),
        ('offset_mask', 'i'),
    )
    defaults = (
        ('val_mask', 0),
        ('val', 0),
        ('offset', 0),
        ('offset_mask', NEXTHDR_MASK),
    )

    def is_nexthdr(self):
        return self['offset_mask'] == self.NEXTHDR_MASK


class ematch(nla):
    fields = (
        ('matchid', 'H'),
        ('kind', 'H'),
        ('_flags', 'H'),
        ('pad', 'H'),
    )
    kind_to_class = {
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
    for key, value in list(kind_to_class.items()):
        kind_to_class[value] = key

    class Flag:
        REL_END = 0
        REL_AND = 1 << 0
        REL_OR = 1 << 1
        INVERT = 1 << 2
        SIMPLE = 1 << 3
        REL_MASK = REL_AND | REL_OR

    kinds = {
        0: 'container',
        1: 'cmp',
        2: 'nbyte',
        3: 'u32',
        4: 'meta',
        5: 'text',
        6: 'vlan',
        7: 'canid',
        8: 'ipset'
    }
    for key, value in list(kinds.items()):
        kinds[value] = key

    relations = {
        0: 'END',
        1: 'AND',
        2: 'OR',
        3: 'INVALID'
    }
    for key, value in list(relations.items()):
        relations[value] = key

    defaults = (
        ('matchid', 0),
        ('kind', 0),
        ('pad', 0),
        ('relation', relations['END']),
        ('invert', False),
        ('simple', False),
    )

    def __init__(self, *args, **kwargs):
        nla.__init__(self, *args, **kwargs)

        for name, value in self.defaults:
            self.setdefault(name, value)

    def get_match_cls(self):
        kind = self['kind']
        if kind in self.kind_to_class:
            return self.kind_to_class[kind]
        return self.hex

    def decode(self):
        nla.decode(self)
        cls = self.get_match_cls()
        self['match'] = cls(self.buf, cls.get_size(), self)
        self['match'].decode()

        self['relation'] = self['_flags'] & self.Flag.REL_MASK
        self['invert'] = bool(self['_flags'] & self.Flag.INVERT)
        self['simple'] = bool(self['_flags'] & self.Flag.SIMPLE)

        del self['_flags']

    def encode(self):
        init = self.buf.tell()
        if isinstance(self['relation'], str):
            self['relation'] = self.relations[self['relation']]

        flags = self['relation'] & self.Flag.REL_MASK
        if self['invert']:
            flags |= self.Flag.INVERT
        if self['simple']:
            flags |= self.Flag.SIMPLE
        self['_flags'] = flags
        nla.encode(self)
        if 'match' in self and self['match']:
            cls = self.get_match_cls()
            if not isinstance(self['match'], cls):
                data = self['match']
                self['match'] = cls(self.buf, cls.get_size(), self)
                self['match'].update(data)
            self['match'].encode()
        self.update_length(init)

        del self['_flags']


class tcf_basic(nla):
    nla_map = (
        ('TCA_BASIC_UNSPEC', 'none'),
        ('TCA_BASIC_CLASSID', 'uint32'),
        ('TCA_BASIC_EMATCH_TREE', 'ematch_tree'),
    )

    class ematch_tree(nla):
        nla_map = (
            ('TCA_EMATCH_TREE_UNSPEC', 'none'),
            ('TCA_EMATCH_TREE_HDR', 'tcf_ematch_tree_hdr'),
            ('TCA_EMATCH_TREE_LIST', 'ematch_tree_list'),
        )

        class tcf_ematch_tree_hdr(nla):
            fields = (
                ('nmatches', 'H'),
                ('progid', 'H'),
            )

        class ematch_tree_list(nla):
            ematch = ematch
            nla_map = (
                ('UNSPEC', 'hex'),
            )  # filled dynamically

            def __init__(self, buf=None, length=None, parent=None,
                         debug=False, init=None):
                if parent:
                    header = parent.get_attr('TCA_EMATCH_TREE_HDR')
                    self.nla_map = list(self.nla_map)
                    for i in range(header['nmatches']):
                        self.nla_map.append(
                            ('EMATCH', 'ematch')
                        )
                nla.__init__(self, buf, length, parent, debug, init)
