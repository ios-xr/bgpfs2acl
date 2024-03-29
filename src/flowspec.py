from __future__ import unicode_literals
import hashlib

from enum import Enum


class FlowSpecRule:
    class FeatureNames(Enum):
        source_ip = 'Source'
        destination_ip = 'Dest'
        protocol = 'Proto'
        destination_port = 'DPort'
        source_port = 'SPort'
        icmp_type = 'ICMPType'
        icmp_code = 'ICMPCode'
        fragment_type = 'Frag'
        packet_length = 'Length'

    class Actions(Enum):
        deny = 'Traffic-rate: 0 bps'
        nexthop = 'Nexthop: '
        redirect_vrf = 'Redirect: VRF'

    def __init__(self):
        self._raw_flow = None
        self._raw_actions = None
        self._flow_features = {}

    @staticmethod
    def _validate(raw_flow, raw_actions, raise_exception=True):
        if not raw_flow.strip().startswith("Flow"):
            if raise_exception:
                raise ValueError("Bad flow format: {}".format(raw_flow))
            return None, None

        if not raw_actions.strip().startswith("Actions"):
            if raise_exception:
                raise ValueError("Bad actions format: {}".format(raw_actions))
            return None, None

        raw_flow = raw_flow.split(':', 1)[1]
        raw_actions = raw_actions.split(':', 1)[1]

        return raw_flow, raw_actions

    @property
    def flow(self):
        return self._raw_flow

    @property
    def actions(self):
        return self._raw_actions

    def get_feature(self, feature_name):
        if feature_name not in [f.value for f in FlowSpecRule.FeatureNames.__members__.values()]:
            raise ValueError("Wrong feature name: {}".format(feature_name))

        return self._flow_features.get(feature_name, None)

    def features_iter(self):
        return self._flow_features.items()

    @classmethod
    def from_config(cls, raw_flow, raw_actions):
        raw_flow, raw_actions = cls._validate(raw_flow, raw_actions)

        if not (raw_flow and raw_actions):
            return None

        flowspec = cls()
        flowspec._raw_flow = raw_flow
        flowspec._raw_actions = raw_actions
        raw_flow = raw_flow.split(',')
        for feature in raw_flow:
            split_feature = feature.split(':', 1)
            feature_name = split_feature[0]
            feature_value = split_feature[1]
            flowspec._flow_features.update({feature_name: feature_value})
        return flowspec


class FlowSpec:
    def __init__(self):
        self._raw_config = []
        self._rules = []

    @staticmethod
    def _validate_config(raw_config, raise_exception=True):
        if len(raw_config) <= 1:
            if raise_exception:
                raise ValueError("Empty flowspec: {}".format(raw_config))
            return None

        if raw_config[0].startswith("AFI:"):
            del raw_config[0]

        for i in range(0, len(raw_config), 2):
            if not (raw_config[i].strip().startswith("Flow") and raw_config[i + 1].strip().startswith("Actions")):
                if raise_exception:
                    raise ValueError("Bad flowspec format: {}".format(raw_config))
                return None
        return raw_config

    def is_empty(self):
        return not bool(len(self._rules))

    @property
    def config(self):
        return '\n'.join(self._raw_config)

    @property
    def md5(self):
        return hashlib.md5(self.config.encode('utf-8')).hexdigest()

    @property
    def rules(self):
        return self._rules

    @classmethod
    def from_config(cls, fs_config):
        fs_config = fs_config.strip().split('\n')[3:]
        fs_config = cls._validate_config(fs_config, raise_exception=False)
        if fs_config is None:
            return None
        obj = cls()

        for i in range(0, len(fs_config), 2):
            rule = FlowSpecRule.from_config(raw_flow=fs_config[i], raw_actions=fs_config[i + 1])
            if rule:
                obj._rules.append(rule)
                obj._raw_config.append(fs_config[i])
                obj._raw_config.append(fs_config[i + 1])
        return obj
