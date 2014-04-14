#!/usr/bin/env python
# -*- coding: utf-8 -*-

import iptc
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

class Firewall(object):
    def __init__(self, i_int=None):
        self._rule = iptc.Rule()
        self._rule.in_interface = "eth0" if i_int is None else i_int
        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    
    def __match(self, proto, dport):
        """This method return the match for the *dport* on the selected *proto*
        that should be tcp and port 21 for our purpose."""
        m = self._rule.create_match(proto)
        m.dport = dport
        return m

    def __ruleIsPresent(self, src):
        for rule in self.chain.rules:
            if src in rule.get_src():
                return True
        return False

    def permit(self, src, dport):
        """Insert in INPUT chain the new rule to permit *src*
        to the destionation port *dport*"""
        self._rule.src = src
        self._rule.protocol = "tcp"
        target = self._rule.create_target("ACCEPT")
        self._rule.add_match(self.__match("tcp", dport))
        try:
            if not self.__ruleIsPresent(src):
                self.chain.insert_rule(self._rule)
            else:
                logger.warning('Rule with srcip: %s already present.' % src)
        except Exception as e:
            logger.critical('Cannot insert rule.\n%s' % e)

    def remove(self, src):
        for rule in self.chain.rules:
            if src in rule.get_src():
                try:
                    self.chain.delete_rule(rule)
                except Exception as e:
                    logger.critical('Cannot delete rule with src ip: %s. Error: %s' % (src, e))

''' test unit'''
if __name__ == '__main__':
    f = Firewall()
    f.permit('8.8.8.8', '53')
    f.remove('8.8.8.8')
