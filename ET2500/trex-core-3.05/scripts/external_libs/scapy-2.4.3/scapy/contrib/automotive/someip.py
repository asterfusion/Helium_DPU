#! /usr/bin/env python

# MIT License

# Copyright (c) 2018 Jose Amores

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Sebastian Baar <sebastian.baar@gmx.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Scalable service-Oriented MiddlewarE/IP (SOME/IP)
# scapy.contrib.status = loads

import struct

from scapy.layers.inet import TCP, UDP
from scapy.compat import raw
from scapy.config import conf
from scapy.modules.six.moves import range
from scapy.packet import Packet, bind_layers
from scapy.fields import ShortField, BitEnumField, ConditionalField, \
    BitField, PacketField, IntField, ByteField, ByteEnumField


class _SOMEIP_MessageId(Packet):
    """ MessageId subpacket."""
    name = "MessageId"
    fields_desc = [
        ShortField("srv_id", 0),
        BitEnumField("sub_id", 0, 1, {0: "METHOD_ID", 1: "EVENT_ID"}),
        ConditionalField(BitField("method_id", 0, 15),
                         lambda pkt: pkt.sub_id == 0),
        ConditionalField(BitField("event_id", 0, 15),
                         lambda pkt: pkt.sub_id == 1)
    ]

    def extract_padding(self, s):
        return "", s


class _SOMEIP_RequestId(Packet):
    """ RequestId subpacket."""
    name = "RequestId"
    fields_desc = [
        ShortField("client_id", 0),
        ShortField("session_id", 0)
    ]

    def extract_padding(self, s):
        return "", s


class SOMEIP(Packet):
    """ SOME/IP Packet."""

    PROTOCOL_VERSION = 0x01
    INTERFACE_VERSION = 0x01
    LEN_OFFSET = 0x08
    LEN_OFFSET_TP = 0x0c
    TYPE_REQUEST = 0x00
    TYPE_REQUEST_NO_RET = 0x01
    TYPE_NOTIFICATION = 0x02
    TYPE_REQUEST_ACK = 0x40
    TYPE_REQUEST_NORET_ACK = 0x41
    TYPE_NOTIFICATION_ACK = 0x42
    TYPE_RESPONSE = 0x80
    TYPE_ERROR = 0x81
    TYPE_RESPONSE_ACK = 0xc0
    TYPE_ERROR_ACK = 0xc1
    TYPE_TP_REQUEST = 0x20
    TYPE_TP_REQUEST_NO_RET = 0x21
    TYPE_TP_NOTIFICATION = 0x22
    TYPE_TP_RESPONSE = 0x23
    TYPE_TP_ERROR = 0x24
    RET_E_OK = 0x00
    RET_E_NOT_OK = 0x01
    RET_E_UNKNOWN_SERVICE = 0x02
    RET_E_UNKNOWN_METHOD = 0x03
    RET_E_NOT_READY = 0x04
    RET_E_NOT_REACHABLE = 0x05
    RET_E_TIMEOUT = 0x06
    RET_E_WRONG_PROTOCOL_V = 0x07
    RET_E_WRONG_INTERFACE_V = 0x08
    RET_E_MALFORMED_MSG = 0x09
    RET_E_WRONG_MESSAGE_TYPE = 0x0a

    _OVERALL_LEN_NOPAYLOAD = 16

    name = "SOME/IP"

    fields_desc = [
        PacketField("msg_id", _SOMEIP_MessageId(),
                    _SOMEIP_MessageId),
        IntField("len", None),
        PacketField("req_id", _SOMEIP_RequestId(),
                    _SOMEIP_RequestId),
        ByteField("proto_ver", PROTOCOL_VERSION),
        ByteField("iface_ver", INTERFACE_VERSION),
        ByteEnumField("msg_type", TYPE_REQUEST, {
            TYPE_REQUEST: "REQUEST",
            TYPE_REQUEST_NO_RET: "REQUEST_NO_RETURN",
            TYPE_NOTIFICATION: "NOTIFICATION",
            TYPE_REQUEST_ACK: "REQUEST_ACK",
            TYPE_REQUEST_NORET_ACK: "REQUEST_NO_RETURN_ACK",
            TYPE_NOTIFICATION_ACK: "NOTIFICATION_ACK",
            TYPE_RESPONSE: "RESPONSE",
            TYPE_ERROR: "ERROR",
            TYPE_RESPONSE_ACK: "RESPONSE_ACK",
            TYPE_ERROR_ACK: "ERROR_ACK",
            TYPE_TP_REQUEST: "TP_REQUEST",
            TYPE_TP_REQUEST_NO_RET: "TP_REQUEST_NO_RETURN",
            TYPE_TP_NOTIFICATION: "TP_NOTIFICATION",
            TYPE_TP_RESPONSE: "TP_RESPONSE",
            TYPE_TP_ERROR: "TP_ERROR",
        }),
        ByteEnumField("retcode", 0, {
            RET_E_OK: "E_OK",
            RET_E_NOT_OK: "E_NOT_OK",
            RET_E_UNKNOWN_SERVICE: "E_UNKNOWN_SERVICE",
            RET_E_UNKNOWN_METHOD: "E_UNKNOWN_METHOD",
            RET_E_NOT_READY: "E_NOT_READY",
            RET_E_NOT_REACHABLE: "E_NOT_REACHABLE",
            RET_E_TIMEOUT: "E_TIMEOUT",
            RET_E_WRONG_PROTOCOL_V: "E_WRONG_PROTOCOL_VERSION",
            RET_E_WRONG_INTERFACE_V: "E_WRONG_INTERFACE_VERSION",
            RET_E_MALFORMED_MSG: "E_MALFORMED_MESSAGE",
            RET_E_WRONG_MESSAGE_TYPE: "E_WRONG_MESSAGE_TYPE",
        }),
        ConditionalField(BitField("offset", 0, 28),
                         lambda pkt: SOMEIP._is_tp(pkt)),
        ConditionalField(BitField("res", 0, 3),
                         lambda pkt: SOMEIP._is_tp(pkt)),
        ConditionalField(BitField("more_seg", 0, 1),
                         lambda pkt: SOMEIP._is_tp(pkt))
    ]

    def post_build(self, pkt, pay):
        length = self.len
        if length is None:
            if SOMEIP._is_tp(self):
                length = SOMEIP.LEN_OFFSET_TP + len(pay)
            else:
                length = SOMEIP.LEN_OFFSET + len(pay)

            pkt = pkt[:4] + struct.pack("!I", length) + pkt[8:]
        return pkt + pay

    def answers(self, other):
        if other.__class__ == self.__class__:
            if self.msg_type in [SOMEIP.TYPE_REQUEST_NO_RET,
                                 SOMEIP.TYPE_REQUEST_NORET_ACK,
                                 SOMEIP.TYPE_NOTIFICATION,
                                 SOMEIP.TYPE_TP_REQUEST_NO_RET,
                                 SOMEIP.TYPE_TP_NOTIFICATION]:
                return 0
            return self.payload.answers(other.payload)
        return 0

    @staticmethod
    def _is_tp(pkt):
        """Returns true if pkt is using SOMEIP-TP, else returns false."""

        tp = [SOMEIP.TYPE_TP_REQUEST, SOMEIP.TYPE_TP_REQUEST_NO_RET,
              SOMEIP.TYPE_TP_NOTIFICATION, SOMEIP.TYPE_TP_RESPONSE,
              SOMEIP.TYPE_TP_ERROR]
        if isinstance(pkt, Packet):
            return pkt.msg_type in tp
        else:
            return pkt[15] in tp

    def fragment(self, fragsize=1392):
        """Fragment SOME/IP-TP"""
        fnb = 0
        fl = self
        lst = list()
        while fl.underlayer is not None:
            fnb += 1
            fl = fl.underlayer

        for p in fl:
            s = raw(p[fnb].payload)
            nb = (len(s) + fragsize) // fragsize
            for i in range(nb):
                q = p.copy()
                del q[fnb].payload
                q[fnb].len = SOMEIP.LEN_OFFSET_TP + \
                    len(s[i * fragsize:(i + 1) * fragsize])
                q[fnb].more_seg = 1
                if i == nb - 1:
                    q[fnb].more_seg = 0
                q[fnb].offset += i * fragsize // 16
                r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
                r.overload_fields = p[fnb].payload.overload_fields.copy()
                q.add_payload(r)
                lst.append(q)

        return lst


def _bind_someip_layers():
    for i in range(15):
        bind_layers(UDP, SOMEIP, sport=30490 + i)
        bind_layers(TCP, SOMEIP, sport=30490 + i)


_bind_someip_layers()
