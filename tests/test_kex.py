# Copyright (C) 2003-2009  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Some unit tests for the key exchange protocols.
"""

import os
import threading
import unittest
from binascii import hexlify, unhexlify
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
except ImportError:
    x25519 = None

import paramiko.kex_mlkem
import paramiko.util
from paramiko import Message, RSAKey, Transport
from paramiko.common import byte_chr
from paramiko.kex_curve25519 import KexCurve25519
from paramiko.kex_ecdh_nist import KexNistp256
from paramiko.kex_gex import KexGexSHA256
from paramiko.kex_group14 import KexGroup14SHA256
from paramiko.kex_group16 import KexGroup16SHA512
from paramiko.kex_mlkem import KexMLKEM768X25519
from paramiko.primes import is_probable_prime
from paramiko.ssh_exception import SSHException

from ._loop import LoopSocket
from ._util import TestServer, _support


def dummy_urandom(n):
    return byte_chr(0xCC) * n


def dummy_generate_key_pair(obj):
    private_key_value = 94761803665136558137557783047955027733968423115106677159790289642479432803037  # noqa
    public_key_numbers = "042bdab212fa8ba1b7c843301682a4db424d307246c7e1e6083c41d9ca7b098bf30b3d63e2ec6278488c135360456cc054b3444ecc45998c08894cbc1370f5f989"  # noqa
    public_key_numbers_obj = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), unhexlify(public_key_numbers)
    ).public_numbers()
    obj.P = ec.EllipticCurvePrivateNumbers(
        private_value=private_key_value, public_numbers=public_key_numbers_obj
    ).private_key(default_backend())
    if obj.transport.server_mode:
        obj.Q_S = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), unhexlify(public_key_numbers)
        )
        return
    obj.Q_C = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), unhexlify(public_key_numbers)
    )


class FakeKey:
    def __str__(self):
        return "fake-key"

    def asbytes(self):
        return b"fake-key"

    def sign_ssh_data(self, H, algorithm):
        return b"fake-sig"


class FakeModulusPack:
    # RFC 3526 group 14: a 2048-bit safe prime, satisfying the 2048-bit
    # minimum KexGexSHA256 declares in its GEX request.
    P = KexGroup14SHA256.P
    G = 2

    def get_modulus(self, min, ask, max):
        return self.G, self.P


class FakeTransport:
    def __init__(self, server: bool):
        self.server_mode = server

    local_version = "SSH-2.0-paramiko_1.0"
    remote_version = "SSH-2.0-lame"
    local_kex_init = "local-kex-init"
    remote_kex_init = "remote-kex-init"
    host_key_type = "fake-key"

    def _send_message(self, m):
        self._message = m

    def _expect_packet(self, *t):
        self._expect = t

    def _set_K_H(self, K, H):
        self._K = K
        self._H = H

    def _verify_key(self, host_key, sig):
        self._verify = (host_key, sig)

    def _activate_outbound(self):
        self._activated = True

    def _log(self, level, s):
        pass

    def get_server_key(self):
        return FakeKey()

    def _get_modulus_pack(self):
        return FakeModulusPack()


class KexTest(unittest.TestCase):
    K = 12775342822141462769873836232046646558435129877956840348900188991579146843888867171403769263899832547779397673679342642957844875897383558594540549149134347551943436867189251193643504963370723164708745774339533031080201271549527265102020193515297930725968908655908026380056496240402754592278682068636334505640953936274882549880142393042956896885671602638771239947830672868374200894113013130430877474060410300954800991605865280408697830265503396760409931096001568664943731415297678357368403285720176098024030628702941192943061129241601721237314842959691018246791769382386033845941657702575140897931331859429263816744586  # noqa

    def setUp(self):
        self._original_urandom = os.urandom
        os.urandom = dummy_urandom
        self._original_generate_key_pair = KexNistp256._generate_key_pair
        KexNistp256._generate_key_pair = dummy_generate_key_pair

        if KexCurve25519.is_available():
            static_x25519_key = x25519.X25519PrivateKey.from_private_bytes(
                unhexlify(
                    b"2184abc7eb3e656d2349d2470ee695b570c227340c2b2863b6c9ff427af1f040"  # noqa
                )
            )
            mock_x25519 = Mock()
            mock_x25519.generate.return_value = static_x25519_key
            patcher = patch(
                "paramiko.kex_curve25519.X25519PrivateKey", mock_x25519
            )
            patcher.start()
            self.x25519_patcher = patcher

    def tearDown(self):
        os.urandom = self._original_urandom
        KexNistp256._generate_key_pair = self._original_generate_key_pair
        if hasattr(self, "x25519_patcher"):
            self.x25519_patcher.stop()

    def test_gex_sha256_client(self):
        transport = FakeTransport(server=False)
        kex = KexGexSHA256(transport)
        kex.start_kex()
        x = b"22000008000000080000002000"
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_GROUP,), transport._expect
        )

        msg = Message()
        msg.add_mpint(FakeModulusPack.P)
        msg.add_mpint(FakeModulusPack.G)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_GROUP, msg)
        x = b"2000000100790190D806C7C7C847DD4B0360F67D37E8A3BDA298C2FE0CE643346A27556A2A8F3CDF8BDF2D25EB688993E94C97A7449863B661A7CCA259AE783054795E47C8F0F6FB8226B8E453854EA3DA57A3747D805E691B7A7E7D79A7917483ACF1DA54CE5A6ABCD4DE9EC110CC1EC77796807FDEB47231D8A75640254942C645171A7F76D4B926EF64F6393EF30F9CCC635CDB1FA651852529822614506FD120094B38A28C16B9DB12E05078D8850B23952DF09035C9EC06D648B659730EDD50C0F590E71E0C4C2258143DE206D52FDE9812320EB1D51244F865722C79E248E6E63A0228C30B77BB466E4AE7C1635184923AEB0D22118B1E522C544A0CFCF4EA68BEFD"  # noqa
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,), transport._expect
        )

        msg = Message()
        msg.add_string("fake-host-key")
        msg.add_mpint(69)
        msg.add_string("fake-sig")
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REPLY, msg)
        H = b"F55272D40A2130B1D6AF45F5D659F5D646FFF68F0FB24F620AFDA8E326A60350"
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b"fake-host-key", b"fake-sig"), transport._verify)
        self.assertTrue(transport._activated)

    def test_gex_sha256_old_client(self):
        transport = FakeTransport(server=False)
        kex = KexGexSHA256(transport)
        kex.start_kex(_test_old_style=True)
        x = b"1E00000800"
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_GROUP,), transport._expect
        )

        msg = Message()
        msg.add_mpint(FakeModulusPack.P)
        msg.add_mpint(FakeModulusPack.G)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_GROUP, msg)
        x = b"2000000100790190D806C7C7C847DD4B0360F67D37E8A3BDA298C2FE0CE643346A27556A2A8F3CDF8BDF2D25EB688993E94C97A7449863B661A7CCA259AE783054795E47C8F0F6FB8226B8E453854EA3DA57A3747D805E691B7A7E7D79A7917483ACF1DA54CE5A6ABCD4DE9EC110CC1EC77796807FDEB47231D8A75640254942C645171A7F76D4B926EF64F6393EF30F9CCC635CDB1FA651852529822614506FD120094B38A28C16B9DB12E05078D8850B23952DF09035C9EC06D648B659730EDD50C0F590E71E0C4C2258143DE206D52FDE9812320EB1D51244F865722C79E248E6E63A0228C30B77BB466E4AE7C1635184923AEB0D22118B1E522C544A0CFCF4EA68BEFD"  # noqa
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,), transport._expect
        )

        msg = Message()
        msg.add_string("fake-host-key")
        msg.add_mpint(69)
        msg.add_string("fake-sig")
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REPLY, msg)
        H = b"7781D2ED99E5ACB708C84E8CD5182507654C6DAE31F7FA2091E0C364945A48BD"
        self.assertEqual(self.K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b"fake-host-key", b"fake-sig"), transport._verify)
        self.assertTrue(transport._activated)

    def test_gex_sha256_server(self):
        transport = FakeTransport(server=True)
        kex = KexGexSHA256(transport)
        kex.start_kex()
        self.assertEqual(
            (
                paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST,
                paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD,
            ),
            transport._expect,
        )

        msg = Message()
        msg.add_int(1024)
        msg.add_int(2048)
        msg.add_int(4096)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, msg)
        x = b"1F0000010100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF0000000102"  # noqa
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect
        )

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 16990795098881292300589617966102444175680652951778177259631700176383516080603616441906301938335500329773705262603452401492741304688032031455903325015049940949974478160350932411123752914713990327044723277156679187891975862330047206857050520499309679326064920785106253099713840685083983571002233047138985300154156734949832481250024774893950494419175035146836738574178734648929506915510670561990822486769235403784425002137278502513112036980572148969004021498978241805867769499888203018319483198651244872328054696263486194008908261706627251110376575377156054865326784792813332765373886800245074117363065380728484836472695  # noqa
        H = b"6B4B430D1E2387C17179152ACC1AA6AF454DA5D3700DE580ACB3440C92ACB32E"
        x = b"210000000866616B652D6B657900000100790190D806C7C7C847DD4B0360F67D37E8A3BDA298C2FE0CE643346A27556A2A8F3CDF8BDF2D25EB688993E94C97A7449863B661A7CCA259AE783054795E47C8F0F6FB8226B8E453854EA3DA57A3747D805E691B7A7E7D79A7917483ACF1DA54CE5A6ABCD4DE9EC110CC1EC77796807FDEB47231D8A75640254942C645171A7F76D4B926EF64F6393EF30F9CCC635CDB1FA651852529822614506FD120094B38A28C16B9DB12E05078D8850B23952DF09035C9EC06D648B659730EDD50C0F590E71E0C4C2258143DE206D52FDE9812320EB1D51244F865722C79E248E6E63A0228C30B77BB466E4AE7C1635184923AEB0D22118B1E522C544A0CFCF4EA68BEFD0000000866616B652D736967"  # noqa
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_gex_sha256_server_with_old_client(self):
        transport = FakeTransport(server=True)
        kex = KexGexSHA256(transport)
        kex.start_kex()
        self.assertEqual(
            (
                paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST,
                paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD,
            ),
            transport._expect,
        )

        msg = Message()
        msg.add_int(2048)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST_OLD, msg)
        x = b"1F0000010100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF0000000102"  # noqa
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_INIT,), transport._expect
        )

        msg = Message()
        msg.add_mpint(12345)
        msg.rewind()
        kex.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_INIT, msg)
        K = 16990795098881292300589617966102444175680652951778177259631700176383516080603616441906301938335500329773705262603452401492741304688032031455903325015049940949974478160350932411123752914713990327044723277156679187891975862330047206857050520499309679326064920785106253099713840685083983571002233047138985300154156734949832481250024774893950494419175035146836738574178734648929506915510670561990822486769235403784425002137278502513112036980572148969004021498978241805867769499888203018319483198651244872328054696263486194008908261706627251110376575377156054865326784792813332765373886800245074117363065380728484836472695  # noqa
        H = b"74B11B41A7359E7C65B795069C979BFF397782502D979447B03BF5ABE728B967"
        x = b"210000000866616B652D6B657900000100790190D806C7C7C847DD4B0360F67D37E8A3BDA298C2FE0CE643346A27556A2A8F3CDF8BDF2D25EB688993E94C97A7449863B661A7CCA259AE783054795E47C8F0F6FB8226B8E453854EA3DA57A3747D805E691B7A7E7D79A7917483ACF1DA54CE5A6ABCD4DE9EC110CC1EC77796807FDEB47231D8A75640254942C645171A7F76D4B926EF64F6393EF30F9CCC635CDB1FA651852529822614506FD120094B38A28C16B9DB12E05078D8850B23952DF09035C9EC06D648B659730EDD50C0F590E71E0C4C2258143DE206D52FDE9812320EB1D51244F865722C79E248E6E63A0228C30B77BB466E4AE7C1635184923AEB0D22118B1E522C544A0CFCF4EA68BEFD0000000866616B652D736967"  # noqa
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_kex_nistp256_client(self):
        K = 91610929826364598472338906427792435253694642563583721654249504912114314269754  # noqa
        transport = FakeTransport(server=False)
        kex = KexNistp256(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_ecdh_nist._MSG_KEXECDH_REPLY,), transport._expect
        )

        # fake reply
        msg = Message()
        msg.add_string("fake-host-key")
        Q_S = unhexlify(
            "043ae159594ba062efa121480e9ef136203fa9ec6b6e1f8723a321c16e62b945f573f3b822258cbcd094b9fa1c125cbfe5f043280893e66863cc0cb4dccbe70210"  # noqa
        )
        msg.add_string(Q_S)
        msg.add_string("fake-sig")
        msg.rewind()
        kex.parse_next(paramiko.kex_ecdh_nist._MSG_KEXECDH_REPLY, msg)
        H = b"BAF7CE243A836037EB5D2221420F35C02B9AB6C957FE3BDE3369307B9612570A"
        self.assertEqual(K, kex.transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b"fake-host-key", b"fake-sig"), transport._verify)
        self.assertTrue(transport._activated)

    def test_kex_nistp256_server(self):
        K = 91610929826364598472338906427792435253694642563583721654249504912114314269754  # noqa
        transport = FakeTransport(server=True)
        kex = KexNistp256(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_ecdh_nist._MSG_KEXECDH_INIT,), transport._expect
        )

        # fake init
        msg = Message()
        Q_C = unhexlify(
            "043ae159594ba062efa121480e9ef136203fa9ec6b6e1f8723a321c16e62b945f573f3b822258cbcd094b9fa1c125cbfe5f043280893e66863cc0cb4dccbe70210"  # noqa
        )
        H = b"2EF4957AFD530DD3F05DBEABF68D724FACC060974DA9704F2AEE4C3DE861E7CA"
        msg.add_string(Q_C)
        msg.rewind()
        kex.parse_next(paramiko.kex_ecdh_nist._MSG_KEXECDH_INIT, msg)
        self.assertEqual(K, transport._K)
        self.assertTrue(transport._activated)
        self.assertEqual(H, hexlify(transport._H).upper())

    def test_kex_group14_sha256_client(self):
        transport = FakeTransport(server=False)
        kex = KexGroup14SHA256(transport)
        kex.start_kex()
        x = b"1E00000101009850B3A8DE3ECCD3F19644139137C93D9C11BC28ED8BE850908EE294E1D43B88B9295311EFAEF5B736A1B652EBE184CCF36CFB0681C1ED66430088FA448B83619F928E7B9592ED6160EC11D639D51C303603F930F743C646B1B67DA38A1D44598DCE6C3F3019422B898044141420E9A10C29B9C58668F7F20A40F154B2C4768FCF7A9AA7179FB6366A7167EE26DD58963E8B880A0572F641DE0A73DC74C930F7C3A0C9388553F3F8403E40CF8B95FEDB1D366596FCF3FDDEB21A0005ADA650EF1733628D807BE5ACB83925462765D9076570056E39994FB328E3108FE406275758D6BF5F32790EF15D8416BF5548164859E785DB45E7787BB0E727ADE08641ED"  # noqa
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual(
            (paramiko.kex_group14._MSG_KEXDH_REPLY,), transport._expect
        )

        # fake "reply"
        msg = Message()
        msg.add_string("fake-host-key")
        msg.add_mpint(69)
        msg.add_string("fake-sig")
        msg.rewind()
        kex.parse_next(paramiko.kex_group14._MSG_KEXDH_REPLY, msg)
        K = 21526936926159575624241589599003964979640840086252478029709904308461709651400109485351462666820496096345766733042945918306284902585618061272525323382142547359684512114160415969631877620660064043178086464811345023251493620331559440565662862858765724251890489795332144543057725932216208403143759943169004775947331771556537814494448612329251887435553890674764339328444948425882382475260315505741818518926349729970262019325118040559191290279100613049085709127598666890434114956464502529053036826173452792849566280474995114751780998069614898221773345705289637708545219204637224261997310181473787577166103031529148842107599  # noqa
        H = b"D007C23686BE8A7737F828DC9E899F8EB5AF423F495F138437BE2529C1B8455F"
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b"fake-host-key", b"fake-sig"), transport._verify)
        self.assertTrue(transport._activated)

    def test_kex_group14_sha256_server(self):
        transport = FakeTransport(server=True)
        kex = KexGroup14SHA256(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_group14._MSG_KEXDH_INIT,), transport._expect
        )

        msg = Message()
        msg.add_mpint(69)
        msg.rewind()
        kex.parse_next(paramiko.kex_group14._MSG_KEXDH_INIT, msg)
        K = 21526936926159575624241589599003964979640840086252478029709904308461709651400109485351462666820496096345766733042945918306284902585618061272525323382142547359684512114160415969631877620660064043178086464811345023251493620331559440565662862858765724251890489795332144543057725932216208403143759943169004775947331771556537814494448612329251887435553890674764339328444948425882382475260315505741818518926349729970262019325118040559191290279100613049085709127598666890434114956464502529053036826173452792849566280474995114751780998069614898221773345705289637708545219204637224261997310181473787577166103031529148842107599  # noqa
        H = b"15080A19894D489ACD0DA724480E1B08E71293E07EBC25FAD10F263C00B343DC"
        x = b"1F0000000866616B652D6B657900000101009850B3A8DE3ECCD3F19644139137C93D9C11BC28ED8BE850908EE294E1D43B88B9295311EFAEF5B736A1B652EBE184CCF36CFB0681C1ED66430088FA448B83619F928E7B9592ED6160EC11D639D51C303603F930F743C646B1B67DA38A1D44598DCE6C3F3019422B898044141420E9A10C29B9C58668F7F20A40F154B2C4768FCF7A9AA7179FB6366A7167EE26DD58963E8B880A0572F641DE0A73DC74C930F7C3A0C9388553F3F8403E40CF8B95FEDB1D366596FCF3FDDEB21A0005ADA650EF1733628D807BE5ACB83925462765D9076570056E39994FB328E3108FE406275758D6BF5F32790EF15D8416BF5548164859E785DB45E7787BB0E727ADE08641ED0000000866616B652D736967"  # noqa
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    def test_kex_group16_sha512_client(self):
        transport = FakeTransport(server=False)
        kex = KexGroup16SHA512(transport)
        kex.start_kex()
        x = b"1E0000020100859FF55A23E0F66463561DD8BFC4764C69C05F85665B06EC9E29EF5003A53A8FA890B6A6EB624DEB55A4FB279DE7010A53580A126817E3D235B05A1081662B1500961D0625F0AAD287F1B597CBA9DB9550D9CC26355C4C59F92E613B5C21AC191F152C09A5DB46DCBA5EA58E3CA6A8B0EB7183E27FAC10106022E8521FA91240FB389060F1E1E4A355049D29DCC82921CE6588791743E4B1DEEE0166F7CC5180C3C75F3773342DF95C8C10AAA5D12975257027936B99B3DED6E6E98CF27EADEAEAE04E7F0A28071F578646B985FCE28A59CEB36287CB65759BE0544D4C4018CDF03C9078FE9CA79ECA611CB6966899E6FD29BE0781491C659FE2380E0D99D50D9CFAAB94E61BE311779719C4C43C6D223AD3799C3915A9E55076A21152DBBF911D6594296D6ECDC1B6FA71997CD29DF987B80FCA7F36BB7F19863C72BBBF839746AFBF9A5B407D468C976AA3E36FA118D3EAAD2E08BF6AE219F81F2CE2BE946337F06CC09BBFABE938A4087E413921CBEC1965ED905999B83396ECA226110CDF6EFB80F815F6489AF87561DA3857F13A7705921306D94176231FBB336B17C3724BC17A28BECB910093AB040873D5D760E8C182B88ECCE3E38DDA68CE35BD152DF7550BD908791FCCEDD1FFDF5ED2A57FFAE79599E487A7726D8A3D950B1729A08FBB60EE462A6BBE8BF0F5F0E1358129A37840FE5B3EEB8BF26E99FA222EAE83"  # noqa
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertEqual(
            (paramiko.kex_group14._MSG_KEXDH_REPLY,), transport._expect
        )

        # fake "reply"
        msg = Message()
        msg.add_string("fake-host-key")
        msg.add_mpint(69)
        msg.add_string("fake-sig")
        msg.rewind()
        kex.parse_next(paramiko.kex_group14._MSG_KEXDH_REPLY, msg)
        K = 933242830095376162107925500057692534838883186615567574891154103836907630698358649443101764908667358576734565553213003142941996368306996312915844839972197961603283544950658467545799914435739152351344917376359963584614213874232577733869049670230112638724993540996854599166318001059065780674008011575015459772051180901213815080343343801745386220342919837913506966863570473712948197760657442974564354432738520446202131551650771882909329069340612274196233658123593466135642819578182367229641847749149740891990379052266213711500434128970973602206842980669193719602075489724202241641553472106310932258574377789863734311328542715212248147206865762697424822447603031087553480483833829498375309975229907460562402877655519980113688369262871485777790149373908739910846630414678346163764464587129010141922982925829457954376352735653834300282864445132624993186496129911208133529828461690634463092007726349795944930302881758403402084584307180896465875803621285362317770276493727205689466142632599776710824902573926951951209239626732358074877997756011804454926541386215567756538832824717436605031489511654178384081883801272314328403020205577714999460724519735573055540814037716770051316113795603990199374791348798218428912977728347485489266146775472  # noqa
        H = b"F6E2BCC846B9B62591EFB86663D55D4769CA06B2EDABE469DF831639B2DDD5A271985011900A724CB2C87F19F347B3632A7C1536AF3D12EE463E6EA75281AF0C"  # noqa
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b"fake-host-key", b"fake-sig"), transport._verify)
        self.assertTrue(transport._activated)

    def test_kex_group16_sha512_server(self):
        transport = FakeTransport(server=True)
        kex = KexGroup16SHA512(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_group14._MSG_KEXDH_INIT,), transport._expect
        )

        msg = Message()
        msg.add_mpint(69)
        msg.rewind()
        kex.parse_next(paramiko.kex_group14._MSG_KEXDH_INIT, msg)
        K = 933242830095376162107925500057692534838883186615567574891154103836907630698358649443101764908667358576734565553213003142941996368306996312915844839972197961603283544950658467545799914435739152351344917376359963584614213874232577733869049670230112638724993540996854599166318001059065780674008011575015459772051180901213815080343343801745386220342919837913506966863570473712948197760657442974564354432738520446202131551650771882909329069340612274196233658123593466135642819578182367229641847749149740891990379052266213711500434128970973602206842980669193719602075489724202241641553472106310932258574377789863734311328542715212248147206865762697424822447603031087553480483833829498375309975229907460562402877655519980113688369262871485777790149373908739910846630414678346163764464587129010141922982925829457954376352735653834300282864445132624993186496129911208133529828461690634463092007726349795944930302881758403402084584307180896465875803621285362317770276493727205689466142632599776710824902573926951951209239626732358074877997756011804454926541386215567756538832824717436605031489511654178384081883801272314328403020205577714999460724519735573055540814037716770051316113795603990199374791348798218428912977728347485489266146775472  # noqa
        H = b"F97BB05A572A663688CA7EA1AA812D3C82EE6C8FA9D4B1D69435783D931157F199909EA38B003E4E4385C8861183CBFF0CF0EF1433A8B3C69AB4DD9420FCC85F"  # noqa
        x = b"1F0000000866616B652D6B65790000020100859FF55A23E0F66463561DD8BFC4764C69C05F85665B06EC9E29EF5003A53A8FA890B6A6EB624DEB55A4FB279DE7010A53580A126817E3D235B05A1081662B1500961D0625F0AAD287F1B597CBA9DB9550D9CC26355C4C59F92E613B5C21AC191F152C09A5DB46DCBA5EA58E3CA6A8B0EB7183E27FAC10106022E8521FA91240FB389060F1E1E4A355049D29DCC82921CE6588791743E4B1DEEE0166F7CC5180C3C75F3773342DF95C8C10AAA5D12975257027936B99B3DED6E6E98CF27EADEAEAE04E7F0A28071F578646B985FCE28A59CEB36287CB65759BE0544D4C4018CDF03C9078FE9CA79ECA611CB6966899E6FD29BE0781491C659FE2380E0D99D50D9CFAAB94E61BE311779719C4C43C6D223AD3799C3915A9E55076A21152DBBF911D6594296D6ECDC1B6FA71997CD29DF987B80FCA7F36BB7F19863C72BBBF839746AFBF9A5B407D468C976AA3E36FA118D3EAAD2E08BF6AE219F81F2CE2BE946337F06CC09BBFABE938A4087E413921CBEC1965ED905999B83396ECA226110CDF6EFB80F815F6489AF87561DA3857F13A7705921306D94176231FBB336B17C3724BC17A28BECB910093AB040873D5D760E8C182B88ECCE3E38DDA68CE35BD152DF7550BD908791FCCEDD1FFDF5ED2A57FFAE79599E487A7726D8A3D950B1729A08FBB60EE462A6BBE8BF0F5F0E1358129A37840FE5B3EEB8BF26E99FA222EAE830000000866616B652D736967"  # noqa
        self.assertEqual(K, transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual(x, hexlify(transport._message.asbytes()).upper())
        self.assertTrue(transport._activated)

    @pytest.mark.skipif("not KexCurve25519.is_available()")
    def test_kex_c25519_client(self):
        K = 71294722834835117201316639182051104803802881348227506835068888449366462300724  # noqa
        transport = FakeTransport(server=False)
        kex = KexCurve25519(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_curve25519._MSG_KEXECDH_REPLY,), transport._expect
        )

        # fake reply
        msg = Message()
        msg.add_string("fake-host-key")
        Q_S = unhexlify(
            "8d13a119452382a1ada8eea4c979f3e63ad3f0c7366786d6c5b54b87219bae49"
        )
        msg.add_string(Q_S)
        msg.add_string("fake-sig")
        msg.rewind()
        kex.parse_next(paramiko.kex_curve25519._MSG_KEXECDH_REPLY, msg)
        H = b"05B6F6437C0CF38D1A6C5A6F6E2558DEB54E7FC62447EBFB1E5D7407326A5475"
        self.assertEqual(K, kex.transport._K)
        self.assertEqual(H, hexlify(transport._H).upper())
        self.assertEqual((b"fake-host-key", b"fake-sig"), transport._verify)
        self.assertTrue(transport._activated)

    @pytest.mark.skipif("not KexCurve25519.is_available()")
    def test_kex_c25519_server(self):
        K = 71294722834835117201316639182051104803802881348227506835068888449366462300724  # noqa
        transport = FakeTransport(server=True)
        kex = KexCurve25519(transport)
        kex.start_kex()
        self.assertEqual(
            (paramiko.kex_curve25519._MSG_KEXECDH_INIT,), transport._expect
        )

        # fake init
        msg = Message()
        Q_C = unhexlify(
            "8d13a119452382a1ada8eea4c979f3e63ad3f0c7366786d6c5b54b87219bae49"
        )
        H = b"DF08FCFCF31560FEE639D9B6D56D760BC3455B5ADA148E4514181023E7A9B042"
        msg.add_string(Q_C)
        msg.rewind()
        kex.parse_next(paramiko.kex_curve25519._MSG_KEXECDH_INIT, msg)
        self.assertEqual(K, transport._K)
        self.assertTrue(transport._activated)
        self.assertEqual(H, hexlify(transport._H).upper())


# RFC 2409 group 2: a genuine 1024-bit safe prime. Used to prove the GEX
# client enforces its declared 2048-bit minimum (it is prime, so only the
# bit-size policy can reject it).
GROUP2_1024_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF  # noqa


class KexValidationTest(unittest.TestCase):
    """
    Validation of peer-supplied key exchange values and of GEX group
    parameters, applied uniformly across the modp kex engines
    (group14-sha256, group16-sha512, group-exchange-sha256) and across
    client/server roles, matching the strictness the elliptic-curve
    engines already had.
    """

    @staticmethod
    def _degenerate_values(p):
        # identity element, order-2 element, the modulus itself, and
        # values outside the group entirely
        return [0, 1, p - 1, p, p + 1, 2 * p]

    def _group_pair(self, kex_class):
        client = kex_class(FakeTransport(server=False))
        client.start_kex()
        server = kex_class(FakeTransport(server=True))
        server.start_kex()
        return client, server

    def _gex_pair(self):
        client = KexGexSHA256(FakeTransport(server=False))
        client.start_kex()
        group = Message()
        group.add_mpint(FakeModulusPack.P)
        group.add_mpint(FakeModulusPack.G)
        group.rewind()
        client.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_GROUP, group)
        server = KexGexSHA256(FakeTransport(server=True))
        server.start_kex()
        request = Message()
        request.add_int(2048)
        request.add_int(2048)
        request.add_int(4096)
        request.rewind()
        server.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_REQUEST, request)
        return client, server

    def _assert_degenerate_matrix(
        self, pair_factory, p, reply_type, init_type
    ):
        # every degenerate value must be rejected on both sides of the
        # exchange: as the server's "f" (client role) and as the
        # client's "e" (server role)
        for value in self._degenerate_values(p):
            with self.subTest(value=value):
                client, server = pair_factory()
                reply = Message()
                reply.add_string("fake-host-key")
                reply.add_mpint(value)
                reply.add_string("fake-sig")
                reply.rewind()
                with pytest.raises(SSHException):
                    client.parse_next(reply_type, reply)
                init = Message()
                init.add_mpint(value)
                init.rewind()
                with pytest.raises(SSHException):
                    server.parse_next(init_type, init)

    def test_group14_rejects_degenerate_values(self):
        self._assert_degenerate_matrix(
            lambda: self._group_pair(KexGroup14SHA256),
            KexGroup14SHA256.P,
            paramiko.kex_group14._MSG_KEXDH_REPLY,
            paramiko.kex_group14._MSG_KEXDH_INIT,
        )

    def test_group16_rejects_degenerate_values(self):
        self._assert_degenerate_matrix(
            lambda: self._group_pair(KexGroup16SHA512),
            KexGroup16SHA512.P,
            paramiko.kex_group14._MSG_KEXDH_REPLY,
            paramiko.kex_group14._MSG_KEXDH_INIT,
        )

    def test_gex_rejects_degenerate_values(self):
        self._assert_degenerate_matrix(
            self._gex_pair,
            FakeModulusPack.P,
            paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,
            paramiko.kex_gex._MSG_KEXDH_GEX_INIT,
        )

    def test_modp_engines_accept_in_range_boundary_values(self):
        # the strict check must not reject legitimate values, including
        # the smallest and largest in-range ones
        engines = [
            (
                lambda: self._group_pair(KexGroup14SHA256),
                KexGroup14SHA256.P,
                paramiko.kex_group14._MSG_KEXDH_REPLY,
                paramiko.kex_group14._MSG_KEXDH_INIT,
            ),
            (
                lambda: self._group_pair(KexGroup16SHA512),
                KexGroup16SHA512.P,
                paramiko.kex_group14._MSG_KEXDH_REPLY,
                paramiko.kex_group14._MSG_KEXDH_INIT,
            ),
            (
                self._gex_pair,
                FakeModulusPack.P,
                paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,
                paramiko.kex_gex._MSG_KEXDH_GEX_INIT,
            ),
        ]
        for pair_factory, p, reply_type, init_type in engines:
            for value in (2, p - 2):
                with self.subTest(value=value):
                    client, server = pair_factory()
                    reply = Message()
                    reply.add_string("fake-host-key")
                    reply.add_mpint(value)
                    reply.add_string("fake-sig")
                    reply.rewind()
                    client.parse_next(reply_type, reply)
                    self.assertTrue(client.transport._activated)
                    init = Message()
                    init.add_mpint(value)
                    init.rewind()
                    server.parse_next(init_type, init)
                    self.assertTrue(server.transport._activated)

    @pytest.mark.skipif("not KexCurve25519.is_available()")
    def test_curve25519_rejects_low_order_public_value(self):
        # the newer engines already reject degenerate inputs; pin that
        # behavior here as the consistency baseline for the modp fixes
        low_order = b"\x00" * 32
        client = KexCurve25519(FakeTransport(server=False))
        client.start_kex()
        reply = Message()
        reply.add_string("fake-host-key")
        reply.add_string(low_order)
        reply.add_string("fake-sig")
        reply.rewind()
        with pytest.raises(SSHException):
            client.parse_next(
                paramiko.kex_curve25519._MSG_KEXECDH_REPLY, reply
            )
        server = KexCurve25519(FakeTransport(server=True))
        server.start_kex()
        init = Message()
        init.add_string(low_order)
        init.rewind()
        with pytest.raises(SSHException):
            server.parse_next(paramiko.kex_curve25519._MSG_KEXECDH_INIT, init)

    # -- GEX group parameter policy -----------------------------------

    def _gex_client(self):
        client = KexGexSHA256(FakeTransport(server=False))
        client.start_kex()
        return client

    def _feed_group(self, client, p, g):
        group = Message()
        group.add_mpint(p)
        group.add_mpint(g)
        group.rewind()
        client.parse_next(paramiko.kex_gex._MSG_KEXDH_GEX_GROUP, group)

    def test_gex_group_enforces_declared_min_bits(self):
        # a prime group below the declared 2048-bit minimum is rejected,
        # even though it passed the old hardcoded 1024-bit floor
        client = self._gex_client()
        with pytest.raises(SSHException, match="out of range"):
            self._feed_group(client, GROUP2_1024_PRIME, 2)

    def test_gex_group_enforces_declared_max_bits(self):
        client = self._gex_client()
        # shrink the declared accept window: a 2048-bit group must then
        # be rejected as too large
        client.max_bits = 1024
        with pytest.raises(SSHException, match="out of range"):
            self._feed_group(client, FakeModulusPack.P, 2)

    def test_gex_group_rejects_composite_p(self):
        # FakeModulusPack.P is prime; P+1 is even, P+2 an odd composite
        for p in (FakeModulusPack.P + 1, FakeModulusPack.P + 2):
            with self.subTest(p=p):
                client = self._gex_client()
                with pytest.raises(SSHException, match="not prime"):
                    self._feed_group(client, p, 2)

    def test_gex_group_rejects_degenerate_generator(self):
        p = FakeModulusPack.P
        for g in (0, 1, p - 1, p, p + 1):
            with self.subTest(g=g):
                client = self._gex_client()
                with pytest.raises(SSHException, match="g.*out of range"):
                    self._feed_group(client, p, g)

    def test_gex_group_accepts_valid_group(self):
        client = self._gex_client()
        self._feed_group(client, FakeModulusPack.P, FakeModulusPack.G)
        self.assertEqual(
            (paramiko.kex_gex._MSG_KEXDH_GEX_REPLY,), client.transport._expect
        )


class PrimalityTest(unittest.TestCase):
    def test_accepts_primes(self):
        for n in (2, 3, 5, 53, 7919, KexGroup14SHA256.P, KexGroup16SHA512.P):
            with self.subTest(n=n):
                self.assertTrue(is_probable_prime(n))

    def test_rejects_composites(self):
        p = KexGroup14SHA256.P
        composites = (
            0,
            1,
            4,
            561,  # Carmichael number
            41041,  # Carmichael number
            3215031751,  # strong pseudoprime to bases 2, 3, 5, 7
            p + 1,  # even
            p + 2,  # odd composite
            p * 3,
        )
        for n in composites:
            with self.subTest(n=n):
                self.assertFalse(is_probable_prime(n))


@pytest.mark.skipif("not KexMLKEM768X25519.is_available()")
class MLKEM768X25519Test(unittest.TestCase):
    """
    Tests for the ML-KEM-768 + X25519 hybrid post-quantum key exchange
    (draft-ietf-sshm-mlkem-hybrid-kex).
    """

    NAME = "mlkem768x25519-sha256"

    def test_is_registered(self):
        self.assertIn(self.NAME, Transport._kex_info)
        self.assertIs(Transport._kex_info[self.NAME], KexMLKEM768X25519)
        self.assertEqual(Transport._preferred_kex[0], self.NAME)

    def test_round_trip(self):
        """
        Drive a real client/server handshake over a loopback and confirm
        the negotiated kex is the hybrid method, both sides authenticate,
        and the encrypted channel is usable end-to-end (which exercises
        the bytes-K key derivation path through Transport._compute_key).
        """
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))

        socks = LoopSocket()
        sockc = LoopSocket()
        sockc.link(socks)
        tc = Transport(sockc)
        ts = Transport(socks)
        try:
            for side in (tc, ts):
                side.get_security_options().kex = (self.NAME,)
            ts.add_server_key(host_key)
            event = threading.Event()
            ts.start_server(event, TestServer())
            tc.connect(
                hostkey=RSAKey(data=host_key.asbytes()),
                username="slowdive",
                password="pygmalion",
            )
            event.wait(1.0)
            self.assertTrue(event.is_set())
            self.assertTrue(ts.is_active())
            self.assertTrue(tc.is_authenticated())
            # Smoke-test the encrypted channel: if the bytes-K key
            # derivation path were broken, the two sides would compute
            # different session keys and the first encrypted packet would
            # fail to decrypt.
            chan = tc.open_session()
            chan.exec_command("yes")
            chan.close()
        finally:
            tc.close()
            ts.close()
            socks.close()
            sockc.close()

    def _server_kex(self):
        kex = KexMLKEM768X25519(FakeTransport(server=True))
        kex.start_kex()
        return kex

    def _client_kex(self):
        kex = KexMLKEM768X25519(FakeTransport(server=False))
        kex.start_kex()
        return kex

    def test_rejects_wrong_init_length(self):
        # Anything other than exactly 1184 + 32 = 1216 bytes must be
        # rejected with SSHException (no ValueError, IndexError, etc.).
        bad_sizes = [
            0,  # empty
            10,  # too short
            1184,  # ML-KEM pubkey-sized but no X25519 half
            32,  # X25519-sized but no ML-KEM half
            1216 - 1,  # one byte short of the correct total
            1216 + 1,  # one byte too long
            1216 * 2,  # two valid-sized payloads concatenated
        ]
        for size in bad_sizes:
            with self.subTest(size=size):
                bad = Message()
                bad.add_string(b"\x00" * size)
                bad.rewind()
                with pytest.raises(SSHException):
                    self._server_kex().parse_next(
                        paramiko.kex_mlkem._MSG_KEX_HYBRID_INIT, bad
                    )

    def test_rejects_wrong_reply_length(self):
        # Symmetric coverage on the client side.
        bad_sizes = [
            0,  # empty
            10,  # too short
            1088,  # ciphertext-sized but no X25519 half
            32,  # X25519-sized but no ciphertext
            1120 - 1,  # one byte short of the correct total
            1120 + 1,  # one byte too long
        ]
        for size in bad_sizes:
            with self.subTest(size=size):
                bad = Message()
                bad.add_string(b"fake-host-key")
                bad.add_string(b"\x00" * size)
                bad.add_string(b"fake-sig")
                bad.rewind()
                with pytest.raises(SSHException):
                    self._client_kex().parse_next(
                        paramiko.kex_mlkem._MSG_KEX_HYBRID_REPLY, bad
                    )
