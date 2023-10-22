from __future__ import unicode_literals

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from ckman.openpgp import OpenPgpController, KEY_SLOT
from yubikit.management import CAPABILITY
from yubikit.core.smartcard import ApduError
from . import condition

import pytest


E = 65537
DEFAULT_PIN = "123456"
NON_DEFAULT_PIN = "654321"
DEFAULT_ADMIN_PIN = "12345678"
NON_DEFAULT_ADMIN_PIN = "87654321"


@pytest.fixture
@condition.capability(CAPABILITY.OPENPGP)
def controller(ccid_connection):
    pgp = OpenPgpController(ccid_connection)
    pgp.reset()
    return pgp


def not_roca(version):
    """ROCA affected"""
    return not ((4, 2, 0) <= version < (4, 3, 5))


def test_generate_requires_admin(controller):
    with pytest.raises(ApduError):
        controller.generate_rsa_key(KEY_SLOT.SIG, 2048)


@condition.check(not_roca)
def test_generate_rsa2048(controller):
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    pub = controller.generate_rsa_key(KEY_SLOT.SIG, 2048)
    assert pub.key_size == 2048
    controller.delete_key(KEY_SLOT.SIG)


@condition.check(not_roca)
@condition.min_version(4)
def test_generate_rsa4096(controller):
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    pub = controller.generate_rsa_key(KEY_SLOT.SIG, 4096)
    assert pub.key_size == 4096


@condition.min_version(5, 2)
def test_generate_secp256r1(controller):
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    pub = controller.generate_ec_key(KEY_SLOT.SIG, "secp256r1")
    assert pub.key_size == 256
    assert pub.curve.name == "secp256r1"


@condition.min_version(5, 2)
def test_generate_ed25519(controller):
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    pub = controller.generate_ec_key(KEY_SLOT.SIG, "ed25519")
    assert len(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)) == 32


@condition.min_version(5, 2)
def test_generate_x25519(controller):
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    pub = controller.generate_ec_key(KEY_SLOT.ENC, "x25519")
    assert len(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)) == 32


def test_import_rsa2048(controller):
    priv = rsa.generate_private_key(E, 2048, default_backend())
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    controller.import_key(KEY_SLOT.SIG, priv)


@condition.min_version(4)
def test_import_rsa4096(controller):
    priv = rsa.generate_private_key(E, 4096, default_backend())
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    controller.import_key(KEY_SLOT.SIG, priv)


@condition.min_version(5, 2)
def test_import_secp256r1(controller):
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    controller.import_key(KEY_SLOT.SIG, priv)


@condition.min_version(5, 2)
def test_import_ed25519(controller):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    controller.import_key(KEY_SLOT.SIG, priv)


@condition.min_version(5, 2)
def test_import_x25519(controller):
    from cryptography.hazmat.primitives.asymmetric import x25519

    priv = x25519.X25519PrivateKey.generate()
    controller.verify_admin(DEFAULT_ADMIN_PIN)
    controller.import_key(KEY_SLOT.ENC, priv)
