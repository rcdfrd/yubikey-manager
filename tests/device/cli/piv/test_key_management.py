from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from yubikit.core import NotSupportedError
from .util import DEFAULT_PIN, DEFAULT_MANAGEMENT_KEY
from ... import condition
import tempfile
import os
import pytest


def generate_pem_eccp256_keypair():
    pk = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return (
        pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def roca(version):
    """Not ROCA affected"""
    return (4, 2, 0) <= version < (4, 3, 5)


def not_roca(version):
    """ROCA affected"""
    return not roca(version)


@pytest.fixture()
def tmp_file():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    yield tmp.name
    os.remove(tmp.name)


class TestKeyExport:
    @condition.min_version(5, 3)
    def test_from_metadata(self, ckman_cli):
        pair = generate_pem_eccp256_keypair()

        ckman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
            input=pair[0],
        )
        exported = ckman_cli("piv", "keys", "export", "9a", "-").stdout_bytes
        assert exported == pair[1]

    @condition.min_version(4, 3)
    def test_from_metadata_or_attestation(self, ckman_cli):
        der = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-F",
            "der",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        ).stdout_bytes
        exported = ckman_cli(
            "piv", "keys", "export", "9a", "-F", "der", "-"
        ).stdout_bytes
        assert der == exported

    def test_from_metadata_or_cert(self, ckman_cli):
        private_key_pem, public_key_pem = generate_pem_eccp256_keypair()
        ckman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
            input=private_key_pem,
        )
        ckman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
            "-s",
            "test",
            input=public_key_pem,
        )

        exported = ckman_cli("piv", "keys", "export", "9a", "-").stdout_bytes

        assert public_key_pem == exported

    @condition.max_version(5, 2, 9)
    def test_from_cert_verify(self, ckman_cli):
        private_key_pem, public_key_pem = generate_pem_eccp256_keypair()
        ckman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
            input=private_key_pem,
        )
        ckman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
            "-s",
            "test",
            input=public_key_pem,
        )
        ckman_cli("piv", "keys", "export", "9a", "--verify", "-P", DEFAULT_PIN, "-")

    @condition.max_version(5, 2, 9)
    def test_from_cert_verify_fails(self, ckman_cli):
        private_key_pem = generate_pem_eccp256_keypair()[0]
        public_key_pem = generate_pem_eccp256_keypair()[1]
        ckman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
            input=private_key_pem,
        )
        ckman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
            "-s",
            "test",
            input=public_key_pem,
        )
        with pytest.raises(SystemExit):
            ckman_cli("piv", "keys", "export", "9a", "--verify", "-P", DEFAULT_PIN, "-")


class TestKeyManagement:
    @condition.check(not_roca)
    def test_generate_key_default(self, ckman_cli):
        output = ckman_cli(
            "piv", "keys", "generate", "9a", "-m", DEFAULT_MANAGEMENT_KEY, "-"
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.check(roca)
    def test_generate_key_default_cve201715361(self, ckman_cli):
        with pytest.raises(NotSupportedError):
            ckman_cli(
                "piv", "keys", "generate", "9a", "-m", DEFAULT_MANAGEMENT_KEY, "-"
            )

    @condition.check(not_roca)
    @condition.fips(False)
    def test_generate_key_rsa1024(self, ckman_cli):
        output = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "RSA1024",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.check(not_roca)
    def test_generate_key_rsa2048(self, ckman_cli):
        output = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "RSA2048",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.fips(False)
    @condition.check(roca)
    def test_generate_key_rsa1024_cve201715361(self, ckman_cli):
        with pytest.raises(NotSupportedError):
            ckman_cli(
                "piv",
                "keys",
                "generate",
                "9a",
                "-a",
                "RSA1024",
                "-m",
                DEFAULT_MANAGEMENT_KEY,
                "-",
            )

    @condition.check(roca)
    def test_generate_key_rsa2048_cve201715361(self, ckman_cli):
        with pytest.raises(NotSupportedError):
            ckman_cli(
                "piv",
                "keys",
                "generate",
                "9a",
                "-a",
                "RSA2048",
                "-m",
                DEFAULT_MANAGEMENT_KEY,
                "-",
            )

    def test_generate_key_eccp256(self, ckman_cli):
        output = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    def test_import_key_eccp256(self, ckman_cli):
        ckman_cli(
            "piv",
            "keys",
            "import",
            "9a",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
            input=generate_pem_eccp256_keypair()[0],
        )

    @condition.min_version(4)
    def test_generate_key_eccp384(self, ckman_cli):
        output = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP384",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.min_version(4)
    def test_generate_key_pin_policy_always(self, ckman_cli):
        output = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "--pin-policy",
            "ALWAYS",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-a",
            "ECCP256",
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.min_version(4)
    def test_import_key_pin_policy_always(self, ckman_cli):
        for pin_policy in ["ALWAYS", "always"]:
            ckman_cli(
                "piv",
                "keys",
                "import",
                "9a",
                "--pin-policy",
                pin_policy,
                "-m",
                DEFAULT_MANAGEMENT_KEY,
                "-",
                input=generate_pem_eccp256_keypair()[0],
            )

    @condition.min_version(4)
    def test_generate_key_touch_policy_always(self, ckman_cli):
        output = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "--touch-policy",
            "ALWAYS",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-a",
            "ECCP256",
            "-",
        ).output
        assert "BEGIN PUBLIC KEY" in output

    @condition.min_version(4)
    def test_import_key_touch_policy_always(self, ckman_cli):
        for touch_policy in ["ALWAYS", "always"]:
            ckman_cli(
                "piv",
                "keys",
                "import",
                "9a",
                "--touch-policy",
                touch_policy,
                "-m",
                DEFAULT_MANAGEMENT_KEY,
                "-",
                input=generate_pem_eccp256_keypair()[0],
            )

    @condition.min_version(4, 3)
    def test_attest_key(self, ckman_cli):
        ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        )
        output = ckman_cli("piv", "keys", "attest", "9a", "-").output
        assert "BEGIN CERTIFICATE" in output

    def _test_generate_csr(self, ckman_cli, tmp_file, algo):
        ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            algo,
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            tmp_file,
        )
        output = ckman_cli(
            "piv",
            "certificates",
            "request",
            "9a",
            tmp_file,
            "-s",
            "test-subject",
            "-P",
            DEFAULT_PIN,
            "-",
        ).output
        csr = x509.load_pem_x509_csr(output.encode(), default_backend())
        assert csr.is_signature_valid

    @condition.fips(False)
    @condition.check(not_roca)
    def test_generate_csr_rsa1024(self, ckman_cli, tmp_file):
        self._test_generate_csr(ckman_cli, tmp_file, "RSA1024")

    def test_generate_csr_eccp256(self, ckman_cli, tmp_file):
        self._test_generate_csr(ckman_cli, tmp_file, "ECCP256")

    def test_import_verify_correct_cert_succeeds_with_pin(self, ckman_cli, tmp_file):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output

        ckman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
            "-s",
            "test",
            input=public_key_pem,
        )

        ckman_cli("piv", "certificates", "export", "9a", tmp_file)

        with pytest.raises(SystemExit):
            ckman_cli(
                "piv",
                "certificates",
                "import",
                "--verify",
                "9a",
                tmp_file,
                "-m",
                DEFAULT_MANAGEMENT_KEY,
            )

        ckman_cli(
            "piv",
            "certificates",
            "import",
            "--verify",
            "9a",
            tmp_file,
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
        )
        ckman_cli(
            "piv",
            "certificates",
            "import",
            "--verify",
            "9a",
            tmp_file,
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            input=DEFAULT_PIN,
        )

    def test_import_verify_wrong_cert_fails(self, ckman_cli):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output

        ckman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
            "-s",
            "test",
            input=public_key_pem,
        )

        cert_pem = ckman_cli("piv", "certificates", "export", "9a", "-").output

        # Overwrite the key with a new one
        ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
            input=public_key_pem,
        )

        with pytest.raises(SystemExit):
            ckman_cli(
                "piv",
                "certificates",
                "import",
                "--verify",
                "9a",
                "-",
                "-m",
                DEFAULT_MANAGEMENT_KEY,
                "-P",
                DEFAULT_PIN,
                input=cert_pem,
            )

    def test_import_no_verify_wrong_cert_succeeds(self, ckman_cli):
        # Set up a key in the slot and create a certificate for it
        public_key_pem = ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
        ).output

        ckman_cli(
            "piv",
            "certificates",
            "generate",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
            "-s",
            "test",
            input=public_key_pem,
        )

        cert_pem = ckman_cli("piv", "certificates", "export", "9a", "-").output

        # Overwrite the key with a new one
        ckman_cli(
            "piv",
            "keys",
            "generate",
            "9a",
            "-a",
            "ECCP256",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-",
            input=public_key_pem,
        )

        with pytest.raises(SystemExit):
            ckman_cli(
                "piv",
                "certificates",
                "import",
                "--verify",
                "9a",
                "-",
                "-m",
                DEFAULT_MANAGEMENT_KEY,
                "-P",
                DEFAULT_PIN,
                input=cert_pem,
            )

        ckman_cli(
            "piv",
            "certificates",
            "import",
            "9a",
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "-P",
            DEFAULT_PIN,
            input=cert_pem,
        )

    @condition.min_version(4, 3)
    def test_export_attestation_certificate(self, ckman_cli):
        output = ckman_cli("piv", "certificates", "export", "f9", "-").output
        assert "BEGIN CERTIFICATE" in output
