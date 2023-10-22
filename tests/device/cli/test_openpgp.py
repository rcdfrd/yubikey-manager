from yubikit.management import CAPABILITY
from .. import condition
import pytest


@pytest.fixture(autouse=True)
@condition.capability(CAPABILITY.OPENPGP)
def preconditions(ckman_cli):
    ckman_cli("openpgp", "reset", "-f")


class TestOpenPGP:
    def test_openpgp_info(self, ckman_cli):
        output = ckman_cli("openpgp", "info").output
        assert "OpenPGP version:" in output

    def test_openpgp_reset(self, ckman_cli):
        output = ckman_cli("openpgp", "reset", "-f").output
        assert "Success! All data has been cleared and default PINs are set." in output
