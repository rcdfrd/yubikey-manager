from canokit.core import TRANSPORT
from ckman.cli.__main__ import cli
from ckman.cli.aliases import apply_aliases
from click.testing import CliRunner
from functools import partial
import pytest


@pytest.fixture(scope="module")
def ckman_cli(device, info):
    if device.transport == TRANSPORT.NFC:
        return partial(_ckman_cli, "--reader", device.reader.name)
    elif info.serial is not None:
        return partial(_ckman_cli, "--device", info.serial)
    else:
        return _ckman_cli


def _ckman_cli(*argv, **kwargs):
    argv = apply_aliases(["ckman"] + [str(a) for a in argv])
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(cli, argv[1:], obj={}, **kwargs)
    if result.exit_code != 0:
        raise result.exception
    return result
