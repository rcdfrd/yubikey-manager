from ckman.device import get_name
from ckman.base import YUBIKEY
from yubikit.core import TRANSPORT
from yubikit.management import (
    CAPABILITY,
    FORM_FACTOR,
    DeviceInfo,
    DeviceConfig,
    Version,
)
from typing import cast


def info(form_factor):
    return DeviceInfo(
        config=cast(DeviceConfig, None),
        serial=None,
        version=Version(5, 3, 0),
        form_factor=form_factor,
        supported_capabilities={TRANSPORT.USB: 0xFF},  # type: ignore
        is_locked=False,
        is_fips=False,
    )


def info_nfc(form_factor):
    with_nfc = info(form_factor)
    with_nfc.supported_capabilities[TRANSPORT.NFC] = 0xFF
    return with_nfc


def test_yk5_formfactors():
    kt = YUBIKEY.YK4
    assert get_name(info(FORM_FACTOR.USB_A_KEYCHAIN), kt) == "YubiKey 5A"
    assert get_name(info_nfc(FORM_FACTOR.USB_A_KEYCHAIN), kt) == "YubiKey 5 NFC"
    assert get_name(info(FORM_FACTOR.USB_A_NANO), kt) == "YubiKey 5 Nano"
    assert get_name(info(FORM_FACTOR.USB_C_KEYCHAIN), kt) == "YubiKey 5C"
    assert get_name(info_nfc(FORM_FACTOR.USB_C_KEYCHAIN), kt) == "YubiKey 5C NFC"
    assert get_name(info(FORM_FACTOR.USB_C_NANO), kt) == "YubiKey 5C Nano"
    assert get_name(info(FORM_FACTOR.USB_C_LIGHTNING), kt) == "YubiKey 5Ci"
    assert get_name(info(FORM_FACTOR.USB_A_BIO), kt) == "YubiKey Bio"
    assert get_name(info(FORM_FACTOR.USB_C_BIO), kt) == "YubiKey C Bio"
    assert get_name(info(FORM_FACTOR.UNKNOWN), kt) == "YubiKey 5"
    assert get_name(info_nfc(FORM_FACTOR.UNKNOWN), kt) == "YubiKey 5 NFC"


def fido(device_info):
    device_info.supported_capabilities[TRANSPORT.USB] = (
        CAPABILITY.U2F | CAPABILITY.FIDO2
    )
    if TRANSPORT.NFC in device_info.supported_capabilities:
        device_info.supported_capabilities[TRANSPORT.NFC] = (
            CAPABILITY.U2F | CAPABILITY.FIDO2
        )
    return device_info


def test_yk5_fido():
    kt = YUBIKEY.YK4
    assert (
        get_name(fido(info(FORM_FACTOR.USB_A_BIO)), kt) == "YubiKey Bio - FIDO Edition"
    )
    assert (
        get_name(fido(info(FORM_FACTOR.USB_C_BIO)), kt)
        == "YubiKey C Bio - FIDO Edition"
    )


def fips(device_info):
    device_info.is_fips = True
    return device_info


def test_yk5_fips_formfactors():
    kt = YUBIKEY.YK4
    assert get_name(fips(info(FORM_FACTOR.USB_A_KEYCHAIN)), kt) == "YubiKey 5A FIPS"
    assert (
        get_name(fips(info_nfc(FORM_FACTOR.USB_A_KEYCHAIN)), kt) == "YubiKey 5 NFC FIPS"
    )
    assert get_name(fips(info(FORM_FACTOR.USB_A_NANO)), kt) == "YubiKey 5 Nano FIPS"
    assert get_name(fips(info(FORM_FACTOR.USB_C_KEYCHAIN)), kt) == "YubiKey 5C FIPS"
    assert (
        get_name(fips(info_nfc(FORM_FACTOR.USB_C_KEYCHAIN)), kt)
        == "YubiKey 5C NFC FIPS"
    )
    assert get_name(fips(info(FORM_FACTOR.USB_C_NANO)), kt) == "YubiKey 5C Nano FIPS"
    assert get_name(fips(info(FORM_FACTOR.USB_C_LIGHTNING)), kt) == "YubiKey 5Ci FIPS"
    assert get_name(fips(info(FORM_FACTOR.USB_A_BIO)), kt) == "YubiKey Bio FIPS"
    assert get_name(fips(info(FORM_FACTOR.USB_C_BIO)), kt) == "YubiKey C Bio FIPS"
    assert get_name(fips(info(FORM_FACTOR.UNKNOWN)), kt) == "YubiKey 5 FIPS"
    assert get_name(fips(info_nfc(FORM_FACTOR.UNKNOWN)), kt) == "YubiKey 5 NFC FIPS"
