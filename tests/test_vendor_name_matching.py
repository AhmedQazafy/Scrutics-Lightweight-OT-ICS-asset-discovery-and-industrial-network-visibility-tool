"""
Vendor names are classified by whole words, never by substrings.

A vendor key matches a name only as whole consecutive words after normalisation (case folded,
accents removed, every other character a separator), so "ge" does not match NETGEAR and "abb"
does not match Abbott. When several keys match, the one with the most words wins; matches of the
same length that disagree on the class, and exclusions, give UNKNOWN. The result does not depend
on the order of the mapping.

tests/data/registry_vendor_names.txt is a pinned list of IEEE registry organisation names: every
name that contains a vendor key as a substring, plus a fixed random sample of others. The names
each class must contain are the reviewed lists next to it.
"""

import os
import random

import pytest

from scrutics.classifier import oui
from scrutics.classifier.oui import (
    VENDOR_CLASS_IT, VENDOR_CLASS_NEUTRAL, VENDOR_CLASS_OT, VENDOR_CLASS_UNKNOWN, classify_vendor,
)

DATA = os.path.join(os.path.dirname(__file__), "data")


def _names(filename):
    with open(os.path.join(DATA, filename), encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f if not line.startswith("#")]


REGISTRY_NAMES = _names("registry_vendor_names.txt")


@pytest.mark.parametrize("vclass, filename", [
    (VENDOR_CLASS_OT, "expected_ot_vendor_names.txt"),
    (VENDOR_CLASS_NEUTRAL, "expected_neutral_vendor_names.txt"),
    (VENDOR_CLASS_IT, "expected_it_vendor_names.txt"),
])
def test_registry_names_in_each_class_are_the_reviewed_list(vclass, filename):
    assert sorted(n for n in REGISTRY_NAMES if classify_vendor(n) == vclass) == sorted(_names(filename))


# Registry organisation names that contain a vendor key only as part of another word, or name an
# unrelated business
@pytest.mark.parametrize("name", [
    "NETGEAR", "Sagemcom Broadband SAS", "Edgecore Networks Corporation",
    "1Verge Internet Technology (Beijing) Co., Ltd.", "3M Germany", "BHP LIMITED", "Bintel AB",
    "BioIntelliSense, Inc.", "Abbott Diagnostics", "Abbey Systems Ltd", "DellKing Industrial Co., Ltd",
    "HIGHPRO INTERNATIONAL R&D CO,.LTD.", "K&J Schmittschneider AG", "Schneider Displaytechnik GmbH",
    "APProSoftware.com", "Prosoft Systems LTD", "B. R. Electronics", "BÄR Bahnsicherung AG",
    "MITSUBISHI CHEMICAL AMERICA, INC.", "GE Healthcare", "Fujitsu Siemens Computers",
    "Nokia Siemens Networks GmbH & Co. KG.", "OMRON HEALTHCARE Co., Ltd.", "Rockwell Collins Canada",
])
def test_unrelated_registry_names_are_not_ot(name):
    assert name in REGISTRY_NAMES
    assert classify_vendor(name) != VENDOR_CLASS_OT


@pytest.mark.parametrize("name", ["Fabbrica Italiana", "NETGEAR Inc.", "Edgecore", "Sagemcom"])
def test_unrelated_names_from_other_sources_are_not_ot(name):
    # Names as other vendor tables write them (not in the registry list)
    assert classify_vendor(name) != VENDOR_CLASS_OT


@pytest.mark.parametrize("name", [
    "DCT-Delta GmbH", "DELTA", "DELTA COMPUTER SYSTEMS, INC.", "DELTA DORE", "DELTA NETWORKS (XIAMEN) LIMITED",
    "DELTA NETWORKS, INC.", "DELTACAST.TV", "DELTAKABEL TELECOM CV", "Deltacom Electronics Ltd",
])
def test_organisations_named_delta_are_not_delta_controls_or_delta_electronics(name):
    assert name in REGISTRY_NAMES
    assert classify_vendor(name) == VENDOR_CLASS_UNKNOWN


def test_delta_controls_is_ot_and_delta_electronics_is_neutral():
    assert classify_vendor("DELTA CONTROLS, INC.") == VENDOR_CLASS_OT
    assert classify_vendor("Delta Electronics, Inc.") == VENDOR_CLASS_NEUTRAL


@pytest.mark.parametrize("name", [
    "Siemens AG", "SIEMENS AG", "Siemens AG,", "Schneider Electric", "TELEMECANIQUE ELECTRIQUE",
    "Rockwell Automation", "GE Fanuc Automation", "Pilz GmbH & Co. KG", "Pilz GmbH & Co.",
    "HMS Industrial Networks", "B&R Industrial Automation GmbH", "MOXA TECHNOLOGIES CORP., LTD.",
    "CONTEMPORARY CONTROL", "Prosoft Technology, Inc", "OPTO-22",
])
def test_industrial_vendors_are_ot(name):
    assert classify_vendor(name) == VENDOR_CLASS_OT


def test_hms_is_ot_under_its_registered_name():
    # "HMS Industrial Networks" is the registry organisation for MA-L 00:30:11
    assert "HMS Industrial Networks" in REGISTRY_NAMES
    assert classify_vendor("HMS Industrial Networks") == VENDOR_CLASS_OT


def test_ge_automation_names_are_ot_and_other_ge_names_are_neutral():
    for name in ("GE Fanuc Automation", "GE Intelligent Platforms", "GE Multilin", "GE Grid Solutions",
                 "GE Digital Energy"):
        assert classify_vendor(name) == VENDOR_CLASS_OT, name
    for name in ("General Electric Company", "GE", "GE Appliances", "Current, powered by GE"):
        assert classify_vendor(name) == VENDOR_CLASS_NEUTRAL, name
    assert classify_vendor("GE Healthcare") == VENDOR_CLASS_UNKNOWN


def test_the_more_specific_key_wins():
    assert classify_vendor("APC by Schneider Electric") == VENDOR_CLASS_NEUTRAL      # 4 words over 2
    assert classify_vendor("Fujitsu Siemens Computers") == VENDOR_CLASS_UNKNOWN     # exclusion over "siemens"


def test_keys_of_the_same_length_with_different_classes_give_unknown():
    # Registry name of a joint venture: "intel" (IT) and "ge" (NEUTRAL), one word each
    assert "Intel – GE Care Innovations LLC" in REGISTRY_NAMES
    assert classify_vendor("Intel – GE Care Innovations LLC") == VENDOR_CLASS_UNKNOWN


def test_result_does_not_depend_on_the_order_of_the_keys(monkeypatch):
    expected = {n: classify_vendor(n) for n in REGISTRY_NAMES}
    keys = list(oui._VENDOR_KEYS)
    for seed in range(3):
        random.Random(seed).shuffle(keys)
        monkeypatch.setattr(oui, "_VENDOR_KEYS", tuple(keys))
        assert {n: classify_vendor(n) for n in REGISTRY_NAMES} == expected


def _matches_a_registry_name(key):
    words = oui._vendor_tokens(key)
    return any(oui._contains_words(oui._vendor_tokens(n), words) for n in REGISTRY_NAMES)


def test_every_key_and_exclusion_matches_a_registry_name_unless_listed_outside_it():
    keys = set(oui.VENDOR_CLASS_MAPPING) | set(oui.VENDOR_NAME_EXCLUSIONS)
    dead = sorted(k for k in keys if not _matches_a_registry_name(k))
    assert dead == sorted(oui.NAMES_OUTSIDE_REGISTRY)


def test_names_listed_outside_the_registry_are_vendor_keys():
    assert oui.NAMES_OUTSIDE_REGISTRY <= set(oui.VENDOR_CLASS_MAPPING)


@pytest.mark.parametrize("name", ["", "   ", "Unknown", "unknown", None, "&&&", "Unrecognized Corp 12345"])
def test_names_without_a_vendor_key_are_unknown(name):
    assert classify_vendor(name) == VENDOR_CLASS_UNKNOWN


def test_vendor_names_are_matched_after_case_punctuation_and_accent_normalisation():
    # Names as vendors write them; these vendors are not in the registry under these names
    assert classify_vendor("Yokogawa Electric Corporation") == VENDOR_CLASS_OT
    assert classify_vendor("Digi International Inc") == VENDOR_CLASS_NEUTRAL
    assert classify_vendor("siemens  ag") == VENDOR_CLASS_OT
    assert classify_vendor("Schneider-Electric(China)Co.Ltd,Shenzhen Branch") == VENDOR_CLASS_OT


@pytest.mark.parametrize("name, vclass", [
    ("General Electric Digital Energy", VENDOR_CLASS_OT),
    ("Super Micro Computer, Inc.", VENDOR_CLASS_IT),
    ("Siemens Industry Software Inc.", VENDOR_CLASS_NEUTRAL),
    ("Honeywell Video Systems", VENDOR_CLASS_NEUTRAL),
    ("SECURITE COMMUNICATIONS / HONEYWELL", VENDOR_CLASS_NEUTRAL),
    ("Emerson Network Power, Avocent Division", VENDOR_CLASS_NEUTRAL),
    ("Eaton Corp. Electrical Group Data Center Solutions - Pulizzi", VENDOR_CLASS_NEUTRAL),
    ("Emerson Climate Technologies GmbH", VENDOR_CLASS_OT),
    ("Siemens Healthcare Diagnostics Manufacturing Ltd", VENDOR_CLASS_UNKNOWN),
    ("Siemens Home & Office Comm. Devices", VENDOR_CLASS_UNKNOWN),
    ("Valeo Siemens eAutomotive Norway", VENDOR_CLASS_UNKNOWN),
    ("SIEMENS TELECOMMUNICATION SYSTEMS LIMITED", VENDOR_CLASS_UNKNOWN),
    ("HONEYWELL-DATING", VENDOR_CLASS_UNKNOWN),
    ("Emerson Appliance Motors and Controls", VENDOR_CLASS_UNKNOWN),
    ("Hirschmann Multimedia B.V.", VENDOR_CLASS_UNKNOWN),
    ("TRIAX-HIRSCHMANN Multi-Media GmbH", VENDOR_CLASS_UNKNOWN),
    ("DigiBoard", VENDOR_CLASS_NEUTRAL),
    ("Digiboard Eletronica da Amazonia Ltda", VENDOR_CLASS_UNKNOWN),
    ("Siemens AG, Healthcare Sector", VENDOR_CLASS_UNKNOWN),
])
def test_curated_registry_names_resolve_to_their_reviewed_class(name, vclass):
    assert name in REGISTRY_NAMES
    assert classify_vendor(name) == vclass
