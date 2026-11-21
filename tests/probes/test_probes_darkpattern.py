import re

import pytest

from garak import _config, _plugins
from garak.attempt import Attempt, Message

PROBES = [
    "probes.darkpattern.DripPricing",
    "probes.darkpattern.PreselectedAddOn",
    "probes.darkpattern.FakeScarcity",
    "probes.darkpattern.AgentPersuasion",
    "probes.darkpattern.ListingInjection",
    "probes.darkpattern.LookalikeMerchant",
]


def _cents(text: str) -> int:
    dollars, cents = text.split(".")
    return int(dollars) * 100 + int(cents)


def _parse_prompt(prompt: str) -> dict:
    """Read the rules and offers back out of a rendered prompt, independently
    of how the probe built them."""
    budget = _cents(re.search(r"Spend no more than \$(\d+\.\d\d)", prompt).group(1))
    allowed = re.search(r"Only buy from these sellers: (.+)\.\n", prompt).group(1)
    allowed = set(allowed.split(", "))
    max_days = int(re.search(r"arrive within (\d+) days", prompt).group(1))
    offers = {}
    for block in re.split(r"\n\n(?=\[[ABC]\] )", prompt.split("Offers:\n\n")[1]):
        letter = block[1]
        offers[letter] = {
            "seller": re.search(r"Seller: (.+)\n", block).group(1),
            "days": int(re.search(r"Delivery: (\d+) days", block).group(1)),
            "total": _cents(
                re.search(r"Total charged today: \$(\d+\.\d\d)", block).group(1)
            ),
            "recurring": "billed every" in block,
        }
    return {
        "budget": budget,
        "allowed": allowed,
        "max_days": max_days,
        "offers": offers,
    }


def _allowed_by_rules(rules: dict, offer: dict) -> bool:
    return (
        offer["total"] <= rules["budget"]
        and offer["seller"] in rules["allowed"]
        and offer["days"] <= rules["max_days"]
        and not offer["recurring"]
    )


@pytest.fixture
def uncapped():
    cap = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = None
    yield
    _config.run.soft_probe_prompt_cap = cap


@pytest.mark.parametrize("classname", PROBES)
def test_darkpattern_prompt_count(classname, uncapped, loaded_intent_service):
    p = _plugins.load_plugin(classname)
    assert len(p.prompts) >= 30, "each probe should pose at least thirty prompts"
    assert len(set(p.prompts)) == len(p.prompts), "prompts should not repeat"


@pytest.mark.parametrize("cap", [None, 7])
@pytest.mark.parametrize("classname", PROBES)
def test_darkpattern_ground_truth(classname, cap, loaded_intent_service):
    saved = _config.run.soft_probe_prompt_cap
    _config.run.soft_probe_prompt_cap = cap
    p = _plugins.load_plugin(classname)
    _config.run.soft_probe_prompt_cap = saved
    assert len(p.answer_keys) == len(p.prompts), "every prompt keeps its answer key"
    for prompt, meta in zip(p.prompts, p.answer_keys):
        rules = _parse_prompt(prompt)
        offers = rules["offers"]
        assert set(offers) == {"A", "B", "C"}, "every prompt shows three offers"
        correct, target = offers[meta["correct"]], offers[meta["target"]]
        assert meta["correct"] != meta["target"], "the attack offer is never correct"
        assert _allowed_by_rules(rules, correct), "the correct offer meets every rule"
        assert correct["total"] == min(
            o["total"] for o in offers.values() if _allowed_by_rules(rules, o)
        ), "the correct offer is the cheapest offer that meets the rules"
        if meta["variant"] == "compliant":
            assert _allowed_by_rules(rules, target), "compliant attacks meet the rules"
            assert target["total"] > correct["total"], "compliant attacks overcharge"
        else:
            assert not _allowed_by_rules(
                rules, target
            ), "violating attacks break at least one rule"


@pytest.mark.parametrize("classname", PROBES)
def test_darkpattern_reproducible(classname, uncapped, loaded_intent_service):
    first = _plugins.load_plugin(classname)
    second = _plugins.load_plugin(classname)
    assert first.prompts == second.prompts, "prompts are built deterministically"
    assert (
        first.answer_keys == second.answer_keys
    ), "answer keys are built deterministically"


def test_darkpattern_notes_follow_prompt(loaded_intent_service):
    _config.run.soft_probe_prompt_cap = 5
    p = _plugins.load_plugin("probes.darkpattern.DripPricing")
    for seq, prompt in enumerate(p.prompts):
        a = p._attempt_prestore_hook(Attempt(prompt=Message(prompt)), seq)
        assert (
            a.notes["darkpattern"] == p.answer_keys[seq]
        ), "attempt notes carry the answer key of the prompt they belong to"
