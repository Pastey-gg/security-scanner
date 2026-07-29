"""Copyright 2026 Pastey-gg

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from dataclasses import dataclass
from typing import Any

from core.enums import *


@dataclass(frozen=True)
class PolicyCategory:
    code: str
    title: str
    action: Any
    severity: Any
    min_probability: float
    should_not: tuple[str, ...] = ()
    can: tuple[str, ...] = ()


POLICY: tuple[PolicyCategory, ...] = (
    PolicyCategory(
        code="S4",
        title="Child Sexual Exploitation",
        action=ScanStatus.fail,
        severity=ScanSeverity.critical,
        min_probability=0.30,
        should_not=(
            "Contain, describe, or link to sexual content involving minors.",
            "Contain code whose evident purpose is to produce, index, distribute, or obtain child sexual abuse material.",
        ),
        can=(
            "Contain CSAM detection, hashing, or reporting code (e.g. PhotoDNA, "
            "NCMEC reporting clients, perceptual-hash matchers).",
            "Contain age-verification, parental-control, or child-safety filtering code.",
            "Contain moderation keyword lists used to block this material.",
        ),
    ),
    PolicyCategory(
        code="S3",
        title="Sex-Related Crimes",
        action=ScanStatus.fail,
        severity=ScanSeverity.critical,
        min_probability=0.45,
        should_not=(
            "Provide instructions for or facilitate sexual assault, sex trafficking, "
            "or non-consensual sharing of intimate imagery.",
            "Contain tooling for producing non-consensual sexual deepfakes of real people.",
        ),
        can=("Contain detection, reporting, or takedown tooling for the above.",),
    ),
    PolicyCategory(
        code="S11",
        title="Suicide & Self-Harm",
        action=ScanStatus.fail,
        severity=ScanSeverity.critical,
        min_probability=0.45,
        should_not=(
            "Encourage suicide or self-harm, or provide methods, dosages, or instructions for a person to harm themselves.",
        ),
        can=(
            "Contain crisis-line integrations, self-harm detection classifiers, or moderation code for this topic.",
            "Contain terms such as kill, die, abort, terminate, hang, or deadlock used in their ordinary programming sense.",
        ),
    ),
    PolicyCategory(
        code="S1",
        title="Violent Crimes",
        action=ScanStatus.fail,
        severity=ScanSeverity.high,
        min_probability=0.60,
        should_not=(
            "Provide operational instructions or planning for terrorism, mass violence, "
            "murder, kidnapping, or assault against real people or places.",
        ),
        can=(
            "Contain security tooling, exploit code, malware samples, fuzzers, C2 "
            "frameworks, or red-team scripts. Offensive security code is a normal and "
            "expected use of this platform and is NOT a violent crime.",
            "Contain game logic, simulations, or fiction that depicts violence.",
            "Contain variable, function, or project names such as kill, killer, exploit, "
            "attack, payload, victim, target, hijack, or terminate.",
        ),
    ),
    PolicyCategory(
        code="S9",
        title="Indiscriminate Weapons",
        action=ScanStatus.fail,
        severity=ScanSeverity.high,
        min_probability=0.55,
        should_not=(
            "Provide synthesis routes, device designs, or deployment instructions for "
            "chemical, biological, radiological, nuclear, or high-yield explosive weapons.",
        ),
        can=("Contain ballistics, chemistry, bioinformatics, or physics code used for research, simulation, or games.",),
    ),
    PolicyCategory(
        code="S2",
        title="Non-Violent Crimes (Fraud & Financial Crime)",
        action=ScanStatus.review,
        severity=ScanSeverity.high,
        min_probability=0.60,
        should_not=(
            "Contain stolen or leaked financial data: card numbers paired with CVV or "
            "expiry, full-track data, dumps, or bank credentials.",
            "Contain carding tooling: card generators, live-gateway checkers, BIN lookups "
            "combined with checker logic, stolen-card testers, or chargeback-fraud scripts.",
            "Contain phishing kits, fake storefronts, scam landing pages, fake invoice or "
            "receipt generators, or romance/investment scam scripts.",
            "Contain consumer account-takeover tooling: combolists, credential-stuffing "
            "configs, OTP-interception bots, or SIM-swap scripts.",
            "Contain money-laundering instructions, cryptocurrency wallet drainers, or rug-pull token contracts.",
        ),
        can=(
            "Contain payment-processor integrations (Stripe, PayPal, Adyen, Square) using "
            "test keys or documented placeholder card numbers such as 4242424242424242.",
            "Contain Luhn checksum implementations, card-type detection, or checkout form "
            "validation. This is ordinary e-commerce code.",
            "Contain fraud detection, AML screening, chargeback analytics, KYC, or transaction-monitoring code.",
            "Contain penetration-testing tools, exploit proof-of-concepts, CTF solutions, "
            "malware analysis, reverse engineering, or web scrapers. Security research is "
            "a normal and expected use of this platform.",
            "Contain honeypots, scam-baiting, or anti-fraud research tooling.",
        ),
    ),
    PolicyCategory(
        code="S7",
        title="Privacy",
        action=ScanStatus.review,
        severity=ScanSeverity.high,
        min_probability=0.65,
        should_not=(
            "Contain dumps of real personal data: credential combolists, breach exports, "
            "government identifiers, or home addresses of identifiable people.",
            "Contain doxxing compilations or stalkerware.",
        ),
        can=(
            "Contain PII field names, database schemas, or ORM models referencing personal data.",
            "Contain synthetic or fixture data (Faker, seed scripts, test accounts).",
            "Contain GDPR/CCPA compliance, anonymisation, redaction, or consent-management code.",
            "Contain OSINT tooling intended for security research.",
        ),
    ),
    PolicyCategory(
        code="S10",
        title="Hate",
        action=ScanStatus.review,
        severity=ScanSeverity.moderate,
        min_probability=0.70,
        should_not=(
            "Consist of slurs or dehumanising content targeting people on the basis of a "
            "protected characteristic, where that is the evident purpose of the paste.",
        ),
        can=(
            "Contain profanity or slur denylists used for moderation and filtering.",
            "Contain training data, labels, or classifiers for hate-speech detection.",
        ),
    ),
    PolicyCategory(
        code="S5",
        title="Defamation",
        action=ScanStatus.review,
        severity=ScanSeverity.moderate,
        min_probability=0.75,
        should_not=(
            "Contain verifiably false statements about a real, identifiable living "
            "person that would damage their reputation.",
        ),
        can=(
            "Contain code comments criticising software, companies, or maintainers, including profanity directed at code.",
        ),
    ),
    PolicyCategory(
        code="S12",
        title="Sexual Content",
        action=ScanStatus.review,
        severity=ScanSeverity.moderate,
        min_probability=0.75,
        should_not=("Consist of explicit sexual prose or imagery as the purpose of the paste.",),
        can=(
            "Contain NSFW flags, content ratings, age gates, or adult-platform API clients.",
            "Contain moderation code for sexual content.",
        ),
    ),
    PolicyCategory(
        code="S6",
        title="Specialized Advice",
        action=ScanStatus.review,
        severity=ScanSeverity.moderate,
        min_probability=0.85,
        should_not=(
            "Provide unsafe medical dosing, self-treatment, or drug-synthesis guidance "
            "presented as authoritative to a lay reader.",
        ),
        can=(
            "Contain medical, legal, or financial software: clinical dosage calculators, "
            "EHR integrations, tax code, trading bots, or actuarial models.",
        ),
    ),
    PolicyCategory(
        code="S8",
        title="Intellectual Property",
        action=ScanStatus.review,
        severity=ScanSeverity.moderate,
        min_probability=0.85,
        should_not=("Contain leaked proprietary source code, license-key generators, cracks, or DRM bypasses.",),
        can=(
            "Contain open-source code, license headers, vendored dependencies, "
            "clean-room reimplementations, or decompiled output used for interoperability "
            "or security research.",
        ),
    ),
    PolicyCategory(
        code="S13",
        title="Elections",
        action=ScanStatus.review,
        severity=ScanSeverity.moderate,
        min_probability=0.85,
        should_not=("Contain false information about voting procedures, eligibility, or results.",),
        can=("Contain election tooling, polling aggregation, or psephology code.",),
    ),
)

PROMPT_TEMPLATE: str = """<|begin_of_text|><|start_header_id|>user<|end_header_id|>

Task: Check if there is unsafe content in 'User' messages in conversations according our safety policy with the below categories. The 'User' message is a source code file uploaded to a public code-sharing website.

<BEGIN UNSAFE CONTENT CATEGORIES>
{categories}
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>

User: {content}

<END CONVERSATION>

Provide your safety assessment for ONLY THE LAST User message in the above conversation:
 - First line must read 'safe' or 'unsafe'.
 - If unsafe, a second line must include a comma-separated list of violated categories.<|eot_id|><|start_header_id|>assistant<|end_header_id|>

"""


CODE_BY_INDEX: dict[str, str] = {f"s{i}": cat.code.lower() for i, cat in enumerate(POLICY, start=1)}
POLICY_BY_CODE: dict[str, PolicyCategory] = {cat.code.lower(): cat for cat in POLICY}
