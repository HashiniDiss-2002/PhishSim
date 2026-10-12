"""
compliance_mapper.py
---------------------
Maps observed campaign behaviour (click rate, submission rate, report rate)
to relevant data-protection obligations and produces plain-language
recommendations for the client admin dashboard — both at the CAMPAIGN
level (aggregate across all employees) and the EMPLOYEE level (a single
person's behaviour across all the campaigns they've been part of).

This is deliberately a transparent, editable rules table rather than a
black-box score, so it can be defended and cited in the thesis:
each rule states which regulatory concept it relates to and why. This
is also the core novelty claim of the project — see methodology
Chapter 2.3 — so keep the scoring logic readable and inspectable rather
than optimising it into something opaque.

NOTE ON LEGAL SOURCING: every citation below quotes the operative sentence
of the actual regulation it names, taken from the official/primary text —
GDPR (Regulation (EU) 2016/679, via eur-lex.europa.eu / gdpr-info.eu) and
Sri Lanka's Personal Data Protection Act, No. 9 of 2022 (the enacted bill
text, parliament.lk/uploads/acts/gbills/english/6242.pdf) — not reworded
by this project. This is still a STUDENT RESEARCHER's mapping of "which
article does this behaviour implicate," not a legal determination reviewed
by a qualified lawyer: say so plainly if asked, rather than overclaiming a
formal legal sign-off. Two deliberate honesty notes worth keeping in mind:
(1) GDPR Art. 83 fines are a maximum ceiling the supervisory authority MAY
impose after its own investigation and the criteria in Art. 83(2) — not an
automatic consequence of any one finding; (2) the PDPA's Section 38
penalty (up to LKR 10,000,000) is specifically for non-compliance with a
DIRECTIVE the Data Protection Authority has already issued under Section
35 — i.e. it bites on an organisation that was told to fix a gap and
didn't, not on the underlying security lapse itself. Both nuances are kept
in the "impact" text below rather than smoothed over, since an examiner
who reads the Act will ask.

BENCHMARK GROUNDING FOR THE THRESHOLDS BELOW: the 30% "high_click_rate"
and <10% "good_baseline" cutoffs are not arbitrary round numbers — they
track published industry benchmarks for simulated-phishing click rates,
specifically KnowBe4's 2025 Phishing By Industry Benchmarking Report,
which reports a global average baseline (untrained) "Phish-Prone
Percentage" of 33.1%, falling to 4.1% after 12 months of recurring
security-awareness training (KnowBe4, 2025,
https://www.knowbe4.com/press/knowbe4-report-reveals-security-training-reduces-global-phishing-click-rates-by-86-percent).
Cite this (or your own more recent benchmark) explicitly in the
dissertation wherever these thresholds are justified, rather than
presenting them as internally derived.

RISK MODEL SCOPE: everything in this module scores LIKELIHOOD — how
probable it is, based on observed behaviour, that a given employee or
department falls for a real attack. That is a VULNERABILITY/susceptibility
measure on its own, not "risk" in the ISO 27005 / NIST SP 800-30 sense,
which is likelihood combined with IMPACT (what's actually at stake if
this particular person is compromised). See
compute_employee_overall_risk() further below, which explicitly
layers a department-based impact weight on top of compute_employee_risk()'s
likelihood score to produce a genuine likelihood x impact risk figure —
kept as a separate function specifically so the adaptive-difficulty engine
(difficulty_for_tier()) can keep using the unweighted likelihood score
alone: how hard the NEXT simulation should be must depend only on how
easily this person is actually fooled, never on which department they
sit in.

BEHAVIOURAL PERSONALIZATION (adaptive-content engine, research
contribution): compute_persuasion_profile() and classify_click_speed()
already existed to populate the employee-profile page, but their output
was previously a dead end — shown to an admin, never fed back into the
next simulation's content. peak_click_period() (below) adds a third,
previously-uncomputed signal from the SAME interactions.occurred_at data
already recorded. admin.py's create_campaign() now assembles all three
(plus a department-wide persuasion trend) into a `behavior_profile` dict
and passes it into services/pretext_generator.py's generate_pretext(),
which folds it into the LLM prompt as an extra instruction block. This is
what distinguishes genuine per-employee history-informed personalization
from the difficulty tier alone, which only ever reflected an aggregate
risk SCORE, never which pretext worked, when, or how fast. As with the
difficulty tier, this is deliberately ignored for condition='generic'
(the fixed control baseline) and for the TOAD vector (a fixed template by
design) — see generate_pretext()'s docstring.
"""

# Each citation quotes the regulation's OWN operative sentence (see the
# sourcing note above) rather than this project's paraphrase of it, so a
# dashboard/report reader — or a viva examiner — can check it word-for-word
# against the Act. "note" flags the one honesty caveat specific to that
# citation (e.g. PDPA s.38's penalty being directive-non-compliance, not a
# direct per-breach fine) so it travels with the citation everywhere it's
# rendered, not just in this file's comments.

_GDPR_SECURITY_DUTY = {
    "jurisdiction": "GDPR (EU) 2016/679",
    "article": "Article 32(1) – Security of processing",
    "text": (
        "“the controller and the processor shall implement appropriate "
        "technical and organisational measures to ensure a level of "
        "security appropriate to the risk”"
    ),
}
_GDPR_INTEGRITY_PRINCIPLE = {
    "jurisdiction": "GDPR (EU) 2016/679",
    "article": "Article 5(1)(f) – Integrity and confidentiality",
    "text": (
        "personal data shall be “processed in a manner that ensures "
        "appropriate security of the personal data, including protection "
        "against unauthorised or unlawful processing… using appropriate "
        "technical or organisational measures”"
    ),
}
_GDPR_TESTING_DUTY = {
    "jurisdiction": "GDPR (EU) 2016/679",
    "article": "Article 32(1)(d) – Testing/evaluating measures",
    "text": (
        "“a process for regularly testing, assessing and evaluating "
        "the effectiveness of technical and organisational measures for "
        "ensuring the security of the processing”"
    ),
}
_GDPR_BREACH_NOTICE = {
    "jurisdiction": "GDPR (EU) 2016/679",
    "article": "Article 33(1) – Breach notification to the supervisory authority",
    "text": (
        "“the controller shall without undue delay and, where "
        "feasible, not later than 72 hours after having become aware of "
        "it, notify the personal data breach to the supervisory "
        "authority… unless the personal data breach is unlikely to "
        "result in a risk to the rights and freedoms of natural persons”"
    ),
}
_PDPA_SECURITY_DUTY = {
    "jurisdiction": "Sri Lanka PDPA, No. 9 of 2022",
    "article": "Section 10 – Integrity and confidentiality of personal data",
    "text": (
        "“Every controller shall ensure integrity and confidentiality "
        "of personal data that is being processed” using appropriate "
        "technical and organisational measures (the Act names encryption, "
        "pseudonymisation, anonymisation and access controls) to prevent "
        "unauthorised processing and accidental loss or damage"
    ),
}

RULES = [
    {
        "id": "high_click_rate",
        "condition": lambda m: m["click_rate"] >= 0.30,
        "severity": "high",
        "regulation": "GDPR Art. 5(1)(f)/32 · Sri Lanka PDPA s.10",
        "citations": [_GDPR_INTEGRITY_PRINCIPLE, _GDPR_SECURITY_DUTY, _PDPA_SECURITY_DUTY],
        "finding": (
            "Click-through rate of {click_rate:.0%} indicates staff are highly "
            "susceptible to social engineering, which is a technical/organisational "
            "control gap under the requirement to ensure a level of security "
            "appropriate to the risk."
        ),
        "impact": (
            "A click rate this high means the human-layer control both laws "
            "require is not effectively in place — this is the control gap a "
            "regulator looks at first, before any breach has even occurred, "
            "because every click here was one step away from the submission "
            "scenario below."
        ),
        "recommendation": (
            "Introduce mandatory, recurring security-awareness training for this "
            "department and consider technical controls such as external-sender "
            "email banners."
        ),
    },
    {
        "id": "high_download_rate",
        "condition": lambda m: m["download_rate"] >= 0.20,
        "severity": "high",
        "regulation": "GDPR Art. 32(1)(b) · Sri Lanka PDPA s.10",
        "citations": [_GDPR_SECURITY_DUTY, _PDPA_SECURITY_DUTY],
        "finding": (
            "{download_rate:.0%} of recipients downloaded the simulated attachment. "
            "In a real attack, this is the step that would actually deliver malware "
            "to an endpoint, regardless of whether a link was also clicked."
        ),
        "impact": (
            "A real malicious attachment opened here would compromise the "
            "“confidentiality, integrity, availability and resilience of "
            "processing systems” GDPR Art. 32(1)(b) requires be maintained — "
            "the same security-of-processing gap the PDPA's Section 10 names, "
            "and the same category of failure that triggers the breach "
            "consequences in the submission-rate finding below."
        ),
        "recommendation": (
            "Deploy or verify endpoint attachment scanning and restrict execution "
            "of macros/scripts from downloaded documents by default policy."
        ),
    },
    {
        "id": "high_submit_rate",
        "condition": lambda m: m["submit_rate"] >= 0.10,
        "severity": "critical",
        "regulation": "GDPR Art. 32/33 · Sri Lanka PDPA s.10/38",
        "citations": [_GDPR_SECURITY_DUTY, _GDPR_BREACH_NOTICE, _PDPA_SECURITY_DUTY],
        "finding": (
            "A submission rate of {submit_rate:.0%} means staff would hand real "
            "credentials straight to an attacker. If this had been a genuine "
            "attack, those credentials would most likely give the attacker "
            "unauthorised access to this organisation's network and the personal "
            "data it processes — exactly the outcome GDPR Art. 32 and PDPA s.10's "
            "security duty exist to prevent and exactly the event GDPR Art. 33 "
            "requires notifying to the supervisory authority within 72 hours."
        ),
        "impact": (
            "Organisational impact if this were real: under GDPR, a breach "
            "traced to inadequate technical/organisational security measures can "
            "draw an administrative fine of up to €20,000,000 or 4% of global "
            "annual turnover, whichever is higher (Art. 83(5)) — a ceiling the "
            "supervisory authority may impose after its own investigation, not an "
            "automatic consequence of this one finding. Under Sri Lanka's PDPA, "
            "the Data Protection Authority can first direct the organisation to "
            "remedy the gap (s.35); continuing not to comply with that directive "
            "then carries a penalty of up to LKR 10,000,000 per instance, doubled "
            "for a repeat failure (s.38). Beyond either fine: mandatory breach "
            "disclosure, a regulator inquiry and reputational damage with "
            "clients and the public."
        ),
        "recommendation": (
            "Prioritise phishing-resistant MFA (e.g. hardware keys/passkeys) so a "
            "submitted credential alone cannot grant access. For awareness "
            "specifically: give the affected employees a targeted retraining "
            "session that walks through exactly this simulation, increase their "
            "simulation frequency and difficulty for the next quarter and share "
            "the department's result (anonymised) at the next security briefing "
            "so the lapse becomes a shared learning moment rather than a private "
            "statistic."
        ),
    },
    {
        "id": "low_report_rate",
        "condition": lambda m: m["report_rate"] < 0.15,
        "severity": "medium",
        "regulation": "GDPR Art. 32(1)(d) · Sri Lanka PDPA s.10",
        "citations": [_GDPR_TESTING_DUTY, _PDPA_SECURITY_DUTY],
        "finding": (
            "Only {report_rate:.0%} of recipients reported the simulated email to "
            "IT/security, indicating weak incident-reporting culture, which limits "
            "how quickly a real campaign would be detected and contained."
        ),
        "impact": (
            "A slow-to-report workforce lengthens how long a real breach would "
            "run undetected, which works against both the regular-testing duty "
            "GDPR Art. 32(1)(d) sets out and against being able to meet GDPR "
            "Art. 33's “without undue delay” breach-notification clock once a "
            "real incident is eventually found."
        ),
        "recommendation": (
            "Add a one-click 'Report Phishing' button to the email client and "
            "publicly recognise employees who report simulations correctly."
        ),
    },
    {
        "id": "high_called_rate",
        "condition": lambda m: m.get("called_rate", 0) >= 0.10,
        "severity": "critical",
        "regulation": "GDPR Art. 32/33 · Sri Lanka PDPA s.10/38",
        "citations": [_GDPR_SECURITY_DUTY, _GDPR_BREACH_NOTICE, _PDPA_SECURITY_DUTY],
        "finding": (
            "{called_rate:.0%} of recipients called the fraudulent number in a "
            "callback-phishing (TOAD) simulation. This vector bypasses email link "
            "filtering entirely — in a real attack the attacker obtains data or "
            "remote access verbally, which carries the same breach-notification "
            "implications as a credential submission."
        ),
        "impact": (
            "The same exposure as the submission finding above applies here, "
            "verbally rather than through a form: potential GDPR Art. 83(5) fines "
            "up to €20,000,000 / 4% of global turnover and PDPA s.38 penalties "
            "of up to LKR 10,000,000 per instance for non-compliance with a "
            "remediation directive."
        ),
        "recommendation": (
            "Extend security-awareness training to cover voice/telephone social "
            "engineering specifically and establish a verified internal "
            "callback procedure for any unsolicited 'please call this number' "
            "request."
        ),
    },
    {
        "id": "good_baseline",
        "condition": lambda m: m["click_rate"] < 0.10 and m["submit_rate"] < 0.03 and m["download_rate"] < 0.05,
        "severity": "info",
        "regulation": "GDPR Art. 32 · Sri Lanka PDPA s.10",
        "citations": [_GDPR_SECURITY_DUTY, _PDPA_SECURITY_DUTY],
        "finding": (
            "Click rate ({click_rate:.0%}), submission rate ({submit_rate:.0%}) and "
            "attachment download rate ({download_rate:.0%}) are all within a low-risk "
            "range for this simulation round."
        ),
        "impact": None,
        "recommendation": (
            "Maintain current training cadence; consider increasing simulation "
            "difficulty (e.g. more targeted pretexts) to continue testing resilience."
        ),
    },
]


def compute_metrics(counts: dict) -> dict:
    """
    counts: {'total': int, 'open': int, 'click': int, 'submit': int,
             'download': int, 'report': int, 'called': int}
    Returns rates as floats between 0 and 1. Avoids division by zero.
    'called' (callback-phishing/TOAD simulation) is optional — callers that
    don't track it simply omit the key and called_rate comes back 0.
    """
    total = max(counts.get("total", 0), 1)
    return {
        "total": counts.get("total", 0),
        "open_rate": counts.get("open", 0) / total,
        "click_rate": counts.get("click", 0) / total,
        "submit_rate": counts.get("submit", 0) / total,
        "download_rate": counts.get("download", 0) / total,
        "report_rate": counts.get("report", 0) / total,
        "called_rate": counts.get("called", 0) / total,
    }


def get_compliance_findings(counts: dict) -> list:
    """
    Runs the metrics through the rules table and returns a list of
    triggered findings, each with severity, a short combined regulatory
    label ('regulation', for compact/summary views and the CSV export),
    the full list of citations behind that label ('citations' — each a
    {'jurisdiction', 'article', 'text'} dict, 'text' being the regulation's
    OWN quoted sentence, not this project's paraphrase — see the sourcing
    note at the top of this module), an 'impact' paragraph describing the
    organisational consequence/penalty exposure if the finding were real
    (None for the positive 'good_baseline' finding, which has none), a
    plain-language finding and a recommendation — ready to render
    directly on a dashboard (works identically whether `counts` is
    aggregated across a whole campaign or scoped to one employee).
    """
    metrics = compute_metrics(counts)
    findings = []
    for rule in RULES:
        if rule["condition"](metrics):
            findings.append({
                "id": rule["id"],
                "severity": rule["severity"],
                "regulation": rule["regulation"],
                "citations": rule.get("citations", []),
                "impact": rule["impact"].format(**metrics) if rule.get("impact") else None,
                "finding": rule["finding"].format(**metrics),
                "recommendation": rule["recommendation"],
            })
    return findings


# ---------- Per-employee risk scoring ----------
#
# A single employee's behaviour across every campaign they've been part of
# is reduced to one 0-100 risk score, with the exact arithmetic shown in
# the explanation text — this is the "transparent, not opaque" novelty
# claim applied at the individual level. Weights are deliberately simple
# and documented here so they can be defended/adjusted, not hidden.

RISK_WEIGHTS = {
    "click": 40,     # clicking a link is a meaningful lapse
    "download": 45,  # downloading a file is slightly worse than clicking — in a
                      # real attack this is the step that actually delivers malware
    "submit": 60,    # submitting data is the most serious behaviour measured
    "report": -25,   # reporting is the desired behaviour; it REDUCES risk
}

RISK_TIERS = [
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0, "Low"),
]


def _risk_tier(score: float) -> str:
    for threshold, label in RISK_TIERS:
        if score >= threshold:
            return label
    return "Low"


def compute_employee_risk(counts: dict) -> dict:
    """
    Computes this employee's behavioural LIKELIHOOD score (0-100) — how
    probable it is, based on their own observed history, that they would
    fall for a real attack. This is a vulnerability/susceptibility measure
    on its own; see compute_employee_overall_risk() below for the
    likelihood x impact combination that produces an actual risk figure.
    The function name and return keys (score/tier/explanation) are kept
    exactly as the MVP shipped them so every existing caller — including
    the adaptive-difficulty engine, which must keep using this unweighted
    score, never an impact-weighted one — is unaffected.

    counts: {'total': int, 'click': int, 'download': int, 'submit': int, 'report': int}
    'total' here means the number of campaigns this employee has been
    part of (not number of emails sent org-wide).

    Returns a dict with the numeric score (0-100), a severity tier label,
    and a plain-language explanation that shows the arithmetic behind the
    number — the thing that makes this different from a black-box score.
    """
    metrics = compute_metrics(counts)
    raw_score = (
        metrics["click_rate"] * RISK_WEIGHTS["click"]
        + metrics["download_rate"] * RISK_WEIGHTS["download"]
        + metrics["submit_rate"] * RISK_WEIGHTS["submit"]
        + metrics["report_rate"] * RISK_WEIGHTS["report"]
    )
    score = max(0, min(100, round(raw_score)))
    tier = _risk_tier(score)

    total = counts.get("total", 0)
    if total == 0:
        explanation = "This employee has not yet been included in any campaign."
    else:
        explanation = (
            f"Across {total} simulation{'s' if total != 1 else ''}, this employee "
            f"clicked {counts.get('click', 0)} time(s) ({metrics['click_rate']:.0%}), "
            f"downloaded the attachment {counts.get('download', 0)} time(s) ({metrics['download_rate']:.0%}), "
            f"submitted data {counts.get('submit', 0)} time(s) ({metrics['submit_rate']:.0%}) "
            f"and reported {counts.get('report', 0)} time(s) ({metrics['report_rate']:.0%}). "
            f"This nets a behavioural likelihood score of {score} ({tier})."
        )

    return {
        "score": score,
        "tier": tier,
        "explanation": explanation,
    }


# ---------- Department impact weighting (likelihood x impact = risk) ----------
#
# compute_employee_risk() above measures LIKELIHOOD only: how often this
# person's own behaviour suggests they'd fall for a real attack. Two
# employees with an identical click/submit history do not carry identical
# organisational RISK if one sits in Finance (wire transfers, banking
# credentials, financial records) and the other has no access to sensitive
# systems — risk, per NIST SP 800-30 and ISO/IEC 27005, is likelihood
# combined with IMPACT (the consequence if that person's account or
# workstation is actually compromised).
#
# DEPARTMENT_IMPACT_WEIGHTS is a second rules table, deliberately kept
# separate and just as editable as RULES/RISK_WEIGHTS above — organisations
# should replace these example weights with their own asset/business-impact
# classification (see methodology: risk-model limitations). A department
# not listed here gets DEFAULT_IMPACT_WEIGHT (1.0x — no adjustment), so an
# org that hasn't customised this table still gets a sensible, unbiased
# result rather than a silently wrong one.
DEPARTMENT_IMPACT_WEIGHTS = {
    "finance": 1.4,     # wire transfers, banking access, financial records
    "it": 1.3,          # privileged/admin credentials, infrastructure access
    "executive": 1.4,   # high-value BEC target, broad authority
    "hr": 1.2,          # employee PII, payroll data
    "legal": 1.2,       # privileged/contractual data
}
DEFAULT_IMPACT_WEIGHT = 1.0
# Caps how much impact weighting alone can inflate a score, so a high
# multiplier on a department with almost no observed clicking still can't
# manufacture a "Critical" rating out of near-zero likelihood.
MAX_IMPACT_WEIGHT = 1.5


def impact_weight_for_department(department) -> float:
    """Case-insensitive lookup against DEPARTMENT_IMPACT_WEIGHTS; any
    unrecognised or missing department (None, '', a typo, a department an
    org hasn't classified yet) falls back to DEFAULT_IMPACT_WEIGHT rather
    than raising, so this is always safe to call."""
    if not department:
        return DEFAULT_IMPACT_WEIGHT
    weight = DEPARTMENT_IMPACT_WEIGHTS.get(department.strip().lower(), DEFAULT_IMPACT_WEIGHT)
    return min(weight, MAX_IMPACT_WEIGHT)


def compute_employee_overall_risk(likelihood: dict, department) -> dict:
    """
    Combines compute_employee_risk()'s LIKELIHOOD score with a department
    IMPACT weight to produce a final RISK score: risk = likelihood x
    impact — the standard decomposition in NIST SP 800-30 / ISO 27005,
    rather than treating raw behavioural likelihood as "risk" on its own.

    likelihood: the dict returned by compute_employee_risk() — never
    mutated or recomputed here, so the two scores can both be shown
    side by side (see templates/employee_detail.html).
    department: the employee's department string (or None); only used to
    look up the impact weight.

    Returns: score (0-100, capped), tier, explanation, plus
    likelihood_score/likelihood_tier and impact_weight so a caller can
    show the full decomposition rather than only the final number.
    """
    weight = impact_weight_for_department(department)
    score = max(0, min(100, round(likelihood["score"] * weight)))
    tier = _risk_tier(score)

    if likelihood["score"] == 0:
        explanation = likelihood["explanation"]
    else:
        explanation = (
            f"{likelihood['explanation']} Weighted by this employee's department "
            f"impact factor ({weight:.1f}× for "
            f"{department or 'an unclassified department'}), this is a final risk "
            f"score of {score} ({tier}) — likelihood × impact, not "
            f"susceptibility alone."
        )

    return {
        "score": score,
        "tier": tier,
        "explanation": explanation,
        "likelihood_score": likelihood["score"],
        "likelihood_tier": likelihood["tier"],
        "impact_weight": weight,
    }


# ---------- Adaptive difficulty engine ----------
#
# Maps an employee's CURRENT risk tier (from compute_employee_risk, based
# on their history BEFORE the new campaign) to the difficulty level the
# next pretext should be generated at. Centralised here so admin.py and
# any future caller agree on the same mapping.
#
# Rationale: an employee who is already High/Critical risk gets an easier
# ("reinforcement") exercise — repeatedly hitting a struggling employee
# with the most devious pretext available is not a constructive training
# design. An employee with a clean history gets a harder ("advanced")
# pretext, to keep testing genuinely vigilant staff. No history at all
# defaults to "standard".
_TIER_TO_DIFFICULTY = {
    "Critical": "reinforcement",
    "High": "reinforcement",
    "Medium": "standard",
    "Low": "advanced",
}


def difficulty_for_tier(tier: str) -> str:
    return _TIER_TO_DIFFICULTY.get(tier, "standard")


# ---------- Persuasion-principle susceptibility profiling ----------
#
# Aggregates, per Cialdini persuasion principle, how often an employee was
# EXPOSED to an email tagged with that principle vs. how often they fell
# for it (click, submit, download, or called) — producing a susceptibility
# breakdown rather than one flat risk number. This is what lets the
# dashboard say something like "this person is specifically vulnerable to
# urgency-framed pretexts" rather than just "this person is high risk".

def compute_persuasion_profile(rows: list) -> list:
    """
    rows: a list of dicts, one per campaign_email this employee received,
    each shaped like:
        {
            "persuasion_principle": str or None,
            "fell_for_it": bool,   # True if any of click/submit/download/called happened
        }
    (Rows with persuasion_principle = None — e.g. data predating this
    feature's migration — are skipped rather than silently miscounted
    under a fabricated label.)

    Returns a list of dicts, one per principle actually seen, sorted by
    fall-for-it rate descending (most-exploitable-for-this-person first):
        {"principle": str, "exposed": int, "fell_for_it": int, "rate": float}
    """
    totals = {}
    for row in rows:
        principle = row.get("persuasion_principle")
        if not principle:
            continue
        bucket = totals.setdefault(principle, {"exposed": 0, "fell_for_it": 0})
        bucket["exposed"] += 1
        if row.get("fell_for_it"):
            bucket["fell_for_it"] += 1

    profile = []
    for principle, bucket in totals.items():
        exposed = bucket["exposed"]
        rate = bucket["fell_for_it"] / exposed if exposed else 0
        profile.append({
            "principle": principle,
            "exposed": exposed,
            "fell_for_it": bucket["fell_for_it"],
            "rate": rate,
        })
    profile.sort(key=lambda p: p["rate"], reverse=True)
    return profile


# ---------- Click-timing behavioural signal ----------
#
# Classifies the time between the fake-login page loading and the
# recipient submitting the form. A near-instant submission suggests
# automatic/habitual processing rather than any deliberation (see e.g.
# Vishwanath et al., 2011, on habitual email processing as a predictor of
# phishing susceptibility) — a behavioural signal distinct from and
# complementary to, whether they fell for it at all.
DWELL_THRESHOLDS_MS = [
    (3000, "Impulsive (under 3s)"),
    (10000, "Quick (3-10s)"),
]
DWELL_DEFAULT_LABEL = "Deliberate (10s+)"


def classify_click_speed(dwell_ms):
    """
    dwell_ms: int milliseconds, or None (e.g. JS disabled client-side —
    distinguished from 0, a genuinely instant submission).
    Returns a human-readable label, or None if dwell_ms is None.
    """
    if dwell_ms is None:
        return None
    for threshold, label in DWELL_THRESHOLDS_MS:
        if dwell_ms < threshold:
            return label
    return DWELL_DEFAULT_LABEL


# ---------- Peak click-time signal (behavioural personalization) ----------
#
# A third behavioural signal, alongside the persuasion profile and
# click-speed classification above, computed from the same
# interactions.occurred_at timestamps already recorded for every 'click'
# event. Bucketed into broad parts of the working day rather than exact
# hours, since an individual employee's click history is small (often a
# handful of events) and exact-hour granularity would overfit noise.
_PEAK_PERIOD_BUCKETS = [
    (5, 12, "morning"),
    (12, 17, "afternoon"),
    (17, 21, "evening"),
]
_PEAK_PERIOD_DEFAULT = "late night / early hours"


def _period_for_hour(hour: int) -> str:
    for start, end, label in _PEAK_PERIOD_BUCKETS:
        if start <= hour < end:
            return label
    return _PEAK_PERIOD_DEFAULT


def peak_click_period(occurred_at_values: list) -> str:
    """
    occurred_at_values: a list of 'occurred_at' strings as stored by
    interactions (sqlite's datetime('now') format, UTC,
    "YYYY-MM-DD HH:MM:SS"), one per 'click' event this employee has
    generated across their history.

    Returns the most common part-of-day label ("morning", "afternoon",
    "evening", or "late night / early hours"), or None if no timestamps
    were given (e.g. a new employee with no click history yet). Ties are
    broken by whichever period's bucket is checked first (morning, then
    afternoon, then evening), which is an arbitrary but stable choice —
    not claimed to be statistically meaningful with very few data points.
    """
    if not occurred_at_values:
        return None
    counts = {}
    for value in occurred_at_values:
        try:
            hour = int(value[11:13])
        except (TypeError, ValueError, IndexError):
            continue
        period = _period_for_hour(hour)
        counts[period] = counts.get(period, 0) + 1
    if not counts:
        return None
    return max(counts.items(), key=lambda kv: kv[1])[0]
