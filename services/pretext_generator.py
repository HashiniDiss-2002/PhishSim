"""
pretext_generator.py
---------------------
Generates simulated phishing email content (subject + HTML body) using an
LLM, constrained to safe categories, then passes it through a moderation
filter before it can ever be used in a campaign.

LLM PROVIDER: Groq (https://console.groq.com), using Llama/GPT-OSS via
Groq's OpenAI-compatible chat completions endpoint. See the departures
table / limitations section for the provider history (Anthropic → Gemini
→ local Ollama → Groq).

DESIGN CHANGE (context selection): earlier versions had the client admin
manually choose a context snippet from a short curated list before
generating a campaign. This version removes that step entirely: the LLM
is given only the organization's name and the employee's department, and
is asked to draw on its own general knowledge of that organization and
organizations like it to choose a realistic, relevant pretext itself,
from within the same fixed set of allowed categories as before.

This is a deliberate departure worth stating plainly in the thesis
departures table:
  - Pro: removes a manual admin step; the system is closer to fully
    autonomous, which supports the "needs minimal manual effort" design
    goal and objective.
  - Con: the model's knowledge of any specific organization may be
    outdated, generic, or occasionally inaccurate — this is NOT a live
    web-search integration (that was considered and explicitly rejected
    for this build, given time constraints and the number of external
    dependencies already in play). The realism achieved here comes from
    the model's general training knowledge, not verified current facts.
    State this limitation honestly rather than implying live research.

Design notes for the thesis:
- Two conditions are supported: 'generic' (a static template, used as the
  control group in the evaluation study, and unaffected by this change —
  it never used context in the first place) and 'personalized' (LLM-
  generated, the treatment group / novel contribution).
- Realism matters methodologically, not just cosmetically: if the email
  visibly announces itself as a test, click/submit rates measure nothing
  real, and the whole evaluation study in Chapter 3 becomes meaningless.
  The prompt below is written to produce output indistinguishable from a
  genuine internal email; the disclosure only happens AFTER a click, on
  the separate landing/fake-login page — never in the email itself.
- If GROQ_API_KEY is not set, the module runs in MOCK MODE and returns
  a clearly-labelled placeholder (visibly marked "[MOCK]") so the rest of
  the app can be built, run, and demoed offline before you wire up a real
  API key.
"""

import os
import re
import json
import time
import hashlib

import requests

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "openai/gpt-oss-120b"

# Cialdini's six principles of persuasion/influence (Cialdini, 1984/2006) —
# the fixed vocabulary every generated email is tagged with, driving the
# per-employee susceptibility profile in services/compliance_mapper.py.
PERSUASION_PRINCIPLES = [
    "authority", "urgency", "social_proof", "scarcity", "liking", "reciprocity",
]

# Difficulty tiers for the adaptive-difficulty engine (see admin.py:
# create_campaign(), which maps an employee's current risk tier to one of
# these before generation). 'standard' is the default/fallback used
# whenever an employee has no simulation history yet.
DIFFICULTY_LEVELS = ["reinforcement", "standard", "advanced"]

_DIFFICULTY_PROMPT_BLOCKS = {
    "reinforcement": """
DIFFICULTY: REINFORCEMENT (this recipient has recently shown HIGH/CRITICAL
risk — they have clicked, submitted, or downloaded in recent simulations).
Keep the cues a little clearer than usual so the exercise is still a
constructive, confidence-building learning moment rather than a second
"gotcha": mild urgency is fine, and the pretext should still be realistic,
but avoid the most subtle, hard-to-spot techniques for this recipient.""",
    "standard": """
DIFFICULTY: STANDARD (no strong risk signal yet, or a Medium-risk
recipient). Write a normal, realistic simulation at the usual level of
subtlety described above — no extra easing, no extra difficulty.""",
    "advanced": """
DIFFICULTY: ADVANCED (this recipient has recently shown consistently LOW
risk / vigilant behaviour in past simulations). Make the pretext more
subtle and realistic than the baseline: rely on quieter, more
plausible business detail and a more convincing sender persona, rather
than on any dramatic urgency — the goal is to responsibly test whether
a genuinely careful employee can still be caught by a well-crafted,
low-signal attempt.""",
}

# Categories the generator is allowed to use. Keeping this explicit and
# small is itself part of the safety design: the LLM is never asked to
# invent an arbitrary pretext, only to write copy within one of these —
# it now also CHOOSES which one fits, rather than being told via an
# admin-supplied context string.
ALLOWED_CATEGORIES = [
    "IT policy update (e.g. password reset, VPN change)",
    "internal company event or announcement",
    "industry news relevant to the company's sector",
    "software/tool update notification",
]

# A few real-world-style subject lines, given to the LLM purely as style
# anchors — not to be copied verbatim, just to calibrate tone away from
# cliché "URGENT!!! verify now!!!" phishing language toward the kind of
# unremarkable subject line that gets opened without a second thought.
SUBJECT_STYLE_EXAMPLES = [
    "VPN client update required before Friday",
    "Reminder: Q3 expense submissions due this week",
    "Updated remote-access policy — please review",
    "Action needed: confirm your details for payroll",
    "Scheduled maintenance window this weekend",
]

# Keyword-based moderation filter (defence-in-depth alongside prompt
# constraints). Any generated content matching these categories is
# rejected outright — this protects against the LLM surfacing or
# fabricating sensitive personal content.
BLOCKED_TOPICS = [
    "death", "died", "funeral", "bereavement", "illness", "diagnosis",
    "divorce", "pregnan", "layoff", "redundan", "fired", "salary",
    "medical", "hospital", "therapy", "mental health", "financial hardship",
]

# The 'generic' condition is the evaluation study's CONTROL baseline (see
# methodology 3.3.1). It is intentionally NOT personalized or org-aware —
# that's the whole point of a control group — so it is unaffected by the
# context-selection change above.
GENERIC_TEMPLATE = {
    "subject": "Password policy update — action required",
    "html_body": """
    <div style="font-family:Arial,sans-serif;max-width:600px;color:#222;">
      <p>Hi {employee_name},</p>
      <p>As part of our ongoing security improvements, we're updating the
      password policy for all staff accounts. You'll need to confirm your
      current access details before the change takes effect next week.</p>
      <p><a href="{tracking_link}">Confirm your account details</a></p>
      <p>Thanks,<br>IT Support</p>
    </div>
    """,
    # Fixed tag for the control template: it leans on IT Support's
    # institutional authority ("as part of our ongoing security
    # improvements... you'll need to confirm") rather than peer pressure,
    # a deadline, or scarcity.
    "persuasion_principle": "authority",
}

# TOAD (Telephone-Oriented Attack Delivery) / callback-phishing template.
# Unlike every other template in this file, the email itself carries NO
# tracking hyperlink to a fake login page — only a fictional phone number,
# exactly matching the real-world technique this simulates (the victim is
# asked to call in, not click a link, which routes around email/URL
# filters entirely). Ethical safeguard: the number always falls in the
# NANP-reserved 555-01XX drama/fiction range (555-0100-555-0199), which is
# permanently non-routable/non-assignable in the real telephone network
# (see https://en.wikipedia.org/wiki/555_(telephone_number)) — it can
# never reach a real person or premium-rate number.
#
# Technical compromise, documented honestly for the thesis: this app has
# no telephony integration, so an actual phone call can't be detected
# server-side. The "called" interaction is instead logged the moment the
# recipient taps/clicks the phone number in the email (wired to a
# tracking redirect that then hands off to a tel: URI — see
# tracking.py: track_call()). This slightly understates a real TOAD
# attack's stealth (a genuinely hyperlink-free email can't be clicked at
# all), but is the closest behavioural proxy available without a live
# phone system, and is called out as a limitation rather than silently
# assumed to be equivalent.
TOAD_SUBJECT_TEMPLATE = "Action needed: unpaid invoice #{invoice_id} — please call to resolve"
TOAD_HTML_TEMPLATE = """
<div style="font-family:Arial,sans-serif;max-width:600px;color:#222;">
  <p>Hi {employee_name},</p>
  <p>Our records show invoice <strong>#{invoice_id}</strong> from one of our
  suppliers has an outstanding payment issue that needs to be resolved
  before it affects your department's account.</p>
  <p>Please call our accounts support line to verify your details and
  resolve this:</p>
  <p style="font-size:18px;"><a href="{call_link}">&#9742; {phone_display}</a></p>
  <p>Please have your employee ID ready when you call.</p>
  <p>Thanks,<br>Accounts Support</p>
</div>
"""


def _toad_phone_number(org_name: str) -> str:
    """
    Deterministic, per-organization fictional phone number in the
    permanently-reserved, non-routable NANP 555-01XX range — same
    "deterministic from org name, never a real address/number" ethical
    pattern as services/domain_spoofing.py.
    """
    digest = hashlib.sha256(org_name.strip().lower().encode("utf-8")).hexdigest()
    last_two = int(digest[:4], 16) % 100  # 00-99
    return f"+1-555-01{last_two:02d}"


def generate_toad_pretext(employee_name: str, department: str, org_name: str) -> dict:
    """
    Fixed (non-LLM) callback-phishing / TOAD pretext — deliberately NOT
    generated per-call by the LLM, since the whole point of this vector is
    the absence of a link/attachment, not creative email copy. Returns the
    same shape as generate_pretext() so admin.py can treat it uniformly,
    plus a 'phone_display' key tracking.py/templates use to render the
    number consistently with what track_call() redirects to.
    """
    phone_display = _toad_phone_number(org_name)
    digest = hashlib.sha256((org_name + employee_name).encode("utf-8")).hexdigest()
    invoice_id = digest[:8].upper()
    result = {
        "subject": TOAD_SUBJECT_TEMPLATE.format(invoice_id=invoice_id),
        "html_body": TOAD_HTML_TEMPLATE.format(
            employee_name=employee_name,
            invoice_id=invoice_id,
            call_link="{call_link}",
            phone_display=phone_display,
        ),
        "attachment_filename": None,
        "persuasion_principle": "urgency",
        "phone_display": phone_display,
    }
    _moderate(result["subject"] + " " + result["html_body"])
    return result



class ModerationError(Exception):
    pass


def _moderate(text: str):
    lowered = text.lower()
    for topic in BLOCKED_TOPICS:
        if topic in lowered:
            raise ModerationError(
                f"Generated content blocked: contains disallowed topic '{topic}'."
            )


def _build_behavior_block(behavior_profile: dict, department: str) -> str:
    """
    Turns the behavior_profile dict assembled by admin.py's
    create_campaign() (see compliance_mapper.py's module docstring —
    "BEHAVIOURAL PERSONALIZATION") into an extra prompt instruction block.
    Returns "" if there's nothing to say yet (e.g. a new employee with no
    history and no department trend either) — this is the research-facing
    hook that actually makes the 'personalized' condition personalized on
    more than department + a difficulty tier.
    """
    if not behavior_profile:
        return ""

    lines = []
    if behavior_profile.get("top_principle"):
        lines.append(
            f"- In past simulations, this specific recipient acted on "
            f"{behavior_profile['top_principle']}-framed emails "
            f"{behavior_profile['top_principle_rate']:.0%} of the times they received one — "
            f"the single persuasion principle they have personally been most receptive to."
        )
    if behavior_profile.get("peak_click_period"):
        lines.append(
            f"- This recipient has historically been most likely to click during the "
            f"{behavior_profile['peak_click_period']}."
        )
    if behavior_profile.get("click_speed_label"):
        lines.append(
            f"- When they have submitted data before, their response speed was classified as "
            f"\"{behavior_profile['click_speed_label']}\"."
        )
    if behavior_profile.get("dept_top_principle"):
        lines.append(
            f"- More broadly, the {department} department as a whole has shown the highest "
            f"fell-for-it rate on {behavior_profile['dept_top_principle']}-framed emails "
            f"({behavior_profile['dept_top_principle_rate']:.0%})."
        )
    if not lines:
        return ""

    return (
        "\n\nBEHAVIOURAL PERSONALIZATION (adaptive engine — real signal from this "
        "recipient's own and their department's simulation history, not demographic "
        "profiling or any invented personal detail):\n"
        + "\n".join(lines)
        + "\n\nUse this ONLY to help choose which persuasion principle to lean into and how "
        "urgent or subtle the framing should be. Never mention any of this analysis, any "
        "statistic, or the fact that past behaviour was reviewed, anywhere in the email itself."
    )


def _build_prompt(employee_name: str, department: str, org_name: str,
                   real_world_reference: str = None,
                   difficulty: str = "standard",
                   behavior_profile: dict = None) -> str:
    categories = "\n".join(f"- {c}" for c in ALLOWED_CATEGORIES)
    style_examples = "\n".join(f'- "{s}"' for s in SUBJECT_STYLE_EXAMPLES)
    principles = ", ".join(PERSUASION_PRINCIPLES)
    difficulty_block = _DIFFICULTY_PROMPT_BLOCKS.get(
        difficulty, _DIFFICULTY_PROMPT_BLOCKS["standard"]
    )
    behavior_block = _build_behavior_block(behavior_profile, department)

    # Stage 2 ("threat-intelligence-informed") addition: a human researcher
    # has manually read a real, publicly reported phishing campaign write-up
    # and summarised its STRUCTURAL features only (pretext category,
    # urgency/authority framing, delivery vector) — never any real domain,
    # URL, hash, or literal copy from the source. This block, when present,
    # asks the model to let those structural patterns inform an ORIGINAL
    # regenerated simulation, rather than reusing anything from the real
    # campaign. This is the "defanging" principle from methodology 3.2.4:
    # the real campaign is a source of structural metadata only, never
    # content to copy or adapt directly.
    reference_block = ""
    if real_world_reference:
        reference_block = f"""

ADDITIONAL CONTEXT (Stage 2 — real-world-informed simulation):
A researcher has reviewed a real, publicly reported phishing campaign and
summarised its STRUCTURAL characteristics below (not its literal content —
no real domains, links, or copied text are included here, only the pattern
of the attack). Let these structural patterns inform your choice of
pretext category, framing, and delivery vector for a WHOLLY ORIGINAL email
you write yourself — do not attempt to reproduce, quote, or closely imitate
the real campaign's actual wording; use it only as inspiration for realistic
structure:

{real_world_reference.strip()}

Stay within the allowed pretext categories listed below even if the real
campaign's pretext doesn't map neatly onto one — pick the closest fit."""

    return f"""You are helping build an authorised, consented security-awareness
training simulation for the organization "{org_name}". You are writing a
SIMULATED phishing email used only to train employees to recognise real
phishing attempts. This is not sent to anyone outside an approved training
exercise.

Write a short, realistic internal-style email for a training simulation,
addressed to {employee_name} in the {department} department.

You know general public information about "{org_name}" and about
organizations of this type (its likely industry, scale, and the kind of
internal communications such an organization would realistically send).
Use that general knowledge, together with the recipient's department, to
choose the MOST PLAUSIBLE pretext yourself — do not ask for more
information, decide it yourself. The email MUST use one of these pretext
categories only:
{categories}

REALISM IS CRITICAL. The entire point of this exercise is to measure
genuine employee behaviour, which only works if the email is indistinguishable
from a real internal email. Follow these rules strictly:
- Write in the calm, understated tone of routine internal business email —
  NOT dramatic, NOT alarming, NOT written like a stereotypical scam.
- Do NOT use hallmark phishing clichés: no ALL CAPS, no excessive
  exclamation points, no "your account will be suspended/deleted/locked",
  no "verify immediately or else", no "dear valued customer", no generic
  unaddressed greetings.
- Mild, believable urgency is fine (e.g. a deadline a few days out) —
  manufactured panic is not.
- The call to action should read like a normal, boring internal instruction
  (e.g. "please confirm your details" / "review the update here"), not an
  aggressive demand to click.
- Sign off with a plausible internal sender — a first name and a generic
  role (e.g. "Priya, IT Support" or "The HR Team") rather than an unsigned
  or overly formal "Security Department".
- For calibration only (do not copy these verbatim, write an original
  subject line in a similar register):
{style_examples}
- CRITICAL: the email itself must NEVER mention that it is a test,
  simulation, drill, training exercise, or phishing example, anywhere in
  the subject or body. The disclosure happens separately, only after
  someone clicks, on a page outside this email. If the recipient can tell
  from the email content alone that it isn't real, the simulation has
  failed at its one job.
- Do NOT reference any personal, medical, financial, or family information
  about the individual.
- Do NOT state or imply any specific current fact about "{org_name}" that
  you are not confident is accurate (e.g. a named system, a named
  executive, a specific recent event) — if unsure, keep the pretext
  generic to the category and the organization's general type rather than
  inventing a specific detail that could be wrong.
{reference_block}
{difficulty_block}
{behavior_block}

Separately, name the SINGLE persuasion principle (from the psychology of
influence) that your email's framing relies on MOST, choosing exactly one
of: {principles}. This is for research classification only — it must never
be mentioned anywhere in the email itself.

Some pretexts realistically come with an attached document (e.g. a policy
update PDF, a meeting agenda, software release notes) and some do not
(e.g. a software update notification usually has no attachment). Decide
for yourself whether THIS pretext would realistically include one. If
yes, invent a short, plausible filename for it (e.g. "Policy_Update.pdf",
"Q3_Agenda.pdf"). If no, this should be null.

Output ONLY valid JSON with exactly four keys: "subject", "html_body",
"attachment_filename", and "persuasion_principle".
- html_body should be simple HTML (a few short paragraphs, a plausible sign-off,
  and one link placeholder written exactly as {{tracking_link}}). Do NOT
  reference the attachment inside html_body yourself — if attachment_filename
  is set, a visual attachment element will be added to the email automatically
  after you respond, so just write the body as if that will be present.
- attachment_filename: a short plausible filename as described above, or null.
- persuasion_principle: exactly one of {principles}, as described above.

Respond with JSON only, no other text, no markdown code fences."""


LLM_MAX_RETRIES = int(os.environ.get("LLM_MAX_RETRIES", "5"))

# Base backoff for a 429 (rate-limited) response, in seconds. Doubled each
# attempt (1, 2, 4, 8, 16 s by default for 5 attempts) — exponential
# backoff rather than the earlier fixed 2s/4s wait, because Groq's free
# tier limits reset per-minute: a short, fixed wait was long enough to
# dodge a single slow request but not a sustained burst (e.g. generating
# pretexts for many employees back-to-back in create_campaign()'s loop),
# which is exactly the failure this project hit in practice — see the
# departures/implementation-issues table.
LLM_RETRY_BASE_SECONDS = float(os.environ.get("LLM_RETRY_BASE_SECONDS", "1"))


def _call_llm(prompt: str) -> dict:
    api_key = os.environ.get("GROQ_API_KEY")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        # GPT-OSS is a reasoning model: it spends tokens "thinking" before
        # producing the final answer, and those hidden reasoning tokens are
        # drawn from the SAME max_tokens budget even when reasoning_format
        # is "hidden" — 2000 gives enough headroom for both.
        "max_tokens": 2000,
        "response_format": {"type": "json_object"},  # Groq enforces valid JSON output
        # GPT-OSS models on Groq support a reasoning_format setting; leaving it
        # at its default can conflict with JSON mode and trigger a 400 error
        # (documented Groq behaviour). "hidden" avoids that conflict and keeps
        # only the final answer, which is all this app needs.
        "reasoning_format": "hidden",
    }

    last_error = None
    for attempt in range(LLM_MAX_RETRIES):
        try:
            resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=30)
            if resp.status_code == 429:
                last_error = requests.exceptions.HTTPError("429 rate limited (retryable)", response=resp)
                if attempt < LLM_MAX_RETRIES - 1:
                    # Respect the server's own Retry-After header when it
                    # provides one (Groq sometimes does); otherwise fall
                    # back to exponential backoff.
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after is not None:
                        try:
                            wait_seconds = float(retry_after)
                        except ValueError:
                            wait_seconds = LLM_RETRY_BASE_SECONDS * (2 ** attempt)
                    else:
                        wait_seconds = LLM_RETRY_BASE_SECONDS * (2 ** attempt)
                    time.sleep(wait_seconds)
                    continue
                # All retries exhausted and still 429: raise with Groq's
                # actual response body attached, not just the generic
                # "429 Client Error" text plain raise_for_status() gives —
                # the body usually says WHICH limit was hit (requests/day,
                # requests/minute, or tokens/minute), which matters for
                # deciding whether a longer pacing delay would even help
                # or whether it's a hard daily cap that has to be waited out.
                try:
                    detail = resp.json()
                except ValueError:
                    detail = resp.text
                raise requests.exceptions.HTTPError(
                    f"429 rate limited after {LLM_MAX_RETRIES} attempts — Groq response: {detail}",
                    response=resp,
                )
            if resp.status_code >= 400:
                try:
                    detail = resp.json()
                except ValueError:
                    detail = resp.text
                raise requests.exceptions.HTTPError(
                    f"{resp.status_code} error from Groq API: {detail}", response=resp
                )
            break
        except requests.exceptions.ReadTimeout as e:
            last_error = e
            if attempt < LLM_MAX_RETRIES - 1:
                continue
            raise

    data = resp.json()
    raw_text = data["choices"][0]["message"]["content"]

    cleaned = re.sub(r"^```json|```$", "", raw_text.strip(), flags=re.MULTILINE).strip()
    return json.loads(cleaned)


def generate_pretext(employee_name: str, department: str, org_name: str,
                      condition: str = "personalized",
                      real_world_reference: str = None,
                      difficulty: str = "standard",
                      behavior_profile: dict = None) -> dict:
    """
    Returns {"subject": str, "html_body": str, "attachment_filename": ...,
    "persuasion_principle": ...} for one employee.
    Raises ModerationError if generated content fails the safety filter.

    NOTE: no longer takes a `context` parameter — the LLM now chooses the
    pretext itself for the 'personalized' condition. 'generic' is
    unaffected, as it never used context.

    real_world_reference (optional, Stage 2): a short, human-written
    summary of a real, publicly reported phishing campaign's STRUCTURAL
    features (pretext category, urgency/authority framing, delivery
    vector) — never the real campaign's literal content, domains, or
    links. When provided, it's folded into the prompt so the model's
    choice of pretext/framing/vector is informed by a real-world pattern,
    while the output remains a wholly original, regenerated simulation —
    see methodology 3.2.4 ("defanging"). Ignored for condition='generic',
    which is the fixed control-group baseline and was never context-aware.

    difficulty (adaptive-difficulty engine, novelty feature): one of
    DIFFICULTY_LEVELS ('reinforcement' | 'standard' | 'advanced'), chosen
    by the caller (admin.py: create_campaign()) from the recipient's own
    recent risk tier. Folded into the LLM prompt as an extra instruction
    block; ignored for condition='generic', which is a fixed template at
    one fixed difficulty by design.

    behavior_profile (adaptive-CONTENT engine, novelty feature): optional
    dict assembled by admin.py's create_campaign() — see
    compliance_mapper.py's module docstring section "BEHAVIOURAL
    PERSONALIZATION" for exactly how it's built and why. Shape:
        {"top_principle": str or None, "top_principle_rate": float or None,
         "peak_click_period": str or None, "click_speed_label": str or None,
         "dept_top_principle": str or None, "dept_top_principle_rate": float or None}
    Folded into the LLM prompt as a further extra instruction block (see
    _build_behavior_block()) so the model can lean into the specific
    persuasion principle, timing, and urgency level this recipient (and
    their department) has actually responded to before — this is what
    makes the 'personalized' condition personalized on more than just
    department name and a coarse difficulty tier. None/missing fields are
    simply omitted from the prompt rather than guessed at. Ignored for
    condition='generic' (fixed control template, same as difficulty).
    """
    if condition == "generic":
        return {
            "subject": GENERIC_TEMPLATE["subject"],
            "html_body": GENERIC_TEMPLATE["html_body"].format(
                employee_name=employee_name, tracking_link="{tracking_link}"
            ),
            # The generic/control template never has an attachment — it's a
            # fixed baseline, not something the LLM decides on.
            "attachment_filename": None,
            "persuasion_principle": GENERIC_TEMPLATE["persuasion_principle"],
        }

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        # MOCK MODE: this [MOCK] label is intentional and should stay obvious —
        # it exists so placeholder test output is never mistaken for the real
        # thing. If your emails look "obviously fake," this is very likely why:
        # set a real GROQ_API_KEY to get realistic, non-mock output.
        result = {
            "subject": f"[MOCK] IT Update relevant to {department}",
            "html_body": (
                f"<div style='font-family:Arial'><p>Hi {employee_name},</p>"
                f"<p>(MOCK MODE — no GROQ_API_KEY set) This would be an LLM-generated "
                f"message, with the pretext chosen by the model itself based on "
                f"{org_name} and the {department} department. Difficulty tier "
                f"requested: {difficulty}.</p>"
                f"<p><a href='{{tracking_link}}'>View update</a></p></div>"
            ),
            # Included here (rather than null) so mock mode still exercises
            # the full attachment-tracking pipeline during offline testing.
            "attachment_filename": "Policy_Update.pdf",
            # Fixed in mock mode for determinism (no LLM call to classify).
            "persuasion_principle": "authority",
        }
        if real_world_reference:
            result["html_body"] = result["html_body"].replace(
                "</div>",
                "<p style='color:#999;font-size:11px;'>[MOCK] Stage 2 reference was supplied "
                "but is only actually used by the real LLM call, not mock mode.</p></div>",
            )
        if behavior_profile:
            # Surfaced here too (not just difficulty) so the wiring can be
            # exercised and demoed offline, without a GROQ_API_KEY — see the
            # difficulty tier's own mock-mode note above for the same reasoning.
            summary_bits = []
            if behavior_profile.get("top_principle"):
                summary_bits.append(
                    f"top principle: {behavior_profile['top_principle']} "
                    f"({behavior_profile['top_principle_rate']:.0%})"
                )
            if behavior_profile.get("peak_click_period"):
                summary_bits.append(f"peak click time: {behavior_profile['peak_click_period']}")
            if behavior_profile.get("click_speed_label"):
                summary_bits.append(f"click speed: {behavior_profile['click_speed_label']}")
            if behavior_profile.get("dept_top_principle"):
                summary_bits.append(
                    f"dept trend: {behavior_profile['dept_top_principle']} "
                    f"({behavior_profile['dept_top_principle_rate']:.0%})"
                )
            if summary_bits:
                result["html_body"] = result["html_body"].replace(
                    "</div>",
                    "<p style='color:#999;font-size:11px;'>[MOCK] behavior_profile received "
                    "but only actually used by the real LLM call, not mock mode. "
                    + "; ".join(summary_bits) + ".</p></div>",
                )
    else:
        prompt = _build_prompt(employee_name, department, org_name,
                                real_world_reference, difficulty, behavior_profile)
        result = _call_llm(prompt)
        # Defensive default: older prompt versions or an unexpected model
        # response might omit this key entirely — treat missing as "no
        # attachment" rather than raising a KeyError later.
        result.setdefault("attachment_filename", None)
        # Same defensive handling for the new key: fall back to "authority"
        # if missing, or if the model returned something outside the fixed
        # vocabulary (keeps compliance_mapper.py's profiling safe from
        # unexpected values).
        principle = result.get("persuasion_principle")
        if principle not in PERSUASION_PRINCIPLES:
            principle = "authority"
        result["persuasion_principle"] = principle

    _moderate(result["subject"] + " " + result["html_body"])
    return result
