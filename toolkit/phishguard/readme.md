# PhishGuard

A phishing-email detector that runs as a single Tampermonkey/Violentmonkey
userscript. Public corpora in, a logistic-regression model out, inference in
plain JS with no network calls.

Run the whole thing with `scripts/run_all.ps1`.

## Install

Drag `dist/phishguard.user.js` into Tampermonkey or Violentmonkey. It is
self-contained (~279 KB, model inlined), matches `mail.google.com`, and makes
no network requests — your mail never leaves the browser.

## The central design constraint

A userscript sees the **rendered DOM**, not the raw message. No `Received`
chain, no SPF/DKIM/DMARC, no `Return-Path`, and in Gmail no `Reply-To`.

Most published phishing-detection accuracy leans heavily on those headers. So
every feature here is restricted to what the DOM actually exposes, and both
training and inference go through the same `EmailView` shape:

```
{from_name, from_addr, reply_to, subject, text, links[{href,text}], has_password_input}
```

Training on anything richer would inflate offline numbers and collapse in the
browser.

## Results

6,898 messages after filtering: 3,226 phishing / 3,672 legitimate.

| model  | split        | AUC    | recall @0.5 | FPR @0.5 |
|--------|--------------|--------|-------------|----------|
| STRUCT | random       | 0.9705 | 0.897       | 0.058    |
| TEXT   | random       | 0.9995 | 0.988       | 0.011    |
| BOTH   | random       | 0.9975 | 0.979       | 0.014    |
| STRUCT | cross-corpus | 0.9502 | 0.794       | 0.050    |
| TEXT   | cross-corpus | 0.9921 | 0.650       | 0.003    |
| BOTH   | cross-corpus | 0.9807 | 0.815       | 0.010    |

**Read the cross-corpus row, not the random one.** Random split trains on
Nazario + phishing_pot together; both contain whole campaign families, so
near-relatives of every test message sit in training. Cross-corpus trains on
Nazario phish and tests on phishing_pot phish — disjoint collection methods and
years. That is the number that predicts behaviour on mail the model has never
seen the likes of.

Note how TEXT barely moves on AUC but its recall collapses from 0.988 to 0.650.
Shipped model is BOTH, with thresholds calibrated on out-of-fold predictions:

| band   | threshold | recall | FPR    |
|--------|-----------|--------|--------|
| warn   | 0.4239    | 0.987  | 0.0199 |
| danger | 0.8991    | 0.846  | 0.0030 |

Tuned by false-positive rate rather than at 0.5, because a banner that fires on
5% of real mail gets ignored within a week.

## Leakage found and removed

The first training run produced these as the strongest "phishing" tokens:

```
your, de, you, 2023, account, para, monkey, 2025, wallet, 2026, jose, sie, ...
```

Three separate leaks, all of which scored beautifully and meant nothing:

1. **`monkey`, `jose`** — the Nazario corpus is Jose Nazario's own inbox, so
   every phishing sample is addressed to `jose@monkey.org`. The model learned
   who collected the mail. Fixed by redacting collection artifacts in
   `parse_corpora.py`.
2. **`de, para, sie, voc, sua`** — the phishing is multilingual, SpamAssassin
   ham is all English, so "not English" became a perfect phishing signal. Fixed
   by requiring the same English-token threshold of both classes.
3. **`2023, 2025, 2026`** — phishing is 2019-2023, ham is 2002. Fixed by
   restricting the vocabulary to letters only.

A fourth was caught before training: ~23% of phishing_pot has been anonymized
down to no `From` header at all, while SpamAssassin ham nearly always has one.
"Sender missing => phishing" would have been a near-perfect offline feature and
worthless in a browser, where a sender is always displayed. Those messages are
dropped rather than featurized.

After the fixes the top tokens are actual phishing register: `your, please,
account, details, wallet, dear, kindly, payment, verify`.

## Train/serve parity

`features.py` and `features.js` are line-for-line mirrors, and
`scripts/parity_test.py` asserts they agree on 400 real messages:

```
compared 400 messages x 34 features
max abs feature diff: 8.882e-16
max abs probability diff: 3.331e-16
PARITY OK
```

Run it after touching either file. Two bugs it already caught:

- `log_text_len` differed because Python `len()` counts code points and JS
  `.length` counts UTF-16 units, so emoji counted double.
- `subject_caps_ratio` differed because Python `str.isalpha()` is
  Unicode-aware and JS `/[A-Za-z]/` is not.

Both are exactly the kind of silent skew that makes a model behave worse in the
browser than on the bench with no visible error.

## Known limitations

- **Legitimate marketing is the main false-positive source.** The three worst
  false positives are all from SpamAssassin's `hard_ham` (deliberately
  spammy-looking real mail): an HP promo, a HarperCollins author newsletter, a
  Cisco announcement. Bulk marketing and phishing share a structure — lots of
  links, tracking redirects, urgency, brand names — and the DOM alone does not
  separate them well.
- **The ham is 2002.** SpamAssassin's public corpus is the only sizeable free
  ham set. Real inbox mail from 2026 looks different. The best fix is your own
  mail: export a few hundred legitimate messages as `.eml`, drop them in
  `data/raw/user_ham/`, add a source line in `parse_corpora.py`, retrain. That
  will help more than any other change.
- **The text half is sensitive to how the body is extracted.** In the fixture,
  one message scored 0.981 from the corpus body and 0.093 from the flattened
  DOM body. Structural features are far more stable across rendering. If you
  want robustness over raw benchmark score, train STRUCT only.
- **`reply_to` and `has_password_input` are effectively always empty in
  Gmail** — it does not expose Reply-To in the DOM and it strips form inputs
  from rendered mail. Those features carry real weight in training and near-zero
  at inference. Worth removing if you only target Gmail.
- Only a Gmail adapter exists. `collectViews()` in the template is the single
  place to add Outlook/Proton.
  exclusion for `data/raw/` in Avast (Menu > Settings > Exceptions) and re-run
  `fetch_data.ps1`; 2024 and 2025 are the most current phishing available and
  are worth having.
