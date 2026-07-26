# Paper outline — Output-Inference-Resistant Aggregation

## Working title (options)

- **"Output-Inference-Resistant Aggregation: Membership-Private Multi-Party
  Analytics under Auxiliary-Information Adversaries"** (formal)
- **"When Aggregates Leak: Formalizing Membership Privacy for Regulatory
  Multi-Party Analytics"** (attention-grabbing)
- **"OIRA: A Unifying Framework for Output-Inference-Resistant
  Aggregation"** (short, framework-y)

Working name in this repo: **OIRA**.

## One-paragraph elevator pitch

Multi-party private set intersection with payload aggregation (MPSI-CS,
MPSU-Sum, PJC-with-cardinality) has become the standard building block
for cross-institution regulatory analytics — banks jointly compute risk
statistics on companies they share, regulators receive the aggregate.
Existing security definitions guarantee input privacy and, for
cardinality-only variants, that the specific IDs in the intersection
stay hidden. However, **when the aggregate output is fine-grained**
(per-company scores, per-industry sub-aggregates, high-precision
ratios), a polynomial-time adversary with access to an auxiliary
information source (public financial disclosures, credit-rating
databases) can invert the aggregate to recover intersection
membership. We formalize this failure mode as a violation of
*Output-Inference-Resistant Aggregation* (OIRA), a new security notion
parameterized by adversary auxiliary budget and output granularity. We
prove an impossibility theorem, a matching lower bound, and construct
a protocol realizing OIRA at aggregate granularity via
MPSI-CS + differential privacy + k-anonymity gating. We introduce a
novel primitive, **Bucketed OIRA (BOIRA)**, that computes B-bin
histograms at O(B log B) communication rather than the naive O(B²) of
running MPSI-CS B times. We validate the framework in a live
deployment with the Monetary Authority of Singapore's supervisory
technology unit.

## Full section plan (target: 28 pages, LNCS format)

### §1. Introduction (2 pp)

- Motivating anecdote: MAS wants sector-wide leverage statistics across
  N banks × M companies without either side learning distinctive per-
  company values.
- The failure of "obvious" designs: reveal-per-company MPSI leaks
  membership through payload distinctiveness.
- Our contributions (bullet list of 4).
- Roadmap.

### §2. Background & related work (2 pp)

- MPSI family: KMPRT, Chandran, MPSO (Dong CCS'25)
- MPSI-CA + PSI-Sum: Miao CRYPTO'20, Falzon USENIX'25 (which
  identifies but does not formalize the leak)
- Differential privacy (Dwork 2006), DP + MPC composition (Cheu et al.)
- Membership inference in ML (Shokri 2017)
- What each of these captures / fails to capture. Table.

### §3. Model & threat model (3 pp)

- Real-world scenario: N parties, 1 aggregator (SP).
- Semi-honest adversary model.
- **Auxiliary-information oracle 𝒟**: adversary makes q queries to a
  public database of `(id, attribute-vector)` pairs.
- Concrete instantiation: SGX financial-disclosure database (public
  filings), credit-rating databases (Moody's/S&P), IMDA business
  registrar. Formalize what the auxiliary database looks like.
- Universe 𝒰 of possible IDs; each id has a public feature vector
  φ(id) ∈ ℝ^d.
- The vulnerability score s(id) = f(bank₁(id), ..., bank_N(id)) is a
  deterministic function of secret inputs, possibly correlated with
  φ(id) (this correlation is what enables the attack).

### §4. Definitions (2 pp)

- Ideal functionality **F_OIRA**(g, k, ε): parameterized by output
  granularity g, cardinality threshold k, DP noise ε.
- Real protocol Π with adversary A.
- Simulator-based security def.
- **OIRA advantage**: adv(A) := |Pr[real] − Pr[ideal]| where the game
  is "guess whether id* was in the intersection".
- Π realizes F_OIRA if adv(A) ≤ negl(λ) for every polynomial A with
  auxiliary budget q ≤ poly(λ).

### §5. Impossibility theorem (3 pp)

- **Thm 5.1** (informal): For any protocol Π that outputs per-item
  scores at granularity g > (log|𝒰|)⁻¹, and any auxiliary database 𝒟
  with expressive feature vectors (formalized below), there exists a
  polynomial adversary A_D with OIRA advantage ≥ 1/poly(λ).
- Adversary construction: A_D queries 𝒟 for a small set of "landmark"
  IDs with known feature vectors, correlates the observed per-item
  score s(id) with predicted score ŝ(φ(id)) using a public model,
  and outputs the closest match.
- Reduction: if this attack failed, then the auxiliary database
  contains no information about the score function — a strong
  incompressibility assumption that fails empirically in the SG
  financial-disclosure setting.
- **Corollary 5.2:** any protocol releasing per-item output at
  granularity strictly better than |intersection|-th aggregation is not
  OIRA-secure under real-world auxiliary databases.

### §6. Positive construction (4 pp)

- Construction Π_OIRA: **MPSICS + k-threshold gate + DP-noise on cardinality + DP-noise on aggregate.**
- **Thm 6.1**: Π_OIRA realizes F_OIRA(g=|I|, k, ε) with adversary
  advantage bounded by
  ```
  adv(A) ≤ ε · q + 2⁻λ + q / |{ids with score-collision ≤ noise floor}|.
  ```
  All three terms controllable by k, ε, and DP-noise magnitude.
- **UC composition proof:** F_OIRA composes safely with downstream
  threshold-alerting, quantile-release, and audit protocols.
- Concrete parameter choice for MAS deployment: k=20 (≥20 companies
  per aggregate), ε=1.0 (moderate), q=10⁶ (attacker budget).

### §7. Lower bound (3 pp)

- **Thm 7.1** (informal): Any protocol realizing F_OIRA(g, k, ε) with
  advantage ≤ 2⁻λ requires Ω(N·k·λ) bits of online communication.
- Proof: information-theoretic argument on the amount of hidden
  membership indicator bits.
- Corollary: our Π_OIRA is optimal up to constant factors in
  communication.

### §8. Novel primitive: BOIRA — Bucketed OIRA (3 pp)

- Motivation: SP often wants histograms (Σ_bucket count), not scalars.
- Naive: B parallel MPSICS invocations = O(B²) communication.
- **Construction:** unary-encoding of bucket assignment + single MPSICS
  invocation over expanded state = O(B log B) communication.
- **Thm 8.1:** BOIRA realizes F_BOIRA(bucketing, k, ε) with same
  advantage bound as OIRA.
- Optimality vs. naive: constant-factor improvement for B ≤ 8, log(B)
  factor for B > 8.

### §9. Deployment case study — MAS supervisory technology (3 pp)

- Real trial: N = 3–5 domestic banks, M = 10³–10⁴ common commercial
  customers, running once per supervisory quarter.
- Threat model mapped to MAS TRM Guidelines / CSA CCoP 2.0 / PDPA
  Anonymisation Guide.
- Key management: HSM-backed Beaver-triple oracle, per-quarter session
  keys, T14-style long-term identities.
- Benchmarks: 3 hours wall-clock at N=3, |companies|=10⁴, |feature|=6
  ratios per company, over 1 Gbps LAN.
- Audit trail: T11-style transcript signatures, ex-post verifiable by
  MAS internal auditor.
- Lessons: what surprised the operator; regulatory review outcomes.

### §10. Discussion & open problems (1 pp)

- Malicious security path (corrected OKVS from ASIACRYPT'24)
- Multi-jurisdictional deployment (cross-border aggregation)
- Adaptive queries (SP releases multiple aggregates over overlapping
  sub-populations)
- Connection to federated learning: score function as a small model

### §11. Conclusion (1 pp)

## Venue analysis

| Venue | Cycle | Fit for this paper | Notes |
|---|---|---|---|
| **PoPETs / PETS** | Rolling deadlines, 4 cycles/year | **Strong (recommended #1)** | Privacy-first, welcomes DP + MPC combination; 25-page ceiling; recent papers on similar formalizations (Cheu, Wang) landed well. |
| **CCS** | May, mid-July | Strong (recommended #2) | Higher bar for novelty; the impossibility + lower bound + novel primitive combined would clear it. |
| **USENIX Security** | Feb, Jun, Oct | Strong for the deployment section | Case-study track fits the SG MAS trial well; can pair with the crypto paper. |
| **NDSS** | Apr | Medium | Similar bar to CCS; less DP-friendly historically. |
| **S&P (Oakland)** | May, Sep | Medium | Prefers attacks + strong theory; the impossibility fits, less so the deployment. |
| **CRYPTO / EUROCRYPT / ASIACRYPT** | Feb, Oct, May | Weak | Pure crypto venues; deployment section doesn't help there and the construction is too much of a reduction. |
| **IEEE TDSC / TIFS** | Rolling | Medium | Fits systems-and-crypto, longer format; consider as extended-version target after conference publication. |

**Recommended path: PoPETs first submission (target next open cycle).**
If accepted → extended journal version to IEEE TDSC. If rejected →
resubmit with revisions to CCS with the systems section beefed up.

## Related-work map (§2 skeleton)

| Prior work | What it does | What it misses (that OIRA addresses) |
|---|---|---|
| **Kissner-Song 2005** | Original private set operations via polynomial | No formal notion of aggregate output privacy against aux info |
| **KMPRT CCS'17** | Multi-party PSI | Reveals intersection to designated party — no membership hiding beyond that |
| **Miao CRYPTO'20** | Malicious PSI-Sum-CA | Aggregate is a scalar; no auxiliary-information adversary model |
| **Chandran CCS'21** | Linear MPSI variants | Same as Miao |
| **Dong CCS'25 (MPSO)** | Unified MPSI/MPSI-CA/MPSI-CS/MPSU | Full protocol, but security definition is standard MPSI-CA — silent on aux-info attacks |
| **Falzon USENIX'25** | *Learning from Functionality Outputs* | Empirically shows PJC outputs leak; **calls out the gap OIRA closes but does not formalize a definition or construct a defense** — this is our jumping-off point |
| **Dwork ICALP'06** | Original DP | DP as a standalone; not composed with cryptographic aggregation |
| **Cheu CRYPTO'19** | Distributed DP + MPC (shuffle model) | Related — but focuses on additive queries over per-item releases, not aggregate-over-intersection |
| **Shokri S&P'17** | Membership inference in ML | ML setting; not applied to MPC/PSI outputs |
| **Bonawitz CCS'17** | Secure aggregation for FL | Related aggregation primitive; no auxiliary-info analysis |

**Positioning:** OIRA is the natural successor to Falzon USENIX'25 — takes their empirical observation and turns it into a formal security notion + impossibility + construction + tight bound. That's the "novelty story" for the reviewers.

## Submission timeline (assuming target = PoPETs)

- Cycles: submission deadlines ~ May 31, Aug 31, Nov 30, Feb 28 (approximate; verify each year)
- Realistic timeline from today (2026-07-24, session date):
  - **T + 2 wks**: threat model + F_OIRA draft (theory doc 2, this session's output)
  - **T + 6 wks**: impossibility proof polished (theory doc 3 draft → co-author review → revision)
  - **T + 10 wks**: positive construction proof + UC composition
  - **T + 14 wks**: BOIRA primitive design + proof
  - **T + 18 wks**: MAS deployment field trial complete, benchmarks in hand
  - **T + 20 wks**: paper draft complete
  - **T + 22 wks**: internal review round
  - **T + 24 wks**: submission (aim for the Aug 31 cycle if starting now — realistically Nov 30)

## What each contribution needs (co-author skill mapping)

| Contribution | Who drives | Difficulty |
|---|---|---|
| §4 F_OIRA definition | You + me | Medium |
| §5 Impossibility | Formal-methods / crypto theory co-author | **Hard** |
| §6 Positive construction + UC proof | Crypto theory co-author | Medium-Hard |
| §7 Lower bound | Same theory co-author | Hard |
| §8 BOIRA novel primitive | Someone with garbled-circuit / bucketed-OT experience | **Very hard** |
| §9 Deployment case study | You + MAS engagement | Medium (writing), Easy (measurement) if trial runs |

**You should recruit:**
- One senior crypto co-author (for theorems and reviewer credibility) — someone with a PoPETs/CCS track record
- One systems/deployment co-author (for §9, ideally with MAS/IMDA/GovTech ties)
- Optionally a DP specialist (Cheu, Kifer's students) for the tight composition analysis in §6

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Falzon USENIX'25 or a concurrent paper scoops the formalization | Speed of submission; strengthen with lower bound and BOIRA which are clearly novel |
| Impossibility theorem doesn't actually hold (aux info not strong enough) | Weaken theorem statement to "under a specific hardness assumption on aux info predictors"; still publishable |
| MAS deployment doesn't finish in time | Fall back to synthetic financial data at same scale; still credible for a conference paper |
| BOIRA construction turns out to require exponential communication | Drop BOIRA to future work; core paper (contributions 1-3) is still strong |
| Reviewers demand malicious-security treatment | Add a subsection with the corrected OKVS integration path; may become §10 |
