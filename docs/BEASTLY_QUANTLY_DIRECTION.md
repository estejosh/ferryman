# Beastly: Quantly research direction

This is the implementation direction for Quantly work coordinated through
Ferryman. It is a research-system brief, not authorization to trade.

## Non-negotiable boundaries

- Quantly's application and runtime remain Rust-first and Rust-only. Do not
  rebuild or extend the runtime in Python.
- Original Quantly-owned code is licensed under UFL 1.1. Ferryman and upstream
  dependencies keep their own licenses; do not relabel third-party code.
- Quantly remains paper-only. Public, read-only data collection is allowed;
  exchange credentials, authenticated order submission, and fund movement are
  out of scope.
- Ferryman is the local-first, device-to-device communication and orchestration
  layer between Quantly, Beastly, and Grouchly. Do not add a cloud relay or put
  credentials, raw private research, or account data in the channel.

## The system Quantly should become

Replace the narrow `hypothesis -> paper trade` loop with this auditable lifecycle:

```text
idea
  -> point-in-time data integrity
  -> versioned experiment
  -> walk-forward and purged/embargoed validation
  -> paper execution
  -> performance and risk attribution
  -> adversarial challenge
  -> promote, revise, retire, or reject
```

Every transition must be reproducible from an experiment record containing the
strategy and genome version, dataset/content hashes, code revision, random seed,
feature timestamps, split definitions, cost and latency assumptions, parameters,
and resulting artifacts. Market and macro records must retain both `known_at`
and `effective_at`; an experiment may see only information known at that simulated
time. Revisions must remain visible rather than silently replacing history.

## Build the experiment and evolution core first

Do not add another signal family until the core below is usable end to end.

Implement an independent evolutionary strategy-search layer inspired by the
useful research-loop ideas in SETS, without porting SETS code:

- Maintain populations partitioned into species so one early winner cannot erase
  useful strategy diversity.
- Represent each candidate as a versioned genome with bounded genes and explicit
  decoding into a Strategy.
- Support seeded initialization, mutation, crossover, random immigrants, elitism,
  and species-aware survivor quotas.
- Keep a separately evaluated champion while retaining the full population. The
  champion is a benchmark, not a reason to collapse the search to one lineage.
- Use the same Strategy object and decision implementation in historical replay,
  walk-forward evaluation, synthetic-market simulation, and paper trading. Only
  the market-data/execution adapter changes.
- Make the entire run reproducible from its recorded seed and inputs.
- Resolve ambiguous intrabar paths adverse-first. If a bar could have hit both a
  favorable and unfavorable boundary and ordering is unknown, score the adverse
  outcome rather than selecting the profitable path.

Evolution proposes candidates; it does not waive research gates. Leakage,
unreproducible lineage, or a paper-only violation makes a candidate ineligible
regardless of performance.

## Fitness and promotion

Raw win rate is diagnostic only. Selection and promotion should use a
multi-objective fitness record emphasizing:

- net P&L after fees, spread, slippage, funding, borrow, market impact, and other
  modeled costs;
- robustness across walk-forward windows, regimes, venues, and cost/latency
  perturbations;
- drawdown, downside and tail risk, ruin exposure, and loss concentration;
- turnover and capacity/liquidity constraints;
- complexity and overfitting pressure;
- parameter stability and sensitivity to neighboring values; and
- incremental diversification and risk contribution to the strategy portfolio.

Use hard validity gates first, then preserve the Pareto trade-offs rather than
hiding them in raw win rate or a single optimistic score. Promotion requires
out-of-sample robustness, paper evidence, attribution, and an adversarial review.
Retirement uses the same recorded criteria when edge decays or portfolio value
becomes redundant.

## Existing research to retain and connect

The core must make these existing Quantly areas comparable rather than replacing
them:

- macro regime and liquidity/surprise analysis;
- technicals, including moving-average structure, momentum, and volatility;
- futures, perpetuals, options, basis, funding, margin, and other derivatives;
- prediction markets and Polymarket;
- staged complete-set arbitrage and inventory rotation;
- Bayesian and Monte Carlo fair-value estimation;
- fractional Kelly sizing with strict caps for model error;
- order-book-depth paper fills with spread, slippage, fees, and liquidity limits;
- point-in-time `known_at` / `effective_at` data and full experiment lineage;
- counterfactual analysis and failure postmortems;
- strategy-portfolio construction plus performance and risk attribution;
- synthetic-market and regime simulation; and
- independent replication of research papers and Internet strategy claims.

Internet performance claims are hypotheses, never evidence of transferable edge.
Replication must preserve provenance, use Quantly-owned implementations, and pass
the same validation and paper gates.

## Recommended implementation order

1. **Experiment/evolution core:** define Strategy, Genome, Experiment, dataset
   snapshot, split, fitness, lineage, promotion, challenge, and retirement records.
2. **Read-only real-data ingestion and persistence:** normalize append-only market,
   macro, and outcome records with point-in-time timestamps and content hashes.
3. **Population search and validation:** add species, mutation/crossover, immigrants,
   elitism, seeded replay, walk-forward/purged validation, perturbation tests,
   synthetic scenarios, and adverse-first ambiguity handling.
4. **Paper portfolio allocation:** allocate among validated candidates using
   diversification contribution, exposure and tail-risk budgets, then attribute
   every outcome back to strategy, regime, costs, and sizing.

Only after those four stages are working should Quantly expand its signal-family
inventory or consider any separately authorized live-execution design.

## Ferryman responsibilities

- **Quantly** publishes structured research requests, experiment summaries,
  paper results, and lineage references under `quantly.ferryman/v1`.
- **Beastly** builds and reviews the experiment/evolution core in the order above.
- **Grouchly** runs durable read-only collection and paper workloads and returns
  reproducible results; it does not receive live-trading authority.
- **Ferryman** carries signed coordination, acknowledgements, assignments, and
  concise results. Large datasets and private artifacts stay in their controlled
  local stores; channel messages carry hashes and local references, not secrets.
