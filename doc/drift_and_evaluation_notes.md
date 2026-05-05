# Drift and Evaluation Notes

## Context

AegisLog uses unsupervised anomaly detection models on log-derived session features.
The current feature set is **v3-baseline-deviation**, which includes:

- core behavioral features (error ratios, bursts, rare hours),
- Apache-specific features (error vs notice, rare templates, rare paths),
- SSH-specific features (auth streaks, success-after-failure),
- identity baselines (per-IP and per-user average events per session),
- first-seen and rare-seen flags.

Models are trained on sample logs (LogHub SSH and Apache error logs) without labels, so evaluation is based on score distributions and manual inspection of top-ranked sessions rather than ground truth.

## Current Evaluation Method

For each log type (`ssh_auth`, `apache_error`):

1. Train a model (Isolation Forest) on representative logs:
   - `data/loghub/SSH.log`
   - `data/loghub/Apache.log`

2. Compare three model types on the same features:
   - Isolation Forest (`iforest`)
   - One-Class SVM (`ocsvm`)
   - Local Outlier Factor (`lof`)

3. For each model:
   - Fit on `NUMERIC_FEATURES` for all sessions.
   - Compute anomaly scores using a consistent convention (higher = more anomalous).
   - Summarize scores with:
     - min / max / mean
     - 95th percentile
     - 99th percentile (default anomaly threshold)
     - fraction of sessions above the 99th percentile

4. Inspect the top-ranked sessions (e.g., top 10–20) using:
   - `python -m aegislog.cli analyze ...` for SSH
   - `python -m aegislog.cli_apache ...` for Apache

This comparison is scripted via `aegislog.ml.compare_models` and produces JSON summaries under `experiments/`.

## Findings (initial)

_These should be updated as experiments are run._

- **Isolation Forest**
  - Produces smooth score distributions and stable 99th-percentile thresholds for both SSH and Apache.
  - Top sessions tend to correspond to intuitive anomalies (unusual hours, spikes in errors, rare templates).

- **One-Class SVM**
  - Can be more sensitive to feature scaling and kernel parameters.
  - On Apache, may flag a larger fraction of sessions near the threshold; requires parameter tuning if used as default.

- **Local Outlier Factor**
  - Works but can be less stable for very short sessions or small sample sizes.
  - Interpretation of scores is less straightforward; inversion and thresholding are more sensitive to distribution quirks.

For now, **Isolation Forest** remains the default `model_type`, with `ocsvm` and `lof` available as advanced options.

## Drift Considerations

Because models are unsupervised and trained on a fixed snapshot of logs:

- Real environments may have different distributions (new IP ranges, new users, new services).
- Identity-based features (first-seen, rare-seen, per-IP/user baselines) will naturally spike for new identities, which is desirable but may increase alert volume.
- Application changes (new endpoints, error patterns, deployment times) can shift feature distributions significantly.

To monitor for drift:

- Periodically re-run `aegislog.ml.compare_models` on fresh logs.
- Track how the 99th-percentile threshold and the fraction of sessions above it change over time.
- Watch for large shifts in:
  - mean anomaly score,
  - number of sessions flagged at the threshold,
  - composition of top-ranked sessions (e.g., dominated by new services or identities).

If substantial drift is observed:

- Retrain models on newer logs.
- Revisit the default `threshold_percentile` or introduce log-type–specific thresholds.
- Consider adding simple time-based drift checks (e.g., weekly comparison of score distributions).

## Future Evaluation Enhancements

- Incorporate labeled examples (when available) to measure precision/recall, not just score distributions.
- Log score distributions and key metrics over time as a simple drift dashboard.
- Experiment with additional models (e.g., deep log anomaly detectors) while keeping Isolation Forest as a robust baseline.