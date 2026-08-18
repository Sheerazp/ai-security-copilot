# Dataset Sources

The synthetic dataset used for the initial build (`data/security_events.csv`)
can be replaced with real, free, academically-licensed network intrusion
datasets. All of the following are free for academic/research use.

## Recommended: CICIDS2017 (cleaned/preprocessed)
- Kaggle: https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed
- Kaggle (most-used version): https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset
- Official source: https://www.unb.ca/cic/datasets/ids-2017.html

## Alternative: UNSW-NB15
- Kaggle: https://www.kaggle.com/datasets/harshwardhanbhangale/unsw-complete-dataset
- Official source: https://research.unsw.edu.au/projects/unsw-nb15-dataset

## Alternative: NSL-KDD
- Smaller, simpler, good for quick experiments — search "NSL-KDD" on Kaggle.

## License note
All of the above are free for **academic/research purposes**. Commercial
use is not permitted under their original licenses. For a student
portfolio or class project, this is not a concern — just credit the
dataset source in your README/demo, e.g.:

> "Detection models trained on [synthetic data modeled after / the
> CICIDS2017 dataset], Canadian Institute for Cybersecurity, used for
> academic purposes."

## Swapping in real data
1. Download one of the datasets above as CSV.
2. Rename its columns to match `FEATURE_COLUMNS` in
   `notebooks/data_generator.py` (duration, protocol_type, src_bytes,
   dst_bytes, count, srv_count, same_srv_rate, diff_srv_rate,
   serror_rate, rerror_rate, num_failed_logins, logged_in,
   wrong_fragment, urgent, hot) plus a `label` column.
3. Save it as `data/security_events.csv`.
4. Re-run `python notebooks/train_intrusion_model.py` and
   `python notebooks/train_anomaly_model.py`.

No other code changes are required — the backend loads whatever is in
`models/*.pkl`, regardless of what data trained them.
