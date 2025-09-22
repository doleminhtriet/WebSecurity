import argparse, sys, hashlib
from datetime import datetime, timezone
from core.config import load_config
from core.logging import setup_logging
from core.db.mongodb import get_db
from .pipeline import train as train_pipe, evaluate as eval_pipe
from .model import load_artifacts

def main(argv=None):
    parser = argparse.ArgumentParser(prog="phishing")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train", help="Train phishing model")
    p_train.add_argument("--config", default="config/base.yaml")

    p_eval = sub.add_parser("eval", help="Evaluate phishing model")
    p_eval.add_argument("--config", default="config/base.yaml")

    p_pred = sub.add_parser("predict", help="Predict on text or file")
    p_pred.add_argument("--config", default="config/base.yaml")
    p_pred.add_argument("--text")
    p_pred.add_argument("--file")
    p_pred.add_argument("--log", action="store_true")

    args = parser.parse_args(argv)
    setup_logging("config/logging.yaml")
    cfg = load_config(args.config)

    if args.cmd == "train":
        train_pipe(cfg)
        return

    if args.cmd == "eval":
        eval_pipe(cfg)
        return

    if args.cmd == "predict":
        text = None
        if args.text:
            text = args.text
        elif args.file:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        else:
            print("Provide --text or --file", file=sys.stderr)
            sys.exit(1)

        pcfg = cfg["phishing"]
        pipe = load_artifacts(pcfg["artifacts_dir"])
        X = pipe["featurizer"].transform([text])
        prob = float(pipe["clf"].predict_proba(X)[0,1])
        label = int(prob >= pcfg.get("threshold", 0.5))
        print({"label": label, "probability": prob})

        try:
            db = get_db(cfg)
            if db:
                mcfg = pcfg.get("logging", {})
                only_pos = bool(mcfg.get("log_only_positives", True))
                do_log = (label == 1) or bool(args.log) if only_pos else True
                if do_log:
                    col = mcfg.get("collection_predictions", "phishing_predictions")
                    snippet = text if mcfg.get("store_text", False) else (text[: int(mcfg.get("store_snippet_chars", 160))] if text else "")
                    db[col].insert_one({
                        "ts": datetime.now(timezone.utc),
                        "label": label,
                        "probability": prob,
                        "threshold": float(pcfg.get("threshold", 0.5)),
                        "text_sha256": hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest(),
                        "snippet": snippet,
                        "source": "cli/phishing"
                    })
        except Exception:
            pass

if __name__ == "__main__":
    main()
