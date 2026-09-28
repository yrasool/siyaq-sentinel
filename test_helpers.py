import json
from pathlib import Path


def make_grid_repo(root: Path) -> Path:
    (root / "apps/grid").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "package.json").write_text(json.dumps({
        "scripts": {"cf:deploy:grid": "node scripts/deploy-cf-worker.mjs grid"}
    }), encoding="utf-8")
    (root / "apps/grid/package.json").write_text(json.dumps({
        "scripts": {"check": "npm run cf:dry-run && npm run verify:boundary"}
    }), encoding="utf-8")
    (root / "scripts/deploy-cf-worker.mjs").write_text(
        "run('opennextjs-cloudflare build'); run('opennextjs-cloudflare deploy');",
        encoding="utf-8",
    )
    return root
