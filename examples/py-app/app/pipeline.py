"""Synthetic pipeline module for the dep-radar example."""
import json

import numpy as np
import requests
import yaml


def fetch(url: str) -> dict:
    response = requests.get(url, timeout=5)
    return response.json()


def load_config(path: str) -> dict:
    with open(path, encoding='utf-8') as handle:
        return yaml.safe_load(handle)


def summarise(values: list[float]) -> float:
    return float(np.mean(values))


def dumps(payload: dict) -> str:
    return json.dumps(payload)
