import numpy as np
from collections import deque
import json
import os

class AdaptiveThreshold:
    def __init__(self, dataset_name, initial_stats=None, window_size=5000, sensitivity=3.0):
        self.dataset_name = dataset_name
        self.window_size = window_size
        self.sensitivity = sensitivity
        self.scores = deque(maxlen=window_size)

        if initial_stats:
            self.stats = {
                # --- FIX: Invert the mean because the engine works with inverted scores ---
                "median": -initial_stats.get("mean", 0.0),
                "mad": initial_stats.get("std", 1.0)
            }
        else:
            self.stats = {"median": 0.0, "mad": 1.0}


    def update(self, new_scores):
        """Ingest new scores and update rolling statistics."""
        # IF uses negative for anomaly. We invert it so higher = more anomalous
        # assuming input is raw decision_function
        inverted_scores = [-s for s in new_scores]
        self.scores.extend(inverted_scores)

        if len(self.scores) >= 100:
            self._recalculate_stats()

    def _recalculate_stats(self):
        data = np.array(self.scores)
        median = np.median(data)
        # Median Absolute Deviation (Robust against spikes)
        mad = np.median(np.abs(data - median)) + 1e-9

        self.stats["median"] = float(median)
        self.stats["mad"] = float(mad)

    def check_anomaly(self, raw_score):
        """
        Returns (is_anomaly, z_score)
        """
        # Invert score because logic assumes Higher = Bad
        score = -raw_score

        # Modified Z-Score Formula
        z_score = 0.6745 * (score - self.stats["median"]) / self.stats["mad"]

        is_anom = z_score > self.sensitivity
        return is_anom, z_score
