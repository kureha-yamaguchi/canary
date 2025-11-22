from datetime import datetime, timedelta
import random
import pandas as pd
from typing import List, Dict, Any


def random_datetime(start: datetime, end: datetime) -> datetime:
    if start > end:
        raise ValueError("Start datetime must be before or equal to end datetime")

    # Calculate the time difference in seconds
    delta_seconds = (end - start).total_seconds()

    # Generate a random number of seconds to add to start
    random_seconds = random.uniform(0, delta_seconds)

    # Return the random datetime
    return start + timedelta(seconds=random_seconds)


def add_random_time(dt: datetime, mean_minutes: float, std_minutes: float) -> datetime:
    # Generate random minutes using normal distribution
    random_minutes = random.gauss(mean_minutes, std_minutes)

    # Ensure the value is never negative
    random_minutes = max(0.01, random_minutes)

    # Add the random time to the datetime
    return dt + timedelta(minutes=random_minutes)


def export_vulnerability_logs_to_csv(
    logs: List[Dict[str, Any]], output_path: str
) -> None:
    df = pd.DataFrame(logs)

    # Ensure proper column order
    columns = [
        "id",
        "base_url",
        "vulnerability_type",
        "technique_id",
        "timestamp",
        "attacker_id",
        "session_id",
        "is_synthetic",
    ]

    # Reorder columns if all are present
    if all(col in df.columns for col in columns):
        df = df[columns]

    df.to_csv(output_path, index=False)
    print(f"Exported {len(logs)} vulnerability logs to {output_path}")
