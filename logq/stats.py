from dataclasses import dataclass

@dataclass
class Stats:
    sum_runtime_errors: int = 0
    sum_name_errors: int = 0
    sum_matches: int = 0
    rec_runtime_errors: int = 0
    rec_matches: int = 0

stats = Stats()