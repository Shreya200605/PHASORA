"""
PHASORA Evaluation Framework
"""

from evaluation.test_cases import (
    SYNTHETIC_TEST_SUITE,
    MANIPULATION_TEST_CASES,
    LEAKAGE_TEST_CASES,
    get_synthetic_test_cases,
    get_manipulation_test_cases,
    get_leakage_test_cases,
    get_test_cases_by_category,
    get_categories,
    get_summary_stats
)

from evaluation.metrics import (
    execute_security_test,
    compute_confusion_matrix,
    compute_category_resilience,
    run_synthetic_evaluation,
    calculate_pii_metrics,
    calculate_leakage_rate,
    calculate_utility_preservation,
    calculate_adversarial_resistance
)

__all__ = [
    "SYNTHETIC_TEST_SUITE",
    "MANIPULATION_TEST_CASES",
    "LEAKAGE_TEST_CASES",
    "get_synthetic_test_cases",
    "get_manipulation_test_cases",
    "get_leakage_test_cases",
    "get_test_cases_by_category",
    "get_categories",
    "get_summary_stats",
    "execute_security_test",
    "compute_confusion_matrix",
    "compute_category_resilience",
    "run_synthetic_evaluation",
    "calculate_pii_metrics",
    "calculate_leakage_rate",
    "calculate_utility_preservation",
    "calculate_adversarial_resistance"
]
