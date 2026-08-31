import pytest

from src.analysis.diversity import diversity_index, simpson_index


def test_simpson_index_is_max_when_concentrated_on_one_category():
    assert simpson_index([10]) == 1.0


def test_simpson_index_is_min_for_uniform_distribution():
    assert simpson_index([1, 1, 1, 1]) == pytest.approx(0.25)


def test_simpson_index_is_max_when_there_is_no_data():
    assert simpson_index([]) == 1.0


def test_diversity_index_is_inverse_of_simpson_index():
    assert diversity_index([1, 1, 1, 1]) == pytest.approx(0.75)
    assert diversity_index([10]) == 0.0
    assert diversity_index([]) == 0.0
