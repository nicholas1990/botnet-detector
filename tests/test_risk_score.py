from src.risk_score import compute_risk_score


def test_compute_risk_score_is_not_implemented_yet():
    try:
        compute_risk_score(stats=None, work_weight=0.9)
    except NotImplementedError:
        pass
    else:
        raise AssertionError("expected NotImplementedError until scoring logic lands")
