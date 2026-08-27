from src.analysis.work_weight import compute_work_weight


def test_compute_work_weight_example_from_spec():
    result = compute_work_weight(
        syn_sent=80, fin_sent=10, rst_received=90, total_tcp_packets=200
    )
    assert result == 0.9
