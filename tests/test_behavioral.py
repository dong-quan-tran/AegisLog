from aegislog.features.behavioral import _compute_success_after_failure_count


def test_success_after_failure_count_handles_mixed_sequences():
    statuses = [
        401, 401, 401,
        200, 200,
        200,
        404, 500,
        401, 200,
        200,
    ]

    count = _compute_success_after_failure_count(statuses)

    # Every 200 that occurs after any earlier 401 is counted.
    assert count == 5