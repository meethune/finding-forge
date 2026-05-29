"""Tests for CVSS calculation module."""

import pytest

from finding_forge.cvss.calculator import (
    CvssResult,
    calculate_cvss,
    score_from_vector,
)


class TestCalculateCvss:
    def test_critical_severity(self) -> None:
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        assert result.score == 9.8
        assert result.rating == "Critical"
        assert "CVSS:3.1" in result.vector

    def test_high_severity(self) -> None:
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="N",
        )
        assert result.score == 9.1
        assert result.rating == "Critical"

    def test_medium_severity(self) -> None:
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="R",
            scope="C",
            confidentiality="L",
            integrity="L",
            availability="N",
        )
        assert result.score == 6.1
        assert result.rating == "Medium"

    def test_low_severity(self) -> None:
        result = calculate_cvss(
            attack_vector="L",
            attack_complexity="H",
            privileges_required="H",
            user_interaction="R",
            scope="U",
            confidentiality="L",
            integrity="N",
            availability="N",
        )
        assert result.score < 4.0
        assert result.rating == "Low"

    def test_returns_cvss_result(self) -> None:
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H",
        )
        assert isinstance(result, CvssResult)

    def test_vector_format(self) -> None:
        result = calculate_cvss(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="L",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="N",
            availability="N",
        )
        assert result.vector.startswith("CVSS:3.1/")
        assert "/AV:N/" in result.vector

    def test_invalid_metric_raises(self) -> None:
        with pytest.raises(ValueError):
            calculate_cvss(
                attack_vector="X",
                attack_complexity="L",
                privileges_required="N",
                user_interaction="N",
                scope="U",
                confidentiality="H",
                integrity="H",
                availability="H",
            )


class TestScoreFromVector:
    def test_valid_vector(self) -> None:
        result = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result.score == 9.8
        assert result.rating == "Critical"

    def test_medium_vector(self) -> None:
        result = score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        assert result.score == 6.1
        assert result.rating == "Medium"

    def test_preserves_vector(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = score_from_vector(vector)
        assert result.vector == vector

    def test_invalid_vector_raises(self) -> None:
        with pytest.raises(ValueError):
            score_from_vector("not-a-vector")

    def test_cvss30_vector(self) -> None:
        result = score_from_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result.score == 9.8
