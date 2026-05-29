"""CVSS 3.1 score calculation using the RedHat cvss library."""

from cvss import CVSS3
from pydantic import BaseModel


class CvssResult(BaseModel):
    """Result of a CVSS 3.1 calculation."""

    vector: str
    score: float
    rating: str


def calculate_cvss(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> CvssResult:
    """Build a CVSS 3.1 vector from individual metrics and compute the score."""
    vector = (
        f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}"
        f"/PR:{privileges_required}/UI:{user_interaction}"
        f"/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    )
    return score_from_vector(vector)


def score_from_vector(vector: str) -> CvssResult:
    """Compute CVSS score and rating from a vector string."""
    try:
        c = CVSS3(vector)
    except Exception as e:
        msg = f"Invalid CVSS vector: {vector}"
        raise ValueError(msg) from e
    base_score = c.scores()[0]
    rating = c.severities()[0]
    return CvssResult(
        vector=c.clean_vector(),
        score=base_score,
        rating=rating,
    )
