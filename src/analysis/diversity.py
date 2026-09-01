"""Simpson's Diversity Index (specifiche sez. 5).

D = sum(p_i^2), dove p_i è la proporzione di elementi nella categoria i.
D vicino a 1 indica traffico concentrato su poche categorie (bassa diversità);
D vicino a 0 indica traffico distribuito su molte categorie (alta diversità).
"""


def simpson_index(counts):
    total = sum(counts)
    if total == 0:
        return 1.0
    return sum((count / total) ** 2 for count in counts)


def diversity_index(counts):
    """Indice inverso (1 - D): 0 = concentrato, 1 = disperso."""
    return 1.0 - simpson_index(counts)
