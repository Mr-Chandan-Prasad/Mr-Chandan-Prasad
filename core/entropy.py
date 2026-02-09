import math


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    frequencies = {}
    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy
