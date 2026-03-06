def compute_cvss(results):

    score = 0

    for r in results:

        output = r["output"].lower()

        if "critical" in output:
            score += 9

        elif "high" in output:
            score += 7

        elif "medium" in output:
            score += 5

        elif "low" in output:
            score += 2

    if score > 10:
        score = 10

    return score