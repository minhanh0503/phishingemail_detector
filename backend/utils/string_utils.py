def extract_domain(email: str) -> str:
    return email.split("@")[-1].lower()

def extract_local_part(email: str) -> str:
    return email.split("@")[0].lower()

def extract_tld(domain: str) -> str:
    return domain.split(".")[-1]

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0

    rows = len(a) + 1
    cols = len(b) + 1
    dp = [[0] * cols for _ in range(rows)]

    for i in range(rows):
        dp[i][0] = i
    for j in range(cols):
        dp[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            )

    return dp[-1][-1]
