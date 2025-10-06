import re

def find_flag():
    regex = (r"EHCTF{\x72(\x33)\g<+2>(g)(3)((x)?(?(1)_|\x69))(15){1}(?(?<=\W)(\d)|(_))"
             r"\x74([^a-zA-Z0-9]|h)(\x34((?=\x74{1}_)[^\d]{2}))\g{-9}(?<!a-zA-Z)"
             r"\x34(\x35){1}\x79(?12)(?+1)\g{-8}\x44(\g{8})}")
    
    test_strings = [
        "EHCTF{r3gex_15_t4g45yD}",  # Expected flag based on regex analysis
        "EHCTF{r3gex_15_t4g45yX}",
        "EHCTF{r3gex_15_t4g45yZ}",
        "EHCTF{r3gex_15_t4g45yA}",
        "EHCTF{r3gex_15_t4g45yB}",
        "EHCTF{r3gex_15_t4g45yC}",
        "EHCTF{r3gex_15_t4g45yE}",
        "EHCTF{r3gex_15_t4g45yF}",
        "EHCTF{r3gex_15_t4g45yG}",
        "EHCTF{r3gex_15_t4g45yH}",
        "EHCTF{r3gex_15_t4g45yI}",
        "EHCTF{r3gex_15_t4g45yJ}",
        "EHCTF{r3gex_15_t4g45yK}",
        "EHCTF{r3gex_15_t4g45yL}",
        "EHCTF{r3gex_15_t4g45yM}",
        "EHCTF{r3gex_15_t4g45yN}",
        "EHCTF{r3gex_15_t4g45yO}",
        "EHCTF{r3gex_15_t4g45yP}",
        "EHCTF{r3gex_15_t4g45yQ}",
        "EHCTF{r3gex_15_t4g45yR}",
        "EHCTF{r3gex_15_t4g45yS}",
        "EHCTF{r3gex_15_t4g45yT}",
        "EHCTF{r3gex_15_t4g45yU}",
        "EHCTF{r3gex_15_t4g45yV}",
        "EHCTF{r3gex_15_t4g45yW}",
        "EHCTF{random_test_string}",
        "EHCTF{some_other_test_case}",
        "EHCTF{incorrect_format_test}",
    ]
    
    for test in test_strings:
        if re.fullmatch(regex, test):
            print("Flag found:", test)
            return test
    
    print("No matching flag found.")
    return None

if __name__ == "__main__":
    find_flag()
