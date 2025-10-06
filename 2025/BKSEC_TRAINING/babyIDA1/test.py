from sympy import symbols, Eq, solve

a, b, c, d, e = symbols('a b c d e')

eq1 = Eq(a + b + c, 10)
eq2 = Eq(b + c + d, 12)
eq3 = Eq(c + d + e, 10)
eq4 = Eq(d + e + a, 11)
eq5 = Eq(e + a + b, 11)

solution = solve((eq1, eq2, eq3, eq4, eq5), (a, b, c, d, e))
print(solution)
