from my_module.math_operations import add, subtract, multiply, divide

# Test the functions
print(f"Add: 2 + 3 = {add(2, 3)}")
print(f"Subtract: 5 - 2 = {subtract(5, 2)}")
print(f"Multiply: 4 * 3 = {multiply(4, 3)}")
print(f"Divide: 10 / 2 = {divide(10, 2)}")

# Example of dividing by zero
try:
    print(divide(10, 0))
except ValueError as e:
    print(e)
    