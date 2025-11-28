#!/usr/bin/env python3
"""Check Python file for syntax errors and indentation issues"""
import ast
import sys

def check_file(filename):
    """Check a Python file for syntax errors"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source = f.read()
        
        # Try to parse the file
        try:
            ast.parse(source)
            print(f"✓ {filename}: Syntax is valid")
            return True
        except SyntaxError as e:
            print(f"✗ {filename}: Syntax error at line {e.lineno}")
            print(f"  Error: {e.msg}")
            print(f"  Text: {e.text}")
            if e.text:
                print(f"  Position: {' ' * (e.offset - 1)}^")
            return False
    except Exception as e:
        print(f"✗ Error reading {filename}: {e}")
        return False

if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "routes/aws_manager.py"
    success = check_file(filename)
    sys.exit(0 if success else 1)

