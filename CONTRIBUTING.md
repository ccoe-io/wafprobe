# Contributing to WAF Testing Framework

Thank you for your interest in contributing to the WAF Testing Framework! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Contributing Workflow](#contributing-workflow)
- [Adding New Rule Modules](#adding-new-rule-modules)
- [Adding New Test Vectors](#adding-new-test-vectors)
- [Coding Guidelines](#coding-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Guidelines](#documentation-guidelines)

## Code of Conduct

Please be respectful and considerate of others when contributing to this project. We aim to create a welcoming environment for all contributors regardless of background or experience level.

## Development Setup

1. **Fork the repository**:
   - Fork the repository to your own GitHub account

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/waf-testing.git
   cd waf-testing
   ```

3. **Set up a virtual environment**:
   ```bash
   # Create a virtual environment
   python -m venv venv
   
   # Activate it
   # On macOS/Linux:
   source venv/bin/activate
   # On Windows:
   venv\Scripts\activate
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   
   # Install development dependencies (if applicable)
   pip install -r requirements-dev.txt
   ```

5. **Set up pre-commit hooks** (if applicable):
   ```bash
   pre-commit install
   ```

## Project Structure

The WAF Testing Framework is organized as follows:

```
.
├── configs/             # Example configuration files
├── core/                # Core framework code
│   ├── engine.py        # Test engine
│   ├── reporter.py      # Reporting functionality
│   └── utils.py         # Utility functions
├── helpers/             # Helper utilities
├── reports/             # Generated reports (gitignored)
├── rules/               # Rule modules
│   ├── aws_rules.py     # AWS WAF rules
│   ├── graphql_rules.py # GraphQL rules
│   └── ...
├── runners/             # Command-line runners
│   └── multi_waf_tester.py # Main runner
├── vectors/             # Attack vectors
│   ├── sql.py           # SQL injection vectors
│   ├── xss.py           # XSS vectors
│   └── ...
├── requirements.txt     # Dependencies
└── README.md           # Main documentation
```

## Contributing Workflow

1. **Create a new branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**: Implement your feature or fix

3. **Run tests**: Make sure all tests pass

4. **Commit your changes**:
   ```bash
   git commit -am "Add feature: your feature description"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit a pull request**: Go to the original repository and create a pull request

## Adding New Rule Modules

Rule modules define the rules and attack vectors for specific technologies. To add a new rule module:

1. **Create a new file** in the `rules/` directory, e.g., `rules/your_technology_rules.py`

2. **Implement the required functions**:

   ```python
   from typing import List, Dict
   from core.engine import WafRule
   
   def get_category_mappings() -> Dict[str, str]:
       """
       Map category names to rule name patterns.
       Used for filtering rules by category.
       """
       return {
           "your_category": "YourTech_"  # Match rule names starting with YourTech_
       }
   
   def get_categories() -> Dict[str, str]:
       """
       Provide descriptions for categories.
       """
       return {
           "your_category": "Description of your category"
       }
   
   def get_rules() -> List[WafRule]:
       """
       Return a list of WAF rules for your technology.
       """
       rules = []
       
       # Add rules with test vectors
       rules.append(
           WafRule(
               name="YourTech_Rule1",
               description="Description of rule 1",
               test_vectors=["vector1", "vector2"],
               request_components=["body", "querystring"]
           )
       )
       
       # You can also import vectors from the vectors/ directory
       # from vectors.your_vectors import your_vectors_list
       # ...
       
       return rules
   ```

3. **Add documentation** for your new rules in `rule_list.txt`

4. **Test your new module**:
   ```bash
   python -m runners.multi_waf_tester --module your_technology_rules --list-rules
   ```

## Adding New Test Vectors

Test vectors are the actual payloads used to test WAF rules. To add new vectors:

1. **Create or update a file** in the `vectors/` directory, e.g., `vectors/your_vectors.py`

2. **Define your vectors**:

   ```python
   # Basic vector list
   your_vectors = [
       "attack payload 1",
       "attack payload 2",
       # ...
   ]
   
   # Or organize by type
   your_vectors_by_type = {
       "type1": [
           "attack type 1 payload 1",
           "attack type 1 payload 2"
       ],
       "type2": [
           "attack type 2 payload 1",
           "attack type 2 payload 2"
       ]
   }
   ```

3. **Import your vectors** in your rule module:

   ```python
   from vectors.your_vectors import your_vectors
   
   def get_rules() -> List[WafRule]:
       # ...
       rules.append(
           WafRule(
               name="YourTech_Rule1",
               description="Tests vectors for your technology",
               test_vectors=your_vectors,
               request_components=["body"]
           )
       )
       # ...
   ```

## Coding Guidelines

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write docstrings for functions and classes
- Keep functions small and focused on a single task
- Use meaningful variable and function names

## Testing Guidelines

Before submitting a pull request, ensure:

1. **Your code works** with all supported Python versions (3.7+)
2. **Your module integrates properly** with the existing framework
3. **Your attack vectors are effective** against appropriate targets
4. **You've tested with different configurations** to ensure flexibility

### Testing Matrix

| Test Type | What to Test |
|-----------|--------------|
| Functionality | Do your rules and vectors work as expected? |
| Integration | Does your module work with the main runner? |
| Edge Cases | Does your code handle invalid inputs gracefully? |
| Performance | Are your vectors reasonably efficient? |

## Documentation Guidelines

Good documentation is crucial for this project. Please:

1. **Add docstrings** to your code
2. **Update relevant documentation files** like README.md or guides
3. **Add example configurations** for your new modules in `configs/`
4. **Document your rule categories** and their purpose

### Example Documentation

For every new rule module, update the rule_list.txt file with details:

```
YourTech_Rule1: Tests for vulnerability X in technology Y
YourTech_Rule2: Tests for vulnerability Z in technology Y
...
```

## Pull Request Process

1. **Ensure your code meets the guidelines**
2. **Fill out the pull request template** with all required information
3. **Link to any relevant issues**
4. **Be responsive to feedback and requests for changes**
5. **Allow maintainers time to review your submission**

## Release Process

For maintainers only:

1. Update version numbers in relevant files
2. Merge the release branch to main
3. Create a new release tag
4. Update the changelog

---

Thank you for contributing to the WAF Testing Framework! Your efforts help improve security for everyone. 