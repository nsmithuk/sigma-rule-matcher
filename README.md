# sigma-rule-matcher

`sigma-rule-matcher` is a Python package for evaluating Sigma detection rules against structured event data. 
Built on top of [pySigma](https://github.com/SigmaHQ/pySigma), it parses and applies Sigma rule logic—including 
condition expressions and most common modifiers—to incoming events to determine whether they match.

So far, this project is primarily a learning tool, put together to better understand how Sigma rules operate under the hood.

## Installation

Install the package from PyPI:

```bash
pip install sigma-rule-matcher
```

> Requires Python 3.10 or later. This will install the library and its dependencies:
>
> - boolean.py (for boolean expression evaluation)
> - pySigma (for parsing Sigma rules)

## Usage

Sigma rules can include multiple selectors, logical operators, and modifiers. For example:

```python
from sigma.rule import SigmaRule
from sigma_rule_matcher import RuleMatcher

sigma_rule = '''
title: Suspicious activity
logsource:
  product: test
detection:
  sel1:
    src_ip:
      - 10.0.0.1
      - 10.0.0.2
  sel2:
    user:
      - root
  sel3:
    process_name:
      - 'malicious.exe'
  condition: (sel1 or sel2) and sel3
'''

rule = SigmaRule.from_yaml(sigma_rule)
matcher = RuleMatcher(rule)

# Test against an event
event = {
    'src_ip': '10.0.0.2',
    'user': 'guest',
    'process_name': 'malicious.exe'
}

assert matcher.match(event) is True
```

## Running Tests

The library includes a comprehensive test suite. To run the tests:

```bash
pytest
```

### License

This project is licensed under the [MIT License](LICENSE).

It uses the [pySigma](https://github.com/SigmaHQ/pySigma) library, which is licensed under the **GNU Lesser General Public License v2.1 (LGPL-2.1)**. A copy of the [LGPL-2.1 license](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html) is here.

We use pySigma without modification.
