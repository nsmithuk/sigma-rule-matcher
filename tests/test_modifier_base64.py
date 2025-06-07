import base64

from sigma.rule import SigmaRule

from sigma_rule_matcher import RuleMatcher


def test_match_with_base64_modifier():
    sigma_rule = """
    title: Base64 match
    logsource:
      product: test
    detection:
      selection1:
        payload|base64: foo
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    event = {'payload': base64.b64encode(b'foo').decode()}
    assert matcher.match(event) is True


def test_match_with_base64offset_modifier():
    sigma_rule = """
    title: Base64offset match
    logsource:
      product: test
    detection:
      selection1:
        payload|base64offset|contains: foo
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    junk = b"x" * 100
    value = junk + base64.b64encode(b'foo')
    event = {'payload': value.decode(errors='ignore')}
    assert matcher.match(event) is True


# def test_match_with_utf16_base64_modifier():
#     sigma_rule = """
#     title: UTF16 + base64 match
#     logsource:
#       product: test
#     detection:
#       selection1:
#         payload|utf16|base64offset|contains: foo
#       condition: selection1
#     """
#     rule = SigmaRule.from_yaml(sigma_rule)
#     matcher = RuleMatcher(rule)
#     value = base64.b64encode("foo".encode("utf-16")).decode()
#     event = {'payload': value}
#     assert matcher.match(event) is True


# def test_match_with_utf16le_base64_modifier():
#     sigma_rule = """
#     title: UTF16LE + base64 match
#     logsource:
#       product: test
#     detection:
#       selection1:
#         payload|utf16le|base64: foo
#       condition: selection1
#     """
#     rule = SigmaRule.from_yaml(sigma_rule)
#     matcher = RuleMatcher(rule)
#     value = base64.b64encode("foo".encode("utf-16le")).decode()
#     event = {'payload': value}
#     assert matcher.match(event) is True


# def test_match_with_utf16be_base64_modifier():
#     sigma_rule = """
#     title: UTF16BE + base64 match
#     logsource:
#       product: test
#     detection:
#       selection1:
#         payload|utf16be|base64: foo
#       condition: selection1
#     """
#     rule = SigmaRule.from_yaml(sigma_rule)
#     matcher = RuleMatcher(rule)
#     value = base64.b64encode("foo".encode("utf-16be")).decode()
#     event = {'payload': value}
#     assert matcher.match(event) is True


def test_match_with_wide_base64_modifier():
    sigma_rule = """
    title: Wide + base64 match
    logsource:
      product: test
    detection:
      selection1:
        payload|wide|base64: foo
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    value = base64.b64encode("foo".encode("utf-16le")).decode()
    event = {'payload': value}
    assert matcher.match(event) is True


# --- With contains ---

# def test_match_with_utf16le_base64_contains_modifier():
#     sigma_rule = """
#     title: UTF16LE + base64 + contains
#     logsource:
#       product: test
#     detection:
#       selection1:
#         CommandLine|utf16le|base64|contains: ping
#       condition: selection1
#     """
#     rule = SigmaRule.from_yaml(sigma_rule)
#     matcher = RuleMatcher(rule)
#     value = base64.b64encode("ping -n 4".encode("utf-16le")).decode()
#     event = {'CommandLine': value}
#     assert matcher.match(event) is True


def test_match_with_wide_base64_contains_modifier():
    sigma_rule = """
    title: Wide + base64 + contains
    logsource:
      product: test
    detection:
      selection1:
        CommandLine|wide|base64offset|contains: ping
      condition: selection1
    """
    rule = SigmaRule.from_yaml(sigma_rule)
    matcher = RuleMatcher(rule)
    value = base64.b64encode("ping -t".encode("utf-16le")).decode()
    event = {'CommandLine': value}
    assert matcher.match(event) is True


# def test_match_with_utf16be_base64offset_contains_modifier():
#     sigma_rule = """
#     title: UTF16BE + base64offset + contains
#     logsource:
#       product: test
#     detection:
#       selection1:
#         CommandLine|utf16be|base64offset|contains: ping
#       condition: selection1
#     """
#     rule = SigmaRule.from_yaml(sigma_rule)
#     matcher = RuleMatcher(rule)
#     data = b"x" * 80 + base64.b64encode("ping /?".encode("utf-16be"))
#     event = {'CommandLine': data.decode(errors="ignore")}
#     assert matcher.match(event) is True

#
# def test_match_with_utf16_base64offset_contains_modifier():
#     sigma_rule = """
#     title: UTF16 + base64offset + contains
#     logsource:
#       product: test
#     detection:
#       selection1:
#         CommandLine|utf16|base64offset|contains: ping
#       condition: selection1
#     """
#     rule = SigmaRule.from_yaml(sigma_rule)
#     matcher = RuleMatcher(rule)
#     encoded = base64.b64encode("ping localhost".encode("utf-16"))
#     data = b"x" * 120 + encoded
#     event = {'CommandLine': data.decode(errors="ignore")}
#     assert matcher.match(event) is True

#
# def test_no_match_with_encoding_chain_contains_wrong_text():
#     sigma_rule = """
#     title: No match wrong command
#     logsource:
#       product: test
#     detection:
#       selection1:
#         CommandLine|utf16le|base64|contains: ping
#       condition: selection1
#     """
#     rule = SigmaRule.from_yaml(sigma_rule)
#     matcher = RuleMatcher(rule)
#     value = base64.b64encode("notping".encode("utf-16le")).decode()
#     event = {'CommandLine': value}
#     assert matcher.match(event) is False
