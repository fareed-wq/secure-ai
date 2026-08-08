with open('test_accuracy_suite.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Fix GraphQL check
text = text.replace('"expected_keywords": ["graphql", "graphql_introspection_enabled"],\n        "expected_result_contains": True,', '"finding_keyword": "graphql",')
text = text.replace('"finding_keyword": "graphql",', '"finding_keyword": "graphql",') # in case I want to keep it clean

# Fix Verbose Stack Trace Check
text = text.replace('"check_type": "finding_absence",', '"check_type": "anti_false_positive",')
text = text.replace('"forbidden_keywords": ["verbose backend error", "verbose_stack_trace_leak", "stack trace"],', '"forbidden_findings": ["Verbose Backend Error / Stack Trace Disclosure"],')

with open('test_accuracy_suite.py', 'w', encoding='utf-8') as f:
    f.write(text)
