import sys

with open('test_accuracy_suite.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_benchmark_tests = '''
    {
        "name": "GraphQL Introspection Test (trevorblades.com)",
        "url": "https://countries.trevorblades.com",
        "check_type": "finding_status",
        "expected_statuses": ["informational"],
        "expected_keywords": ["graphql", "graphql_introspection_enabled"],
        "expected_result_contains": True,
        "scope": "Verifies that public GraphQL endpoints emit an informational finding."
    },
    {
        "name": "Verbose Stack Trace Guardrail Test (nextjs.org)",
        "url": "https://nextjs.org",
        "check_type": "finding_absence",
        "forbidden_keywords": ["verbose backend error", "verbose_stack_trace_leak", "stack trace"],
        "scope": "Verifies that HTML/SPA routes do not trigger false positive stack trace leaks."
    },
'''

if 'GraphQL Introspection Test' not in content:
    content = content.replace('BENCHMARK_TARGETS = [', 'BENCHMARK_TARGETS = [\n' + new_benchmark_tests)
    with open('test_accuracy_suite.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print("Benchmark tests added!")
else:
    print("Benchmark tests already exist!")
