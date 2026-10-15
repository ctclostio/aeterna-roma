## 2024-05-24 - Optimizing strip_templates with lambda removal
**Learning:** In Python `re.sub()`, using a lambda function when a static replacement string will suffice causes a significant overhead (about 28% slower).
**Action:** Replace lambda with a static string `''` in `re.sub(r'<[^<>]*>', '', txt)` to eliminate the lambda overhead.
