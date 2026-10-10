git add services/analysis.py
git commit -m "feat(analysis): add dedicated SIP vulnerability and bypass checks

- Inspect entitlements for rootless and debug entitlements (com.apple.rootless.*, get-task-allow)
- Check for missing __RESTRICT segments alongside debug entitlements / dyld injection indicators
- Categorize and flag SIP-related findings with appropriate High/Critical severities in the vulnerabilities table"
