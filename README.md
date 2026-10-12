# Bugsieve scan

Scan the pushed branch with Bugsieve and fail the build when it has flaws attackers are exploiting right now (CISA KEV).

```yaml
- uses: bugsieve/scan-action@v1
  with:
    server: https://bugsieve.example.com
    token: ${{ secrets.BUGSIEVE_TOKEN }}
    fail-on: exploited   # or none, critical, high, medium
```

Create the token on your Bugsieve profile under **API tokens**. Private repositories use the access token saved for that repository in Bugsieve.

Each scan counts toward your Bugsieve limits. When a limit is reached, the step warns and passes. Pull requests from forks get no secrets, so the step is skipped there.
