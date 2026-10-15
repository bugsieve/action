# Bugsieve scan

Scan the pushed branch with Bugsieve and fail the build when it has flaws attackers are exploiting right now (CISA KEV).

```yaml
- uses: bugsieve/action@v1
  with:
    token: ${{ secrets.BUGSIEVE_TOKEN }}
    fail-on: exploited   # or none, critical, high, medium
```

Create the token on your Bugsieve profile under **API tokens**. Private repositories use the access token saved for that repository in Bugsieve.

Each scan counts toward your Bugsieve limits. When a limit is reached, the step warns and passes. Pull requests from forks get no secrets, so the step is skipped there.

## Options

| Input | Default | What it does |
|---|---|---|
| `fail-on` | `exploited` | Fail the build at this level or above: `none`, `exploited`, `critical`, `high` or `medium`. Each level includes the ones before it. |
| `strict` | `false` | Also fail when Bugsieve itself can't be reached or answers with an error. By default an outage on our side only warns, so it never blocks your pipeline. |
| `repository`, `ref` | the running repo and branch | What to scan. |
| `timeout-minutes` | `20` | How long to wait for the result. |
| `server` | `https://bugsieve.com` | Only change this if you run your own Bugsieve. |

Outputs: `status` (`completed`, `failed`, `skipped` or `timeout`), `critical`, `high`, `exploited`, `scan-id` and `report-url`.
