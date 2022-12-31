# Crowdstrike Falcon OSQuery Extension

Gathers basic data on sensor using `falconctl stats`.

## Usage
For testing, you can load the extension with `osqueryi`.

By default, osquery does not want to load extensions not owned by root. You can either change the ownership of crowdstrike.ext to root, or run osquery with the `--allow_unsafe` flag.

```bash
osqueryi --extension /path/to/crowdstrike.ext
```

For production deployment, you should refer to the [osquery documentation](https://osquery.readthedocs.io/en/stable/deployment/extensions/).
