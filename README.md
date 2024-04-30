# Sensor downloader for CrowdStrike Falcon

A CLI/TUI for sorting and filtering through the available sensor installers, with the ability to download specific releases.

Requires a customer client ID and client secret for API access.

## Install

### With Go installed

```bash
go install github.com/northwood-labs/crowdstrike-falcon-downloader@latest
```

### As a package

TBD. Coming soon.

## Authentication

These environment variables must be set in order to access the API and view the list.

* `CROWDSTRIKE_CLIENT_ID`
* `CROWDSTRIKE_CLIENT_SECRET`

> [!IMPORTANT]
> When installing a sensor, the installation will require a customer identifier. This software does not deal with installation, but you should be aware that you must be a [CrowdStrike](https://www.crowdstrike.com) customer for this to be useful.

## TUI usage

> [!NOTE]
> Where a GUI is a _graphical user interface_, a TUI is a _textual user interface_. For terminals. And shells.

### Help

Always start with the help.

```bash
crowdstrike-falcon-downloader --help
```

### Navigation

1. Arrow keys will move up/down to select a new row in the list.
1. Pressing enter/return will download that package.

### View all available versions

```bash
crowdstrike-falcon-downloader
```

![All downloads](images/all@2x.png)

### View versions for Amazon Linux 2023

```bash
crowdstrike-falcon-downloader --amzn2023
```

![Amazon Linux 2023 downloads](images/amzn2023-all@2x.png)

### View versions for Amazon Linux 2023 on 64-bit Intel-compatible chips

```bash
crowdstrike-falcon-downloader --amzn2023 --intel64
```

![Amazon Linux 2023 downloads](images/amzn2023-intel64@2x.png)

### View the latest version for Amazon Linux 2023 on 64-bit Intel-compatible chips

```bash
crowdstrike-falcon-downloader --amzn2023 --intel64 --latest
```

![Amazon Linux 2023 downloads](images/amzn2023-intel64-latest@2x.png)

### Download the latest version for Amazon Linux 2023 on 64-bit Intel-compatible chips

```bash
crowdstrike-falcon-downloader --amzn2023 --intel64 --latest --download
```

If your filtering has resulted in a single package being matched (i.e., OS-flag + CPU-flag + latest), passing the `--download` flag will download that package automatically.
