<img src="images/scandy-180x180.png" align="right" width="150" height="150" />

# scandy
> Sweet container image scans

Images are scanned every day at 5:30am ET after updating all of the
base image packages.  See the [scheduled github actions
tasks](https://github.com/atgreen/scandy/blob/main/.github/workflows/scan.yaml)
for details.

Reports are available here: https://atgreen.github.io/scandy/

The risk assessment reports include experimental LLM-generated content
and should be cross-checked for accuracy!

The raw scan results data is archived as OCI artifacts in the github
OCI registry, and are available for download using
[`oras`](https://oras.land).  See the complete list here:
https://github.com/atgreen?tab=packages&repo_name=scandy.

For example, download the `ubi9` scans from 2024-06-24 like so:
```
green@fedora:/home/green$ oras pull ghcr.io/atgreen/registry.access.redhat.com--ubi9-with-updates:20240624
Downloading 80ccb19e7032 registry.access.redhat.com--ubi9-with-updates-scandy.tar.gz
Downloaded  80ccb19e7032 registry.access.redhat.com--ubi9-with-updates-scandy.tar.gz
Pulled [registry] ghcr.io/atgreen/registry.access.redhat.com--ubi9-with-updates:20240624
Digest: sha256:f919b5198e58711c0bde4faddf35dbc4ddb762cf5bc7fafdb5432fef9c2ea954
green@fedora:/home/green$ tar tvf registry.access.redhat.com--ubi9-with-updates-scandy.tar.gz
drwxr-xr-x runner/docker     0 2024-06-24 12:41 ubi9/
drwxr-xr-x runner/docker     0 2024-06-24 12:41 ubi9/trivy/
-rw-r--r-- runner/docker 512819 2024-06-24 12:41 ubi9/trivy/registry.access.redhat.com--ubi9-with-updates.json
drwxr-xr-x runner/docker      0 2024-06-24 12:41 ubi9/grype/
-rw-r--r-- runner/docker 721240 2024-06-24 12:41 ubi9/grype/registry.access.redhat.com--ubi9-with-updates.json
```

## Author and License

Scandy is an experiment by [Anthony
Green](https://github.com/atgreen), and is licensed under the terms of
the MIT license.  See source files for details.
