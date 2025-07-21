# Workflows Overview

1. Build and Push containers to GHCR

Trigger: Runs on push events when changes are made to:

- decret/decret.py
- decret/Dockerfile.template
- .github/workflows/build-and-push.yml

What it does:

- Builds Docker images for multiple CVEs on different distros.
- Tags and pushes the images to GitHub Container Registry (GHCR).

Other CVEs can be quickly added under the ***"matrix:"*** part.

and images can be retrieved like so:
```docker pull ghcr.io/<repo_owner>/decret/<cve-xxxx-xxxx>:latest ```

To test feature branches, the branch name should be added under the ***"branches:"*** section

There's no setup needed for this, as it uses ***GITHUB_TOKEN***,
which has permissions to authenticate to GHCR. Permissions are declared
under the ***"permissions:"*** part


2. Trivy CVE Tests

Trigger: Runs after the successful completion of Build and Push containers to GHCR workflow.

 What it does:
- Runs Trivy vulnerability scans on the pushed Docker images for each CVE.
- Checks that the expected CVE is reported in the scan results.

Important Warning:

Even if Trivy reports a container as affected by a CVE, it does not necessarily mean the container is truly vulnerable. Manual verification is required to confirm actual vulnerability.
