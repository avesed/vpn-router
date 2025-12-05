# Building for distribution

`rake artifacts` (or `rake all`) produces the final artifacts for distribution, including signing if code signing details are provided.  Code signing environment variables are defined below.

Build scripts in the `scripts` directory are also provided that clean, then build for all architectures supported on a given platform.

###  Windows

Set environment variables:

| Variable | Value |
|----------|-------|
| PIA_SIGNTOOL_CERTFILE | Path to certificate file (if signing with PFX archived cert) |
| PIA_SIGNTOOL_PASSWORD | Password to decrypt cert file (if signing with encrypted PFX archived cert) |
| PIA_SIGNTOOL_THUMBRPINT | Thumbprint of certificate - signs with cert from cert store instead of PFX archive |

Then call `rake BRAND=pia VARIANT=release all`

### Mac

Set environment variables:

| Variable | Value |
|----------|-------|
| PIA_CODESIGN_CERT | Common name of the signing certificate.  Must be the complete common name, not a partial match. |
| PIA_APPLE_ID_EMAIL | Apple ID used to notarize build. |
| PIA_APPLE_ID_PASSWORD | Password to Apple ID for notarization. |
| PIA_APPLE_ID_PROVIDER | (Optional) Provider to use if Apple ID is member of multiple teams. |

Then call `rake BRAND=pia VARIANT=release ARCHITECTURE=universal all`

A certificate is required for the Mac build to be installable (even for local builds), see below to generate a self-signed certificate for local use.  Unsigned builds can be manually installed by running the install script with `sudo`.

### Linux

#### PIA Linux build environment

All final artifacts shipped with PIA Desktop are now built using a Debian 11 Bullseye Docker container to maximize compatibility and ease of environment management.

Cross builds are still possible - release artifacts for armhf and arm64 are cross-compiled from an x86_64 host.

Instead of a chroot setup, we now utilize Docker containers. The Docker container can be set up with a single command, and you can enter the container environment as needed without special scripts. This approach simplifies the process and makes it more accessible across different systems.

The Qt installation must be in $HOME or /opt to be accessible in the Docker container. If this repository is not under $HOME, additional steps may be required to ensure it is accessible within the Docker environment.

#### Host architecture builds

Commands are executed from the `pia_desktop` repository root.
This setup supports `amd64`, `arm64`, and `armhf` hosts.
Additional architectures can be supported by adjusting the Docker container accordingly.

```shell
# Set up the Docker container:
$ docker build . -f .github/workflows/docker/linux_builder.dockerfile -t pia_builder:latest
$ docker run -it pia_builder:latest bash
# Now, build inside Docker:
$$ rake VARIANT=release BRAND=pia all
```

#### Cross builds

This example uses an x86_64 host to build `arm64` (64 bit); `armhf` is also supported (32-bit hard float).

We build in much the same way as a host architecture build, only using the arm builder docker image with the corresponding arm architecture:

```shell
# Set up the Docker container:
$ ARM_ARCH=arm64 # Can be arm64 or armhf
$ docker build . -f .github/workflows/docker/linux_arm_builder.dockerfile --build-arg="CROSS_ARCH=${ARM_ARCH}" -t pia_${ARM_ARCH}_builder:latest
$ docker run --mount type=bind,source="$(pwd)",target=/pia -e ARM_ARCH=${ARM_ARCH} -it pia_${ARM_ARCH}_builder:latest bash
# Now, build inside Docker:
$$ rake VARIANT=release BRAND=pia ARCHITECTURE=${ARM_ARCH} all
```

