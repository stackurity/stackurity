### Security

- **nginx in the official nginx Alpine images is checked against nginx's own advisories.** Images built from `nginx:*-alpine` install nginx from nginx.org's apk repository, but the package was matched against Alpine's advisories, which describe Alpine's own builds. So nginx 1.27.5 on Alpine 3.21 looked fixed (Alpine's fix is 1.26.3-r4), and nginx on an end-of-life Alpine release matched nothing: nginx2root and other nginx vulnerabilities were missed. The agent and image scans now record each apk's aports build commit and maintainer. An apk that Alpine did not build counts as another repository's build: nginx is matched by its upstream version against NVD, like nginx.org's deb and rpm packages, and other such packages are marked unsupported with the reason. Update the agent to get this; older agents' rows stay matched as Alpine's builds. See [Compatibility](docs/compatibility.md#nginxorgs-packages-in-alpine-images).

### Changed

- **The nginx2root threat notice needs Stackurity 0.20.37 or later on Docker hosts and agents.** Its check now covers nginx.org's packages in Alpine images, so assets last checked by an older agent or image scan count as not checked yet, and the notice says to update them rather than reporting them as covered.
