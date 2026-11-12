### Added

- **`pkg/engine`: `RunningContainersWith` can take each running image's archive from the caller.** `ContainerOptions.Export` supplies the archive (what `docker save` writes) in place of the Docker engine's export, so a program that also reads the archive itself, such as stackurity-scan's key scan of every layer, exports each image once instead of twice. `RunningContainers` is unchanged.
