# Runtime isolation contract

The Docker runner is a disposable execution boundary. Each call uses an immutable image digest, disables networking, mounts a read-only root filesystem, drops all Linux capabilities, enables `no-new-privileges`, limits processes, applies memory and CPU limits, and provides only a bounded `noexec`/`nosuid`/`nodev` tmpfs at `/tmp`. Credential leases are separate read-only mounts and are released by the credential provider after execution.

The runner writes a container ID file and verifies that the container no longer exists after normal completion. On timeout it kills the client process, explicitly removes the recorded container with `docker rm -f`, and verifies removal before reporting the timeout. Arguments are cleared and local container-ID artifacts are removed in both paths.

The Kubernetes gateway pod runs as a non-root user with the RuntimeDefault seccomp profile, no privilege escalation, a read-only root filesystem, all capabilities dropped, no service-account token, and explicit isolation from host network, PID, and IPC namespaces. The deployment uses an in-memory `/tmp` volume and bounded resource limits.

These controls reduce the MADVA application attack surface; they do not replace an independent assessment of the host kernel, container runtime, image provenance, orchestrator configuration, or workload-specific escape paths.
