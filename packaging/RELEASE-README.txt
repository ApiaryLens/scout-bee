Scout Bee is the ApiaryLens installer, updater, recovery tool, and deployment manager.

Run the scout-bee executable from a user-owned folder. It opens its bundled guide in
your browser on a random loopback-only address. End users do not need Go, Node.js,
WSL, or a Linux shell.

Before running, verify the package SHA-256 and GitHub attestation against the
ApiaryLens/scout-bee repository and the matching immutable release tag.

Stable and RC Windows executables are Authenticode-signed. A Preview Windows file
whose name ends in -UNSIGNED-PREVIEW.exe is intentionally not Authenticode-signed;
use it only for Preview testing after checking the release warning, SHA-256, and
GitHub attestation. Linux archives rely on the checksum and repository attestation.

Scout Bee plans are secret-free. Enter credentials only into the running Scout Bee
application and never place them in a deployment plan or repository.
