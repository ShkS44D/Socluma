#!/usr/bin/env sh
set -eu
if [ "$#" -lt 2 ]; then
  echo "usage: install-linux.sh ENROLLMENT_TOKEN BACKEND_URL" >&2
  exit 2
fi
install_dir="${VIGILANTAI_INSTALL_DIR:-/opt/vigilantai-collector}"
state_dir="${VIGILANTAI_STATE_DIR:-/var/lib/vigilantai-collector}"
install -d -m 0750 "$install_dir"
install -d -m 0700 "$state_dir"
echo "Copy the signed collector package to $install_dir and enroll once against $2."
echo "Store the returned credential in a root-readable environment file (mode 0600); do not log it."
echo "Install the provided systemd unit with filesystem and privilege restrictions, then enable it."
