# wrapper to run gdb as root without requiring a password.
# run "sudo visudo" and append the following line (obviously, be careful with this):
# ALL     ALL = (ALL:ALL) NOPASSWD: /<full_path>/gdbsudo.sh
echo hi "$@"
[ `id -u` != 0 ] && exec sudo "$0" "$@" # restart as root
gdb "$@"
