#!/data/data/com.termux/files/usr/bin/sh
exec /data/data/com.termux/files/usr/bin/python "$(dirname "$0")/ecm_capture.py" --fd "$1" --execute
