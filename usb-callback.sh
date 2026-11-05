#!/data/data/com.termux/files/usr/bin/sh
exec /data/data/com.termux/files/usr/bin/python "$(dirname "$0")/diagnostic.py" --fd "$1"
