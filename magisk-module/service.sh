MODDIR="${0%/*}"
if ! magisk --denylist exec true; then
    exit 0
fi
chmod 755 "$MODDIR/magiskhide"
MAGISKTMP="$(magisk --path)" "$MODDIR/magiskhide"