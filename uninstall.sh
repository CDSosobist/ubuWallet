#!/bin/sh
# Удаляет установленные файлы приложения, но НЕ трогает сейф с данными.
set -eu
PREFIX="${PREFIX:-$HOME/.local}"
LIB_APP="$PREFIX/lib/shkatulka/app"
LEGACY_APP="$PREFIX/share/shkatulka/app"
APP_ID="io.github.shkatulka.Shkatulka"
BIN="$PREFIX/bin/shkatulka"
DESKTOP="$PREFIX/share/applications/$APP_ID.desktop"
ICON="$PREFIX/share/icons/hicolor/scalable/apps/$APP_ID.svg"

printf 'Удалить установленную программу (сейф останется)? [y/N] '
read -r answer
case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "Отменено."; exit 0 ;;
esac

# Удаляем только код приложения. Каталог share/shkatulka содержит vault.shk
# и не должен удаляться.
rm -rf "$LIB_APP" "$LEGACY_APP"
rmdir "$PREFIX/lib/shkatulka" 2>/dev/null || true
rm -f "$BIN" "$DESKTOP" "$ICON"
echo "Программа удалена."
echo "Сейф не тронут: ${XDG_DATA_HOME:-$HOME/.local/share}/shkatulka/vault.shk"
