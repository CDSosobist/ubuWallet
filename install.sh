#!/bin/sh
# Установка «Шкатулки» в домашний каталог пользователя (без sudo).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX="${PREFIX:-$HOME/.local}"
LIB="$PREFIX/lib/shkatulka"
APP="$LIB/app"
LEGACY_APP="$PREFIX/share/shkatulka/app"
BIN="$PREFIX/bin"
ICON_DIR="$PREFIX/share/icons/hicolor/scalable/apps"
APPS_DIR="$PREFIX/share/applications"
APP_ID="io.github.shkatulka.Shkatulka"

if [ ! -f "$ROOT/shkatulka/app.py" ]; then
    echo "Ошибка: install.sh должен находиться в каталоге проекта." >&2
    exit 1
fi

echo "Проверка зависимостей…"
if ! python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    print("Требуется Python 3.11 или новее.", file=sys.stderr)
    raise SystemExit(1)
try:
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Gtk, Adw  # noqa: F401
    import cryptography  # noqa: F401
    import argon2  # noqa: F401
except Exception as exc:
    print(f"Не хватает зависимости: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
then
    echo
    echo "Установите системные пакеты:" >&2
    echo "  sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 python3-cryptography python3-argon2" >&2
    exit 1
fi

echo "Копирование в $APP…"
# Code lives under lib/, data lives under share/shkatulka/.  Never delete
# the latter: it contains vault.shk.  The legacy share/shkatulka/app path is
# removed separately for upgrades.
rm -rf "$APP" "$LEGACY_APP"
mkdir -p "$APP" "$BIN" "$ICON_DIR" "$APPS_DIR"
cp -R "$ROOT/shkatulka" "$APP/shkatulka"
cp "$ROOT/README.md" "$APP/README.md" 2>/dev/null || true
cp "$ROOT/SECURITY.md" "$APP/SECURITY.md" 2>/dev/null || true
cp "$ROOT/LICENSE" "$APP/LICENSE" 2>/dev/null || true
find "$APP/shkatulka" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
find "$APP/shkatulka" -name '*.pyc' -delete 2>/dev/null || true

cat > "$BIN/shkatulka" <<'LAUNCHER'
#!/bin/sh
# Сгенерировано install.sh проекта «Шкатулка».
SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONPATH="$SELF_DIR/../lib/shkatulka/app${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -P -m shkatulka "$@"
LAUNCHER
chmod 755 "$BIN/shkatulka"

cp "$ROOT/shkatulka/resources/$APP_ID.svg" "$ICON_DIR/$APP_ID.svg"
chmod 644 "$ICON_DIR/$APP_ID.svg"

cat > "$APPS_DIR/$APP_ID.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Шкатулка
GenericName=Сейф паролей и карт
Comment=Локальное шифрованное хранилище паролей и данных банковских карт
Exec="$BIN/shkatulka"
Icon=$APP_ID
Terminal=false
Categories=Utility;Security;
Keywords=password;wallet;vault;карты;пароли;сейф;
StartupNotify=true
StartupWMClass=$APP_ID
DESKTOP
chmod 644 "$APPS_DIR/$APP_ID.desktop"

# Обновляем кэши, если инструменты доступны. Ошибки не критичны.
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" >/dev/null 2>&1 || true
fi

echo
echo "Готово. Запуск:"
echo "  $BIN/shkatulka"
echo "Также приложение появится в меню «Шкатулка»."
echo "Данные сейфа: ${XDG_DATA_HOME:-$HOME/.local/share}/shkatulka/vault.shk"
echo "Код установлен отдельно, в $APP."
