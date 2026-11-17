#!/usr/bin/env bash
# Ghost-Cloud Installer
# By Gh0st-Bx1 | github.com/Ghost-Bx1

G="\033[92m"; Y="\033[93m"; R="\033[91m"; C="\033[96m"
W="\033[97m"; D="\033[2m"; N="\033[1m"; X="\033[0m"
EQ="════════════════════════════════════════════════════════════════════"
HL="────────────────────────────────────────────────────────────────────"

banner() {
    echo -e "${G}╔${EQ}╗${X}"
    echo -e "${G}║${X}                                                                    ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠛⠛⠿⠟⠉⠛⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠉⢀⣠⣤⣶⣶⣶⣶⣶⣶⣤⣀⠢⢝⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⡡⢀⣴⡿⢋⡴⢿⣿⣿⣿⣿⣿⣿⣿⢷⣦⡑⠈⡛⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⡜⢠⣾⣿⣤⣋⣴⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⠻⣶⣦⣤⣤⣀⠉⠻⣿⣿⣿⡿⠿⢛⢛⡻⠿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⠿⠟⠟⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⢀⣿⣿⣿⡿⠛⠛⠻⣿⣿⣿⡿⠛⠛⢿⣿⣿⣧⠉⠉⣁⣈⣉⣁⢀⣿⣿⢋⠄⣁⣴⣶⣄⠐⢌⢻⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⡏⠀⣴⣦⣄⠢⡙⢿⣿⣿⣿⣿⣿⣿⡇⠀⣼⣿⣿⣿⠅⠀⠀  ⢹⣿⡿⠁⠀⠀⠀⢹⣿⣿⡆⠀⣿⣿⣿⣿⣿⡟⠁⢀⣴⣿⣿⣿⣿⣷⡈⠎⢿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⡇⠀⣿⣿⣿⣷⣌⠀⠙⢿⣿⣿⣿⣿⠀⢀⣿⣿⣿⣿⠀⠀⠀  ⠀⠈⣿⡇⠀⠀⠀⠀⠈⢿⣿⡇⠁⢻⣿⣿⣿⡿⠁⢠⣾⣿⣿⣿⡿⢿⣿⣷⠀⠘⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣇⠀⢿⣿⣿⡟⣿⣷⣄⠀⠙⢿⣿⡇⠀⣸⣿⣿⡿⣿⡀⠀⠀⠀  ⢸⣿⣧⠀⠀⠀⠀⣸⡈⣿⣷⠀⡈⣿⣿⡿⠁⢀⣾⣿⣿⢩⣿⠁⣾⣿⣿⡆⠀⢿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⡀⠘⣿⣿⣿⡘⣿⣿⣷⣌⠂⠉⠁⢠⣿⣿⡟⣰⢿⣷⣤⣤⣴⣿⣿⣿⣷⣄⣠⣴⣿⣧⠸⣿⣧⡐⠢⠉⠁⢀⣾⣿⣿⡇⣼⣿⢸⣿⣿⣿⣇⠀⢸${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣷⡀⠸⣿⣿⣧⠸⣿⣿⣿⣿⣶⣶⣿⣿⠏⡰⢃⣾⣿⣿⣿⣿⡏⠀⠈⣿⣿⣿⣿⣿⣏⠳⣘⣿⣿⣷⣶⣾⣿⣿⣿⣿⢠⣿⣿⣿⣿⣿⣿⣿⠀⢸${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⡇⠀⣿⣿⣿⡄⡿⢿⣿⣿⣿⣿⣿⣷⣾⣷⣿⣿⣿⣿⣿⣿⣧⣀⣠⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⡇⠸⠋⢉⠉⡉⠛⠿⣿⠀⢸${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⡇⢀⣿⣿⣿⣧⢸⡘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⢠⣾⣿⡄⠈⠀⠀⠀⠀ ⣾${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⡟⠀⣸⣿⣿⣿⣿⣜⡇⢿⣧⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡉⠻⠇⠀⠰⠀⠀ ⣀⣾${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⠃⢠⣿⣿⠿⠿⠿⢿⣿⠸⣿⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⢣⢸⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⢰⠜⠋⠀⢀⡄⢰⣤⡀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠃⢻⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣆⠠⠀⡀⠀⠁⣿⣿⠟⠀⣽⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢻⣿⣿⣿⣿⣿⢃⣿⣿⣿⡟⣸⣿⣿⣿⣿⡿⠋⢠⢃⣾⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣷⣶⠆⡄⠈⢉⣠⣴⣾⣿⢿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢋⣴⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⠇⠛⢏⠉⠉⠁⠤⢊⣥⣾⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⢄⠀⢾⣿⣿⣿⣿⡇⢸⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣶⣬⣭⣶⣾⣿⣿⠏⣼⣿⣿⣿⡇⣸⣿⣿⣿⠀⣰⣿⡁⢠⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣤⣀⡀⠀⠀⠉⠉⠁⢸⣿⣿⣿⢸⣿⣿⣿⣿⡹⣿⣿⣿⣿⣿⣿⣿⣿⠋⣼⣿⣿⣿⣿⠇⣿⣿⣿⣿⡀⠹⢿⡇⠀⢿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠛⠀⣼⣿⣿⣿⢸⣿⣿⢻⣿⣷⣌⠻⣿⣿⣿⣿⠟⣡⣾⣿⡟⣼⣿⣿⠀⣿⣿⣿⣿⣿⣶⣤⡀⠀⢸⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⠈⠀⣴⣾⣿⣿⣿⡇⢸⣿⣿⣇⢻⣿⣿⣷⣦⣭⣭⣴⣾⣿⣿⣿⢡⣿⣿⣿⠀⣿⣿⣿⣿⣿⠿⠟⠃⡀⢸⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⡐⠠⢈⡉⠛⠛⠿⡇⢸⣿⣿⣿⡜⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣼⣿⣿⣿⠀⣁⣤⡄⠀⣀⣒⣀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⡌⠀⣦⠀⣼⣿⣿⣿⣇⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⣿⣿⣿⣿⣄⡈⠛⠃⠐⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⢁⣤⣿⣿⣿⣿⣿⠘⣿⣿⣿⣿⣿⣿⣿⣿⡟⢸⣿⣿⣿⣿⣿⣿⣦⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠠⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇⢼⠿⠿⣿⣿⣿⣿⠟⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠈⣙⠛⠛⣛⣛⠛⠀⠻⢿⣿⣿⣿⣿⣿⣿⡃⢠⣤⠀⠀⣀⣉⣁⣀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣶⣶⣶⣤⡀⢀⠈⢿⣿⣿⣿⣿⣷⣄⠁⠀⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠁⠈⣿⣿⣿⣿⣿⣿⡆⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠠⢠⣿⣿⣿⣿⣿⠟⢀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡗⠀⢸⣿⣿⣿⡿⢁⡄⣡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠰⠘⣿⣿⣿⠁⠎⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡑⠈⠻⠇⠈⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}       ${G}⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿${X}       ${G}║${X}"
    echo -e "${G}║${X}                                                                    ${G}║${X}"
    echo -e "${G}║${X}  ${G}${N}GHOST-CLOUD INSTALLER${X}                                             ${G}║${X}"
    echo -e "${G}║${X}  ${C}v2.0.0  ${D}Cloud Security Misconfiguration Scanner${X}                   ${G}║${X}"
    echo -e "${G}║${X}  ${D}${HL:0:44}${X}                      ${G}║${X}"
    echo -e "${G}║${X}  ${W}By Gh0st-Bx1  ${D}│  github.com/Ghost-Bx1${X}                             ${G}║${X}"
    echo -e "${G}║${X}  ${D}${HL:0:44}${X}                      ${G}║${X}"
    echo -e "${G}║${X}                                                                    ${G}║${X}"
    echo -e "${G}╚${EQ}╝${X}"
    echo
}

info()  { echo -e "  ${C}[*]${X} $*"; }
ok()    { echo -e "  ${G}[+]${X} $*"; }
warn()  { echo -e "  ${Y}[~]${X} $*"; }
err()   { echo -e "  ${R}[!]${X} $*"; }
step()  { echo -e "\n${G}  >${X} ${W}$*${X}"; }

banner

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/ghost-cloud"
INSTALL_BIN="/usr/local/bin/ghost-cloud"

if [[ $EUID -ne 0 ]]; then
    warn "Not running as root - installing to ~/.local"
    INSTALL_DIR="$HOME/.local/share/ghost-cloud"
    INSTALL_BIN="$HOME/.local/bin/ghost-cloud"
    mkdir -p "$HOME/.local/bin"
fi

step "Detecting system..."
PYTHON=$(command -v python3 || command -v python)
if [[ -z "$PYTHON" ]]; then
    err "Python 3 not found. Install python3 first."
    exit 1
fi
ok "Python: $($PYTHON --version 2>&1)"

step "Checking optional Python packages..."
for pkg in boto3 azure-identity google-auth; do
    PKG_IMPORT=$(echo "$pkg" | tr '-' '_')
    if $PYTHON -c "import $PKG_IMPORT" 2>/dev/null; then
        ok "$pkg available"
    else
        warn "$pkg not found - install with: pip install $pkg"
    fi
done
info "boto3: AWS SDK - enables deeper AWS checks"
info "azure-identity: Azure SDK - enables deeper Azure checks"
info "google-auth: GCP SDK - enables deeper GCP checks"
warn "Core checks work without any SDK (stdlib only)"

step "Installing ghost-cloud..."

mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/ghost-cloud.py" "$INSTALL_DIR/ghost-cloud.py"
chmod +x "$INSTALL_DIR/ghost-cloud.py"
ok "Copied ghost-cloud.py -> $INSTALL_DIR/"

[[ -f "$SCRIPT_DIR/README.md" ]] && cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"

mkdir -p "$(dirname "$INSTALL_BIN")"
cat > "$INSTALL_BIN" << WRAPPER
#!/usr/bin/env bash
exec python3 $INSTALL_DIR/ghost-cloud.py "\$@"
WRAPPER
chmod +x "$INSTALL_BIN"
ok "Wrapper created: $INSTALL_BIN"

if [[ $EUID -ne 0 ]]; then
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        warn "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
fi

step "Verifying installation..."
echo
if "$PYTHON" "$INSTALL_DIR/ghost-cloud.py" --no-banner --help &>/dev/null; then
    ok "ghost-cloud.py runs correctly"
else
    warn "ghost-cloud.py check returned non-zero (may be normal)"
fi

echo
echo -e "${G}  ╔══════════════════════════════════════╗${X}"
echo -e "${G}  ║${X}  ${G}${N}Installation complete!${X}              ${G}║${X}"
echo -e "${G}  ║${X}  ${D}Run:${X} ${W}ghost-cloud --help${X}               ${G}║${X}"
echo -e "${G}  ║${X}  ${D}Or:${X}  ${W}ghost-cloud aws --help${X}           ${G}║${X}"
echo -e "${G}  ╚══════════════════════════════════════╝${X}"
echo
