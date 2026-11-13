#!/bin/bash

set -e

PROJECT="${KG_HOME:-$HOME/kernelguard}"
# user-local library dir for the root-run reader (override with KG_LIBDIR)
OWNER_HOME="$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)"
LIBDIR="${KG_LIBDIR:-$OWNER_HOME/.local/lib64}"
BPF_DIR="$PROJECT/ebpf"
BPF_OBJ="$BPF_DIR/exec_monitor.bpf.o"
READER="$BPF_DIR/kernelguard_reader"

BPF_FS="/sys/fs/bpf"
PROGRAM_PIN="$BPF_FS/kernelguard_test"
RINGBUF_PIN="$BPF_FS/kernelguard_events"

echo "=========================================="
echo " KernelGuard Permanent Setup"
echo "=========================================="

# --------------------------------------------------
# 1. Check required files
# --------------------------------------------------

if [ ! -f "$BPF_OBJ" ]; then
    echo "[ERROR] BPF object not found:"
    echo "$BPF_OBJ"
    exit 1
fi

if [ ! -x "$READER" ]; then
    echo "[ERROR] KernelGuard reader not found/executable:"
    echo "$READER"
    exit 1
fi

echo "[OK] BPF object found"
echo "[OK] KernelGuard reader found"

# --------------------------------------------------
# 2. Find bpftool
# --------------------------------------------------

BPFTool=$(command -v bpftool)

if [ -z "$BPFTool" ]; then
    echo "[ERROR] bpftool not found"
    exit 1
fi

echo "[OK] bpftool: $BPFTool"

# --------------------------------------------------
# 3. Stop existing KernelGuard services
# --------------------------------------------------

echo "[*] Stopping old KernelGuard services..."

systemctl stop kernelguard-reader.service 2>/dev/null || true
systemctl stop kernelguard-ebpf.service 2>/dev/null || true

# Stop manually running reader if any
pkill -f "$READER" 2>/dev/null || true

# --------------------------------------------------
# 4. Make sure BPF filesystem exists
# --------------------------------------------------

mkdir -p "$BPF_FS"

if ! mountpoint -q "$BPF_FS"; then
    echo "[*] Mounting BPF filesystem..."
    mount -t bpf bpf "$BPF_FS"
fi

echo "[OK] BPF filesystem ready"

# --------------------------------------------------
# 5. Remove old pins
# --------------------------------------------------

rm -f "$PROGRAM_PIN" 2>/dev/null || true
rm -f "$RINGBUF_PIN" 2>/dev/null || true

echo "[OK] Old KernelGuard pins cleaned"

# --------------------------------------------------
# 6. Create permanent BPF startup script
# --------------------------------------------------

cat > "$PROJECT/scripts/start_kernelguard.sh" <<SCRIPT
#!/bin/bash

set -e

BPF_DIR="$PROJECT/ebpf"
BPF_OBJ="\$BPF_DIR/exec_monitor.bpf.o"

BPF_FS="/sys/fs/bpf"
PROGRAM_PIN="\$BPF_FS/kernelguard_test"
RINGBUF_PIN="\$BPF_FS/kernelguard_events"

BPFTool="$BPFTool"

echo "[KernelGuard] Starting..."

# Make sure BPF filesystem is mounted
mkdir -p "\$BPF_FS"

if ! mountpoint -q "\$BPF_FS"; then
    mount -t bpf bpf "\$BPF_FS"
fi

# Remove old pins
rm -f "\$PROGRAM_PIN" 2>/dev/null || true
rm -f "\$RINGBUF_PIN" 2>/dev/null || true

echo "[KernelGuard] Loading BPF-LSM program..."

"\$BPFTool" prog load "\$BPF_OBJ" \
    "\$PROGRAM_PIN" \
    type lsm autoattach

echo "[KernelGuard] BPF-LSM program loaded"

# Find ring buffer map called 'events'
MAP_ID=\$("\$BPFTool" map show | \
    awk '\$2 == "ringbuf" && \$3 == "name" && \$4 == "events" {
        gsub(":", "", \$1);
        print \$1;
        exit
    }')

if [ -z "\$MAP_ID" ]; then
    echo "[KernelGuard] ERROR: events ring buffer not found"
    exit 1
fi

echo "[KernelGuard] Ring buffer map ID: \$MAP_ID"

# Pin ring buffer
"\$BPFTool" map pin id "\$MAP_ID" "\$RINGBUF_PIN"

echo "[KernelGuard] Ring buffer pinned"
echo "[KernelGuard] Startup complete"
SCRIPT

chmod +x "$PROJECT/scripts/start_kernelguard.sh"

echo "[OK] Permanent BPF startup script created"

# --------------------------------------------------
# 7. Create eBPF systemd service
# --------------------------------------------------

cat > /etc/systemd/system/kernelguard-ebpf.service <<SERVICE
[Unit]
Description=KernelGuard eBPF-LSM Runtime Monitor
After=local-fs.target
Before=kernelguard-reader.service

[Service]
Type=oneshot
ExecStart=$PROJECT/scripts/start_kernelguard.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

echo "[OK] kernelguard-ebpf.service created"

# --------------------------------------------------
# 8. Create reader systemd service
# --------------------------------------------------

cat > /etc/systemd/system/kernelguard-reader.service <<SERVICE
[Unit]
Description=KernelGuard User Space Security Reader
Requires=kernelguard-ebpf.service
After=kernelguard-ebpf.service

[Service]
Type=simple
WorkingDirectory=$PROJECT/ebpf
Environment="LD_LIBRARY_PATH=$LIBDIR"
ExecStart=$PROJECT/ebpf/kernelguard_reader
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

echo "[OK] kernelguard-reader.service created"

# --------------------------------------------------
# 9. Reload systemd
# --------------------------------------------------

systemctl daemon-reload

# --------------------------------------------------
# 10. Enable services permanently
# --------------------------------------------------

systemctl enable kernelguard-ebpf.service
systemctl enable kernelguard-reader.service

echo "[OK] Services enabled for boot"

# --------------------------------------------------
# 11. Start eBPF service now
# --------------------------------------------------

echo ""
echo "[*] Starting KernelGuard eBPF service..."

systemctl start kernelguard-ebpf.service

# --------------------------------------------------
# 12. Verify eBPF
# --------------------------------------------------

if [ ! -e "$RINGBUF_PIN" ]; then
    echo "[ERROR] Ring buffer was not pinned"
    systemctl status kernelguard-ebpf.service --no-pager
    exit 1
fi

if [ ! -e "$PROGRAM_PIN" ]; then
    echo "[ERROR] KernelGuard BPF program was not pinned"
    systemctl status kernelguard-ebpf.service --no-pager
    exit 1
fi

echo "[OK] BPF program is active"
echo "[OK] Ring buffer is active"

# --------------------------------------------------
# 13. Start reader
# --------------------------------------------------

echo ""
echo "[*] Starting KernelGuard reader..."

systemctl start kernelguard-reader.service

sleep 2

# --------------------------------------------------
# 14. Final verification
# --------------------------------------------------

echo ""
echo "=========================================="
echo " KernelGuard Status"
echo "=========================================="

systemctl --no-pager --full status kernelguard-ebpf.service || true

echo ""

systemctl --no-pager --full status kernelguard-reader.service || true

echo ""
echo "=========================================="
echo " BPF Filesystem"
echo "=========================================="

ls -l "$BPF_FS"

echo ""
echo "=========================================="
echo " KernelGuard Setup COMPLETE"
echo "=========================================="

echo ""
echo "After reboot, KernelGuard should start automatically."
echo ""
echo "To view reader logs:"
echo "sudo journalctl -u kernelguard-reader.service -f"
echo ""
echo "To check eBPF service:"
echo "sudo systemctl status kernelguard-ebpf.service"
echo ""
echo "To check reader:"
echo "sudo systemctl status kernelguard-reader.service"
