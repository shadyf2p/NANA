$ErrorActionPreference = "Stop"

Write-Host "[1/3] Installing build dependencies..."
py -3.13 -m pip install pyarmor==9.0.7 pyinstaller==6.10.0

Write-Host "[2/3] Obfuscating secure_client.py ..."
pyarmor gen --assert-call --mix-str --enable-jit --private "secure_client.py"

Write-Host "[3/3] Building onefile executable ..."
pyinstaller --onefile --noconsole "dist/secure_client/secure_client.py"

Write-Host "Done. Check dist/secure_client.exe"
