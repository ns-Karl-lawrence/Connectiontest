# Connection Test Suite v2.0

A comprehensive PowerShell connectivity testing tool for Microsoft services and third-party applications. Features an interactive menu, detailed progress output, and robust error handling.

## Requirements

- **PowerShell Version:** 4.0 or higher
- **Operating System:** Windows (tested on Windows 10/11, Server 2016+)
- **Permissions:** Run as Administrator for accurate results (especially for Defender ATP tests)

## Quick Start

### Download and Run from PowerShell

Pick the option that matches how you prefer to obtain the script:

1. **Save locally (recommended):**

   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ns-Karl-lawrence/Connectiontest/main/Connectiontest.ps1" -OutFile ".\Connectiontest.ps1"
   .\Connectiontest.ps1
   ```

2. **One-liner (Windows PowerShell 5.1):** Downloads to `%TEMP%` and runs immediately.

   ```powershell
   powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ns-Karl-lawrence/Connectiontest/main/Connectiontest.ps1' -OutFile $env:TEMP\Connectiontest.ps1; & $env:TEMP\Connectiontest.ps1"
   ```

3. **One-liner (PowerShell 7+ / pwsh):**

   ```powershell
   pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ns-Karl-lawrence/Connectiontest/main/Connectiontest.ps1' -OutFile $env:TEMP/Connectiontest.ps1; & $env:TEMP/Connectiontest.ps1"
   ```

4. **Run without saving (only if you already trust/reviewed the code):**

   ```powershell
   iex (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ns-Karl-lawrence/Connectiontest/main/Connectiontest.ps1" -UseBasicParsing).Content
   ```

5. **Download and run Windows Defender Antivirus test only:**

   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ns-Karl-lawrence/Connectiontest/main/Connectiontest.ps1" -OutFile ".\Connectiontest.ps1"
   .\Connectiontest.ps1 -MenuChoice 3
   ```

6. **Download and run with parameters (Save to CSV):**

   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ns-Karl-lawrence/Connectiontest/main/Connectiontest.ps1" -OutFile ".\Connectiontest.ps1"
   .\Connectiontest.ps1 -MenuChoice 11 -SavePath "C:\Reports\connectivity-results.csv"
   ```

7. **One-liner with parameters (PowerShell 5.1):**

   ```powershell
   powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "& {Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/ns-Karl-lawrence/Connectiontest/main/Connectiontest.ps1' -OutFile $env:TEMP\ct.ps1; & $env:TEMP\ct.ps1 -MenuChoice 2 -SavePath 'C:\temp\wupdate-test.csv'}"
   ```

8. **Run from memory with parameters (no saving to disk):**

   ```powershell
   & ([ScriptBlock]::Create((Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ns-Karl-lawrence/Connectiontest/main/Connectiontest.ps1" -UseBasicParsing).Content)) -MenuChoice 3 -SavePath "C:\temp\defender-results.csv"
   ```

### Interactive Mode (Menu)

```powershell
.\Connectiontest.ps1
```

### Command-Line Mode (Skip Menu)

```powershell
# Run a specific test
.\Connectiontest.ps1 -MenuChoice 1

# Run all tests and save results
.\Connectiontest.ps1 -MenuChoice 12 -SavePath "C:\temp\connectivity_results.csv"
```

## Parameters

- **`-MenuChoice`** *(Int 0-12, optional)* – Skip the menu and run a specific test directly.
- **`-SavePath`** *(String, optional)* – Save CSV output to the provided path.

## Available Tests

- **Microsoft Connectivity** – DNS + TCP tests for 50+ Microsoft endpoints (Windows Update, M365, Azure AD, Teams, Intune, OneDrive, etc.).
- **Windows Update** – HTTP connectivity to Windows Update services and CDNs.
- **Windows Defender Antivirus** – MAPS, definition updates, CRL, and telemetry endpoints.
- **Windows Defender ATP** – Advanced Threat Protection endpoints, Security Center.
- **Windows Defender SmartScreen** – SmartScreen URL reputation services.
- **Windows Telemetry** – Diagnostic data and Windows Error Reporting endpoints.
- **Azure AD SSPR** – Self-Service Password Reset endpoints.
- **Chrome Updates** – Google Chrome update servers.
- **Firefox Updates** – Mozilla Firefox update and add-on servers.
- **Adobe Updates** – Adobe Reader/Acrobat update servers.
- **Package Managers** – Windows Package Manager (winget), PowerShell Gallery, and Chocolatey.
- **Run ALL Tests** – Execute all 11 tests sequentially.
- **Exit** – Exit the application.

## Usage Examples

### Example 1: Interactive Menu

```powershell
PS C:\> .\Connectiontest.ps1

================================================
        CONNECTION TEST SUITE v2.0
================================================

  [1] Microsoft Connectivity (DNS/TCP)
  [2] Windows Update (HTTP)
  [3] Windows Defender Antivirus
  ...
  [11] Package Managers (winget/choco/PSGallery)
  [12] Run ALL Tests

  [0] Exit

================================================
Enter your choice (0-12): 
```

### Example 2: Test Microsoft Connectivity Only

```powershell
.\Connectiontest.ps1 -MenuChoice 1
```

**Output:**

```powershell
[2024-02-09 09:15:00] [INFO] Starting Microsoft connectivity tests (40 endpoints)
================================================
  MICROSOFT CONNECTIVITY TEST
  Endpoints: 40 | Ports: 443
================================================

[1/40] Testing microsoft.com (General)...
  DNS: Resolved to 20.112.250.133
  TCP Port 443: OPEN

[2/40] Testing Windows Update (Generic)...
  DNS: Resolved to 13.107.4.50
  TCP Port 443: OPEN
...

================================================
  TEST SUMMARY
================================================
  Total Endpoints:  40
  Successful:       38
  Failed:           2
  Duration:         01:23
================================================
```

### Example 3: Run All Tests with CSV Export

```powershell
.\Connectiontest.ps1 -MenuChoice 12 -SavePath "C:\Reports\connectivity.csv"
```

### Example 4: Windows Update Connectivity Check

```powershell
.\Connectiontest.ps1 -MenuChoice 2
```

**Output:**

```powershell
[2024-02-09 09:20:00] [INFO] Starting Windows Update connectivity test
================================================
  WINDOWS UPDATE CONNECTIVITY TEST
  Endpoints: 15
================================================

  Results: 14 OK, 1 blocked/failed
  Duration: 00:45
[2024-02-09 09:20:45] [SUCCESS] Windows Update test completed: 14 passed, 1 blocked
```

### Example 5: Package Manager Connectivity

```powershell
.\Connectiontest.ps1 -MenuChoice 11 -SavePath "C:\Reports\package-managers.csv"
```

**Tests:**
- Windows Package Manager (winget) – GitHub API, Microsoft CDNs
- PowerShell Gallery – Module downloads
- Chocolatey – Package repository access

### Example 6: Save Microsoft Connectivity Results to CSV

```powershell
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$path = "C:\Reports\microsoft-connectivity-$timestamp.csv"
.\Connectiontest.ps1 -MenuChoice 1 -SavePath $path
Get-Item $path
```

- Uses `-MenuChoice 1` to target the Microsoft test directly.
- Adds `-SavePath` so the CSV is stored with a timestamped filename for auditing.
- `Get-Item` confirms where the CSV landed.

### Example 7: Run All Tests Headless and Export JSON

```powershell
$results = .\Connectiontest.ps1 -MenuChoice 12
$results | ConvertTo-Json -Depth 4 | Out-File "C:\Reports\connectivity.json"
```

- `-MenuChoice 12` skips the menu and runs every test.
- Captured output can be exported to JSON for ingestion in other systems.

### Example 8: Scheduled Task Compatible Command

```powershell
powershell.exe -File "C:\Tools\Connectiontest.ps1" -MenuChoice 12 -SavePath "C:\Reports\daily-connectivity.csv"
```

- Suitable for Task Scheduler or RMM tools.
- Combines both parameters so the job is non-interactive and produces an artifact automatically.

## Output Format

### Console Output

- **Color-coded results:** Green (success), Yellow (warning), Red (error)
- **Progress bars** for long-running operations
- **Timestamped log messages** with severity levels (INFO, WARN, ERROR, SUCCESS, DEBUG)
- **Summary statistics** after each test

### CSV Export (when using `-SavePath`)

Results include:

- `TestUrl` - The URL tested
- `UnblockUrl` - URL pattern to unblock
- `Description` - Endpoint description
- `Resolved` - DNS resolution success (True/False)
- `IpAddresses` - Resolved IP addresses
- `ActualStatusCode` - HTTP response code
- `ExpectedStatusCode` - Expected response code
- `Blocked` - Whether the endpoint is blocked (True/False)

## Microsoft Endpoints Tested (Choice 1)

The Microsoft Connectivity test checks DNS and TCP port 443 for 50+ endpoints including:

### Windows Update & Delivery Optimization

- `windowsupdate.com`
- `update.microsoft.com`
- `download.windowsupdate.com`
- `delivery.mp.microsoft.com`
- `ctldl.windowsupdate.com`
- `fe2.update.microsoft.com`
- `sls.update.microsoft.com`

### Microsoft 365 / Office 365

- `login.microsoftonline.com`
- `graph.microsoft.com`
- `outlook.office365.com`
- `teams.microsoft.com`
- `portal.office.com`
- `admin.microsoft.com`
- `officecdn.microsoft.com`

### OneDrive for Business

- `onedrive.live.com`
- `api.onedrive.com`
- `g.live.com`
- `admin.sharepoint.com`

### Microsoft Intune / Endpoint Manager / AutoPilot

- `manage.microsoft.com`
- `enrollment.manage.microsoft.com`
- `adrs.manage.microsoft.com`
- `ztd.dds.microsoft.com` (AutoPilot)
- `configmgr.manage.microsoft.com` (Co-management)
- `devicemanagement.microsoft.com`
- `enterprise.appcatalog.microsoft.com`

### Azure Active Directory

- `login.windows.net`
- `graph.windows.net`

### Telemetry & Diagnostics

- `vortex.data.microsoft.com`
- `vortex-win.data.microsoft.com`
- `telemetry.microsoft.com`
- `settings-win.data.microsoft.com`

### Certificate Services

- `mscrl.microsoft.com`
- `ocsp.digicert.com`
- `crl3.digicert.com`
- `crl4.digicert.com`

### Other Services

- `time.windows.com` (NTP)
- `www.msftconnecttest.com` (NCSI)

## Troubleshooting

### Common Issues

#### 1. "Access Denied" errors

```powershell
# Run PowerShell as Administrator
Start-Process powershell -Verb RunAs
```

#### 2. Script execution policy

```powershell
# Allow script execution (run as Admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 3. Defender ATP test warnings about SYSTEM account

- For most accurate results, run the ATP test as the SYSTEM account or as a regular user depending on your proxy configuration

#### 4. Timeout errors

- May indicate network issues or firewall blocking
- Check proxy settings if behind a corporate proxy

#### Reading Results

- ✅ **OPEN/OK** – Endpoint is reachable.
- ⚠️ **CLOSED/TIMEOUT** – Port not responding (may be blocked).
- ❌ **FAILED** – DNS or connection error.
- 🔒 **Blocked** – Endpoint blocked by proxy/firewall.

## Integration with Other Tools

### Export to JSON

```powershell
# Run test and capture results
$results = .\Connectiontest.ps1 -MenuChoice 2

# Export to JSON
$results | ConvertTo-Json -Depth 3 | Out-File "results.json"
```

### Filter Blocked Endpoints

```powershell
$results = .\Connectiontest.ps1 -MenuChoice 12
$blocked = $results | Where-Object { $_.Blocked -eq $true }
$blocked | Format-Table TestUrl, Description, ActualStatusCode
```

## Version History

- **2.0** – Added comprehensive error handling, progress tracking, logging functions, and HTTP test wrapper.
- **1.0** – Initial release with basic connectivity tests.

## License

Internal use only.

## Support

For issues or feature requests, contact your IT administrator.
