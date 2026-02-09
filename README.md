# Connection Test Suite v2.0

A comprehensive PowerShell connectivity testing tool for Microsoft services and third-party applications. Features an interactive menu, detailed progress output, and robust error handling.

## Requirements

- **PowerShell Version:** 4.0 or higher
- **Operating System:** Windows (tested on Windows 10/11, Server 2016+)
- **Permissions:** Run as Administrator for accurate results (especially for Defender ATP tests)

## Quick Start

### Interactive Mode (Menu)

```powershell
.\Connectiontest_ps1.ps1
```

### Command-Line Mode (Skip Menu)

```powershell
# Run a specific test
.\Connectiontest_ps1.ps1 -MenuChoice 1

# Run all tests and save results
.\Connectiontest_ps1.ps1 -MenuChoice 11 -SavePath "C:\temp\connectivity_results.csv"
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-MenuChoice` | Int (0-11) | No | Skip menu and run specific test directly |
| `-SavePath` | String | No | Path to save results as CSV file |

## Available Tests

| Choice | Test Name | Description |
| ------- | --------- | ----------- |
| 1 | **Microsoft Connectivity** | DNS + TCP tests for 40+ Microsoft endpoints (Windows Update, M365, Azure AD, Teams, etc.) |
| 2 | **Windows Update** | HTTP connectivity to Windows Update services and CDNs |
| 3 | **Windows Defender Antivirus** | MAPS, definition updates, CRL, and telemetry endpoints |
| 4 | **Windows Defender ATP** | Advanced Threat Protection endpoints, Security Center |
| 5 | **Windows Defender SmartScreen** | SmartScreen URL reputation services |
| 6 | **Windows Telemetry** | Diagnostic data and Windows Error Reporting endpoints |
| 7 | **Azure AD SSPR** | Self-Service Password Reset endpoints |
| 8 | **Chrome Updates** | Google Chrome update servers |
| 9 | **Firefox Updates** | Mozilla Firefox update and add-on servers |
| 10 | **Adobe Updates** | Adobe Reader/Acrobat update servers |
| 11 | **Run ALL Tests** | Execute all 10 tests sequentially |
| 0 | **Exit** | Exit the application |

## Usage Examples

### Example 1: Interactive Menu

```powershell
PS C:\> .\Connectiontest_ps1.ps1

================================================
        CONNECTION TEST SUITE v2.0
================================================

  [1] Microsoft Connectivity (DNS/TCP)
  [2] Windows Update (HTTP)
  [3] Windows Defender Antivirus
  ...
  [11] Run ALL Tests

  [0] Exit

================================================
Enter your choice (0-11): 
```

### Example 2: Test Microsoft Connectivity Only

```powershell
.\Connectiontest_ps1.ps1 -MenuChoice 1
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
.\Connectiontest_ps1.ps1 -MenuChoice 11 -SavePath "C:\Reports\connectivity.csv"
```

### Example 4: Windows Update Connectivity Check

```powershell
.\Connectiontest_ps1.ps1 -MenuChoice 2
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

The Microsoft Connectivity test checks DNS and TCP port 443 for:

### Windows Update & Delivery Optimization

- `windowsupdate.com`
- `update.microsoft.com`
- `download.windowsupdate.com`
- `delivery.mp.microsoft.com`
- `ctldl.windowsupdate.com`

### Microsoft 365 / Office 365

- `login.microsoftonline.com`
- `graph.microsoft.com`
- `outlook.office365.com`
- `teams.microsoft.com`
- `portal.office.com`

### Azure Active Directory

- `login.windows.net`
- `graph.windows.net`

### Telemetry & Diagnostics

- `vortex.data.microsoft.com`
- `telemetry.microsoft.com`
- `settings-win.data.microsoft.com`

### Certificate Services

- `mscrl.microsoft.com`
- `ocsp.digicert.com`
- `crl3.digicert.com`

### Other Services

- `time.windows.com` (NTP)
- `www.msftconnecttest.com` (NCSI)
- `manage.microsoft.com` (Intune)

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

| Status | Meaning |
| ------- | ------- |
| ✅ **OPEN** / **OK** | Endpoint is reachable |
| ⚠️ **CLOSED/TIMEOUT** | Port not responding (may be blocked) |
| ❌ **FAILED** | DNS or connection error |
| 🔒 **Blocked** | Endpoint blocked by proxy/firewall |

## Integration with Other Tools

### Export to JSON

```powershell
# Run test and capture results
$results = .\Connectiontest_ps1.ps1 -MenuChoice 2

# Export to JSON
$results | ConvertTo-Json -Depth 3 | Out-File "results.json"
```

### Filter Blocked Endpoints

```powershell
$results = .\Connectiontest_ps1.ps1 -MenuChoice 11
$blocked = $results | Where-Object { $_.Blocked -eq $true }
$blocked | Format-Table TestUrl, Description, ActualStatusCode
```

## Version History

| Version | Changes |
|---------|---------|
| 2.0     | Added comprehensive error handling, progress tracking, logging functions, HTTP test wrapper |
| 1.0     | Initial release with basic connectivity tests |

## License

Internal use only.

## Support

For issues or feature requests, contact your IT administrator.
