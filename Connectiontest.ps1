#Requires -Version 4.0
<#
.SYNOPSIS
    Connection Test Suite - Menu-driven connectivity testing for Microsoft and third-party services.

.DESCRIPTION
    This script provides comprehensive HTTP connectivity testing with an interactive menu.
    Run with -MenuChoice parameter to skip menu or use interactively.

.PARAMETER MenuChoice
    Skip menu and run specific test:
    1=Microsoft (DNS/TCP), 2=Windows Update, 3=Defender AV, 4=Defender ATP,
    5=SmartScreen, 6=Telemetry, 7=AAD SSPR, 8=Chrome, 9=Firefox, 10=Adobe, 11=All

.PARAMETER SavePath
    Path to save results CSV file

.EXAMPLE
    .\Connectiontest.ps1

.EXAMPLE
    .\Connectiontest.ps1 -MenuChoice 1

.EXAMPLE
    .\Connectiontest.ps1 -MenuChoice 11 -SavePath ".\results.csv"

powershell -ExecutionPolicy Bypass -File "c:\temp\Connectiontest.ps1" -MenuChoice 11 -SavePath ".\results.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(0,11)]
    [int]$MenuChoice = 0,

    [Parameter(Mandatory=$false)]
    [string]$SavePath
)

Set-StrictMode -Version 4

#region Global Variables
$global:rateLimitCount = 0
$global:sleepSeconds = 5 * 60
$global:TestStartTime = $null
$global:TotalTestCount = 0
$global:CurrentTestIndex = 0
#endregion

#region Logging and Progress Functions

Function Write-LogMessage {
    <#
    .SYNOPSIS
    Writes a formatted log message with timestamp and level.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO','WARN','ERROR','DEBUG','SUCCESS')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory=$false)]
        [switch]$NoNewLine
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'INFO'    { 'White' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'DEBUG'   { 'Gray' }
        'SUCCESS' { 'Green' }
        default   { 'White' }
    }

    $prefix = "[$timestamp] [$Level]"
    if ($NoNewLine) {
        Write-Host "$prefix $Message" -ForegroundColor $color -NoNewline
    } else {
        Write-Host "$prefix $Message" -ForegroundColor $color
    }
}

Function Write-TestProgress {
    <#
    .SYNOPSIS
    Displays progress for the current test operation.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Activity,

        [Parameter(Mandatory=$false)]
        [string]$Status = '',

        [Parameter(Mandatory=$false)]
        [int]$CurrentOperation = 0,

        [Parameter(Mandatory=$false)]
        [int]$TotalOperations = 0,

        [Parameter(Mandatory=$false)]
        [switch]$Completed
    )

    if ($Completed) {
        Write-Progress -Activity $Activity -Completed
        return
    }

    $percentComplete = 0
    if ($TotalOperations -gt 0) {
        $percentComplete = [math]::Round(($CurrentOperation / $TotalOperations) * 100)
    }

    $progressParams = @{
        Activity = $Activity
        Status = $Status
        PercentComplete = $percentComplete
    }

    if ($CurrentOperation -gt 0 -and $TotalOperations -gt 0) {
        $progressParams.CurrentOperation = "Test $CurrentOperation of $TotalOperations"
    }

    Write-Progress @progressParams
}

Function Invoke-WithErrorHandling {
    <#
    .SYNOPSIS
    Executes a script block with comprehensive error handling.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$true)]
        [string]$OperationName,

        [Parameter(Mandatory=$false)]
        [switch]$ContinueOnError,

        [Parameter(Mandatory=$false)]
        $DefaultValue = $null
    )

    try {
        Write-LogMessage -Message "Starting: $OperationName" -Level 'DEBUG'
        $result = & $ScriptBlock
        Write-LogMessage -Message "Completed: $OperationName" -Level 'DEBUG'
        return $result
    }
    catch {
        $errorMessage = $_.Exception.Message
        $errorLine = $_.InvocationInfo.ScriptLineNumber
        Write-LogMessage -Message "Error in $OperationName at line $errorLine`: $errorMessage" -Level 'ERROR'
        
        if ($ContinueOnError) {
            Write-LogMessage -Message "Continuing despite error in $OperationName" -Level 'WARN'
            return $DefaultValue
        }
        throw
    }
}

#endregion

#region HTTP Test Wrapper Function

Function Invoke-HttpConnectivityTest {
    <#
    .SYNOPSIS
    Wrapper function to run HTTP connectivity tests with consistent error handling and progress.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$TestName,

        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[System.Collections.Hashtable]]$TestData,

        [Parameter(Mandatory=$false)]
        [switch]$PerformBluecoatLookup
    )

    $results = New-Object System.Collections.Generic.List[pscustomobject]
    $startTime = Get-Date

    Write-LogMessage -Message "Starting $TestName connectivity test" -Level 'INFO'
    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "  $($TestName.ToUpper()) CONNECTIVITY TEST" -ForegroundColor Cyan
    Write-Host "  Endpoints: $($TestData.Count)" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan

    try {
        $totalUrls = $TestData.Count
        $currentUrl = 0
        $successCount = 0
        $failCount = 0

        foreach ($testParams in $TestData) {
            $currentUrl++
            $urlDisplay = $testParams.TestUrl
            if ($urlDisplay.Length -gt 40) { $urlDisplay = $urlDisplay.Substring(0, 37) + "..." }
            
            Write-TestProgress -Activity "Testing $TestName Connectivity" -Status "[$currentUrl/$totalUrls] $urlDisplay" -CurrentOperation $currentUrl -TotalOperations $totalUrls
            
            try {
                Write-Verbose -Message "Testing: $($testParams.TestUrl)"
                $connectivity = Get-HttpConnectivity @testParams
                $results.Add($connectivity)
                
                if ($connectivity.Blocked) {
                    $failCount++
                } else {
                    $successCount++
                }
            }
            catch {
                $failCount++
                Write-LogMessage -Message "Error testing $($testParams.TestUrl): $($_.Exception.Message)" -Level 'WARN'
                
                # Add a failed result entry
                $results.Add([pscustomobject]@{
                    TestUrl = $testParams.TestUrl
                    UnblockUrl = $testParams.TestUrl
                    UrlType = 'HTTP'
                    Resolved = $false
                    IpAddresses = @()
                    DnsAliases = @()
                    Description = if ($testParams.Description) { $testParams.Description } else { '' }
                    ActualStatusCode = 0
                    ExpectedStatusCode = if ($testParams.ExpectedStatusCode) { $testParams.ExpectedStatusCode } else { 200 }
                    UnexpectedStatus = $true
                    StatusMessage = $_.Exception.Message
                    DetailedStatusMessage = $_.Exception.Message
                    Blocked = $true
                    ServerCertificate = $null
                    BlueCoat = $null
                })
            }
        }

        Write-TestProgress -Activity "Testing $TestName Connectivity" -Completed
    }
    catch {
        Write-LogMessage -Message "Critical error during $TestName connectivity test: $($_.Exception.Message)" -Level 'ERROR'
        Write-TestProgress -Activity "Testing $TestName Connectivity" -Completed
        throw
    }

    # Display summary
    $elapsed = (Get-Date) - $startTime
    $blockedCount = ($results | Where-Object { $_.Blocked -eq $true }).Count
    
    Write-Host ""
    Write-Host "  Results: $($results.Count - $blockedCount) OK, $blockedCount blocked/failed" -ForegroundColor $(if ($blockedCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "  Duration: $($elapsed.ToString('mm\:ss'))" -ForegroundColor White
    Write-LogMessage -Message "$TestName test completed: $($results.Count - $blockedCount) passed, $blockedCount blocked" -Level $(if ($blockedCount -gt 0) { 'WARN' } else { 'SUCCESS' })

    return $results
}

#endregion

#region Core HttpConnectivity Functions

Function Get-ErrorMessage() {
    <#
    .SYNOPSIS
    Gets a simple error message from an error record.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    Process {
        # Return just the essential error message
        return $ErrorRecord.Exception.Message
    }
}

Function Write-TestResult() {
    <#
    .SYNOPSIS
    Displays a clean test result line.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$TestUrl,

        [Parameter(Mandatory=$false)]
        [bool]$Resolved = $false,

        [Parameter(Mandatory=$false)]
        [int]$StatusCode = 0,

        [Parameter(Mandatory=$false)]
        [int]$ExpectedStatusCode = 200,

        [Parameter(Mandatory=$false)]
        [bool]$Blocked = $false,

        [Parameter(Mandatory=$false)]
        [string]$ErrorMessage = ''
    )

    $shortUrl = if ($TestUrl.Length -gt 50) { $TestUrl.Substring(0, 47) + "..." } else { $TestUrl }
    
    if (-not $Resolved) {
        Write-Host ("  [{0,-50}] " -f $shortUrl) -NoNewline
        Write-Host "DNS FAILED" -ForegroundColor Red
    }
    elseif ($Blocked) {
        Write-Host ("  [{0,-50}] " -f $shortUrl) -NoNewline
        Write-Host "BLOCKED" -ForegroundColor Red -NoNewline
        if ($ErrorMessage) {
            $shortError = if ($ErrorMessage.Length -gt 40) { $ErrorMessage.Substring(0, 37) + "..." } else { $ErrorMessage }
            Write-Host " - $shortError" -ForegroundColor DarkGray
        } else {
            Write-Host ""
        }
    }
    elseif ($StatusCode -eq $ExpectedStatusCode -or $StatusCode -in @(200, 301, 302, 400, 403, 404)) {
        Write-Host ("  [{0,-50}] " -f $shortUrl) -NoNewline
        Write-Host "OK ($StatusCode)" -ForegroundColor Green
    }
    else {
        Write-Host ("  [{0,-50}] " -f $shortUrl) -NoNewline
        Write-Host "UNEXPECTED ($StatusCode)" -ForegroundColor Yellow -NoNewline
        if ($ErrorMessage) {
            $shortError = if ($ErrorMessage.Length -gt 30) { $ErrorMessage.Substring(0, 27) + "..." } else { $ErrorMessage }
            Write-Host " - $shortError" -ForegroundColor DarkGray
        } else {
            Write-Host ""
        }
    }
}

Function Get-BlueCoatSiteReview() {
    [CmdletBinding()]
    [OutputType([psobject])]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Uri]$Url,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36',

        [Parameter(Mandatory=$false)]
        [switch]$NoThrottle
    )

    if ($Url.OriginalString.ToLower().StartsWith('http://') -or $Url.OriginalString.ToLower().StartsWith('https://')) {
        $testUri = $Url
    } else {
        $testUri = [Uri]('http://{0}' -f $Url.OriginalString)
    }

    $throttle = !$NoThrottle

    if ($throttle) {
        $global:rateLimitCount++

        if($global:rateLimitCount -gt 10) {
            $nowTime = [DateTime]::Now
            $resumeTime = $nowTime.AddSeconds($global:sleepSeconds)
            Write-Verbose -Message ('Paused for {0} seconds. Current time: {1} Resume time: {2}' -f $global:sleepSeconds,$nowTime,$resumeTime)
            Start-Sleep -Seconds $global:sleepSeconds
            $nowTime = [DateTime]::Now
            Write-Verbose -Message ('Resumed at {0}' -f $nowTime)
            $global:rateLimitCount = 1
        }
    }

    $uri = $testUri
    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $params = @{
        Uri = 'https://sitereview.bluecoat.com/resource/lookup';
        Method = 'POST';
        ProxyUseDefaultCredentials = (([string]$proxyUri) -ne $uri);
        UseBasicParsing = $true;
        UserAgent = $UserAgent;
        ContentType = 'application/json';
        Body = (@{url = $uri; captcha = ''} | ConvertTo-Json);
        Headers = @{Referer = 'https://sitereview.bluecoat.com'};
        Verbose = $false;
        TimeoutSec = 15
    }

    if (([string]$proxyUri) -ne $uri) {
       $params.Add('Proxy',$proxyUri)
    }

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
    $statusCode = 0
    $statusDescription = ''

    try {
        $response = Invoke-WebRequest @params
        $statusCode = $response.StatusCode
    } catch [System.Net.WebException] {
        $statusCode = [int]$_.Exception.Response.StatusCode
        $statusDescription = $_.Exception.Response.StatusDescription
    }

    if ($statusCode -ne 200) {
        throw "BlueCoat Site Review REST API request failed. Status code: $statusCode Status description: $statusDescription"
    }

    $returnedJson = $response.Content
    $siteReview = $returnedJson | ConvertFrom-Json

    if ($siteReview.PSObject.Properties.Name -contains 'errorType') {
        throw ('Error retrieving Blue Coat data. Error Type: {0} Error Message: {1}' -f $siteReview.errorType, $siteReview.error)
    }

    $cats = @{}
    $siteReview.categorization | ForEach-Object {
        $link = ('https://sitereview.bluecoat.com/catdesc.jsp?catnum={0}' -f $_.num)
        $cats.Add($_.name,$link)
    }

    $dateMatched = $siteReview.rateDate -match 'Last Time Rated/Reviewed:\s*(.+)\s*{{.*'
    $lastRated = ''

    if($dateMatched -and $matches.Count -ge 2) {
        $lastRated = $matches[1].Trim()
    }

    $siteReviewObject = [pscustomobject]@{
        SubmittedUri = $Uri;
        ReturnedUri = [System.Uri]$siteReview.url;
        Rated = $siteReview.unrated -eq 'false';
        LastedRated = $lastRated;
        Locked = $siteReview.locked -eq 'true';
        LockMessage = if ($siteReview.locked -eq 'true') {[string]$siteReview.lockedMessage} else {''};
        Pending = $siteReview.multiple -eq 'true';
        PendingMessage = if ($siteReview.multiple -eq 'true') {[string]$siteReview.multipleMessage} else {''};
        Categories = $cats;
    }

    return $siteReviewObject
}

Function Get-IPAddress() {
    <#
    .SYNOPSIS
    Gets the IP address(es) for a URL.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Uri]$Url
    )

    $addresses = [string[]]@()
    try {
        Write-Verbose -Message "Resolving IP address for $($Url.Host)"
        $dnsResults = $null
        $dnsResults = @(Resolve-DnsName -Name $Url.Host -NoHostsFile -Type A_AAAA -QuickTimeout -ErrorAction Stop | Where-Object {$_.Type -eq 'A'})
        $addresses = [string[]]@($dnsResults | ForEach-Object { try { $_.IpAddress } catch [System.Management.Automation.PropertyNotFoundException] {} })
        Write-Verbose -Message "Resolved $($Url.Host) to $($addresses -join ', ')"
    }
    catch [System.ComponentModel.Win32Exception] {
        Write-Verbose -Message "DNS resolution failed for $($Url.Host): $($_.Exception.Message)"
    }
    catch {
        Write-Verbose -Message "Unexpected error resolving $($Url.Host): $($_.Exception.Message)"
    }
    return ,$addresses
}

Function Get-DnsAlias() {
    <#
    .SYNOPSIS
    Gets DNS alias for a URL.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Uri]$Url
    )

    $aliases = [string[]]@()
    try {
        Write-Verbose -Message "Resolving DNS aliases for $($Url.Host)"
        $dnsResults = $null
        $dnsResults = @(Resolve-DnsName -Name $Url.Host -NoHostsFile -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'CNAME' })
        $aliases = [string[]]@($dnsResults | ForEach-Object { $_.NameHost })
        if ($aliases.Count -gt 0) {
            Write-Verbose -Message "Found aliases for $($Url.Host): $($aliases -join ', ')"
        }
    }
    catch [System.ComponentModel.Win32Exception] {
        Write-Verbose -Message "DNS alias lookup failed for $($Url.Host): $($_.Exception.Message)"
    }
    catch {
        Write-Verbose -Message "Unexpected error getting aliases for $($Url.Host): $($_.Exception.Message)"
    }
    return ,$aliases
}

Function Get-CertificateErrorMessage() {
    <#
    .SYNOPSIS
    Gets certificate error messages for an HTTPS URL.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Uri]$Url,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Security.Cryptography.X509Certificates.X509Certificate]$Certificate,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Chain,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Net.Security.SslPolicyErrors]$PolicyError
    )

    $details = ''

    if($PolicyError -ne [Net.Security.SslPolicyErrors]::None) {
        switch ($PolicyError) {
            'RemoteCertificateChainErrors' {
                if ($Chain.ChainElements.Count -gt 0 -and $Chain.ChainStatus.Count -gt 0) {
                    if ($Chain.ChainElements.Count -gt 1 -or $Chain.ChainStatus.Count -gt 1) {
                        Write-Verbose -Message ('Multiple remote certificate chain elements exist. ChainElement Count: {0} ChainStatus Count: {1}' -f $Chain.ChainElements.Count,$Chain.ChainStatus.Count)
                    }
                    $element = $Chain.ChainElements[0]
                    $status = $Chain.ChainStatus[0]
                    $details = ('Certificate chain error. Error: {0} Reason: {1} Certificate: {2}' -f $status.Status, $status.StatusInformation,$element.Certificate.ToString($false))
                } else {
                    $details = ('Certificate chain error. Certificate: {0}' -f $Certificate.ToString($false))
                }
                break
            }
            'RemoteCertificateNameMismatch' {
                $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Certificate
                $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }

                if ($null -eq $sanExtension) {
                    $subject = $cert.Subject.Split(',')[0].Replace('CN=', '')
                    $details = ('Remote certificate name mismatch. Host: {0} Subject: {1}' -f $Url.Host,$subject)
                } else {
                    $subject = $certificate.Subject.Split(',')[0].Replace('CN=', '')
                    $asnData = New-Object Security.Cryptography.AsnEncodedData -ArgumentList $sanExtension.Oid,$sanExtension.RawData
                    $sans = $asnData.Format($false).Replace('DNS Name=', '').Replace(',', '').Split(@(' '), [StringSplitOptions]::RemoveEmptyEntries)
                    $details = ('Remote certificate name mismatch. Host: {0} Subject: {1} SANs: {2}' -f $Url.Host,$subject,($sans -join ', '))
                }
                break
            }
            'RemoteCertificateNotAvailable' {
                $details = 'Remote certificate not available.'
            }
            'None' {
                break
            }
            default {
                $details = ('Unrecognized remote certificate error. {0}' -f $PolicyError)
                break
            }
        }
    }

    return $details
}

Function Get-HttpConnectivity() {
    <#
    .SYNOPSIS
    Gets HTTP connectivity information for a URL.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Uri]$TestUrl,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$UrlPattern,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('HEAD','GET', 'POST', IgnoreCase=$true)]
        [string]$Method = 'GET',

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Int32]$ExpectedStatusCode = 200,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36',

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreCertificateValidationErrors,

        [Parameter(Mandatory=$false)]
        [switch]$PerformBluecoatLookup
    )

    $parameters = $PSBoundParameters
    $isVerbose = $verbosePreference -eq 'Continue'

    if ($TestUrl.OriginalString.ToLower().StartsWith('http://') -or $TestUrl.OriginalString.ToLower().StartsWith('https://')) {
        $testUri = $TestUrl
    } else {
        $testUri = [Uri]('http://{0}' -f $TestUrl.OriginalString)
    }

    if($parameters.ContainsKey('UrlPattern')) {
        $UnblockUrl = $UrlPattern
    } else {
        $UnblockUrl = $testUri.OriginalString
    }

    $newLine = [System.Environment]::NewLine
    Write-Verbose -Message ('{0}*************************************************{1}Testing {2}{3}*************************************************{4}' -f $newLine,$newLine,$testUri,$newLine,$newLine)

    $script:ServerCertificate = $null
    $script:ServerCertificateChain = $null
    $script:ServerCertificateError = $null

    if($IgnoreCertificateValidationErrors) {
        $RemoteCertificateValidationCallback = {
            param([object]$senderObject, [Security.Cryptography.X509Certificates.X509Certificate]$certificate, [Security.Cryptography.X509Certificates.X509Chain]$chain, [Net.Security.SslPolicyErrors]$sslPolicyErrors)
            $script:ServerCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certificate
            $script:ServerCertificateChain = $chain | Select-Object *
            $script:ServerCertificateError = $sslPolicyErrors
            return $true
        }
    } else {
        $RemoteCertificateValidationCallback = {
            param([object]$senderObject, [Security.Cryptography.X509Certificates.X509Certificate]$certificate, [Security.Cryptography.X509Certificates.X509Chain]$chain, [Net.Security.SslPolicyErrors]$sslPolicyErrors)
            $script:ServerCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certificate
            $script:ServerCertificateChain = $chain | Select-Object *
            $script:ServerCertificateError = $sslPolicyErrors
            return [Net.Security.SslPolicyErrors]::None -eq $sslPolicyErrors
        }
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    $proxyUri = [Net.WebRequest]::GetSystemWebProxy().GetProxy($testUri)
    $request = [Net.WebRequest]::CreateHttp($testUri)
    $request.Proxy = if ($testUri -ne $proxyUri) { [Net.WebRequest]::DefaultWebProxy } else { $null }
    $request.UseDefaultCredentials = ($testUri -ne $proxyUri)
    $request.UserAgent = $UserAgent;
    $request.Method = $Method
    $request.ServerCertificateValidationCallback = $RemoteCertificateValidationCallback
    $request.Timeout = 15 * 1000

    $statusCode = 0
    $statusMessage = ''
    $response = $null

    $serverCertificateObject = [pscustomobject]@{
        Certificate = $null;
        Chain = $null;
        Error = $null;
        ErrorMessage = '';
        HasError = $false;
        IgnoreError = $false;
    }

    $address = Get-IPAddress -Url $testUri -Verbose:$false
    $alias = Get-DnsAlias -Url $testUri -Verbose:$false
    $resolved = (@($address)).Length -ge 1 -or (@($alias)).Length -ge 1

    if ($resolved) {
        try {
            $response = $request.GetResponse()
            $httpResponse = $response -as [Net.HttpWebResponse]
            $statusCode = $httpResponse.StatusCode
            $statusMessage = $httpResponse.StatusDescription
        } catch [System.Net.WebException] {
            $statusMessage = Get-ErrorMessage -ErrorRecord $_
            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
            } catch [System.Management.Automation.PropertyNotFoundException] {
                Write-Verbose -Message ('Unable to access {0} due to {1}' -f $testUri,$statusMessage)
            }
        } finally {
            if ($null -ne $response) {
                $response.Close()
            }
        }

        $hasServerCertificateError = if ($null -eq $script:ServerCertificateError) { $false } else { $script:ServerCertificateError -ne [Net.Security.SslPolicyErrors]::None }
        $hasServerCertificateValidationError = $false
        $serverCertificateValidationErrorMessage = ''

        if ($null -ne $script:ServerCertificate) {
            $hasServerCertificateValidationError = -not(Test-Certificate -Cert $script:ServerCertificate -Policy SSL -ErrorVariable serverCertificateValidationErrorMessage -ErrorAction SilentlyContinue)
        }

        $serverCertificateErrorMessage = ''
        if ($testUri.Scheme.ToLower() -eq 'https' -and $hasServerCertificateError) {
            $serverCertificateErrorMessage = Get-CertificateErrorMessage -Url $testUri -Certificate $script:ServerCertificate -Chain $script:ServerCertificateChain -PolicyError $script:ServerCertificateError
        }

        $serverCertificateObject = [pscustomobject]@{
            Certificate = $script:ServerCertificate | Select-Object -Property * -ExcludeProperty RawData;
            Chain = $script:ServerCertificateChain;
            Error = $script:ServerCertificateError;
            ErrorMessage = $serverCertificateErrorMessage;
            HasError = $hasServerCertificateError;
            IgnoreError = $IgnoreCertificateValidationErrors;
            HasValidationError = $hasServerCertificateValidationError;
            ValidationErrorMessage = if ($hasServerCertificateValidationError) { $serverCertificateValidationErrorMessage } else { '' }
        }
    }

    $actualStatusCode = [int]$statusCode
    $isBlocked = $statusCode -eq 0 -and $resolved
    $urlType = if ($UnblockUrl.Contains('*')) { 'Pattern' } else { 'Literal' }
    $isUnexpectedStatus = !($statusCode -in @(200,400,403,404,500,501,503,504))
    $simpleStatusMessage = if ($isUnexpectedStatus) { $statusMessage } else { '' }

    $bluecoat = $null
    if ($PerformBluecoatLookup) {
        try {
            $bluecoat = Get-BlueCoatSiteReview -Url $testUri -Verbose:$isVerbose
        } catch {
            Write-Verbose -Message $_
        }
    }

    $connectivity = [pscustomobject]@{
        TestUrl = $testUri;
        UnblockUrl = $UnblockUrl;
        UrlType = $urlType;
        Resolved = $resolved;
        IpAddresses = [string[]]$address;
        DnsAliases = [string[]]$alias;
        Description = $Description;
        ActualStatusCode = [int]$actualStatusCode;
        ExpectedStatusCode = $ExpectedStatusCode;
        UnexpectedStatus = $isUnexpectedStatus;
        StatusMessage = $simpleStatusMessage;
        DetailedStatusMessage = $statusMessage;
        Blocked = $isBlocked;
        ServerCertificate = $serverCertificateObject;
        BlueCoat = $bluecoat;
    }

    # Display clean test result
    Write-TestResult -TestUrl $testUri.ToString() -Resolved $resolved -StatusCode $actualStatusCode -ExpectedStatusCode $ExpectedStatusCode -Blocked $isBlocked -ErrorMessage $statusMessage

    return $connectivity
}

Function Save-HttpConnectivity() {
    <#
    .SYNOPSIS
    Saves HTTP connectivity objects to a JSON file.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,

        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[pscustomobject]]$Objects,

        [Parameter(Mandatory=$false)]
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [switch]$Compress
    )

    try {
        Write-LogMessage -Message "Saving connectivity results to JSON file..." -Level 'INFO'
        $parameters = $PSBoundParameters

        if (-not($parameters.ContainsKey('OutputPath'))) {
            $OutputPath = $env:USERPROFILE,'Desktop' -join [System.IO.Path]::DirectorySeparatorChar
        }

        $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

        if (-not(Test-Path -Path $OutputPath)) {
            Write-LogMessage -Message "Creating output directory: $OutputPath" -Level 'INFO'
            New-Item -Path $OutputPath -ItemType Directory -ErrorAction Stop | Out-Null
        }

        $filePath = "$OutputPath\$FileName.json"
        $json = $Objects | ConvertTo-Json -Depth 3 -Compress:$Compress
        $json | Out-File -FilePath $filePath -NoNewline -Force -ErrorAction Stop
        Write-LogMessage -Message "Results saved to: $filePath" -Level 'SUCCESS'
    }
    catch {
        Write-LogMessage -Message "Failed to save results: $($_.Exception.Message)" -Level 'ERROR'
        throw
    }
}

#endregion

#region Microsoft Connectivity Test

# Microsoft endpoints from MS_connecttest.ps1
$script:MSTargets = @(
    @{ Display = 'microsoft.com (General)';                      Host = 'microsoft.com' }

    # --- Windows Update & Delivery Optimization ---
    @{ Display = 'Windows Update (Generic)';                     Host = 'windowsupdate.com' }
    @{ Display = 'Windows Update Microsoft';                     Host = 'update.microsoft.com' }
    @{ Display = 'Windows Update Download';                      Host = 'download.windowsupdate.com' }
    @{ Display = 'Windows Update Auth';                          Host = 'wustat.windows.com' }
    @{ Display = 'Windows Update Servicing';                     Host = 'ntservicepack.microsoft.com' }
    @{ Display = 'Windows Update Go Link';                       Host = 'go.microsoft.com' }
    @{ Display = 'Windows Update (FE2)';                         Host = 'fe2.update.microsoft.com.akadns.net' }
    @{ Display = 'Windows Update CTLDL';                         Host = 'ctldl.windowsupdate.com' }
    @{ Display = 'Windows Update SLS';                           Host = 'sls.update.microsoft.com' }
    @{ Display = 'Delivery Optimization (MP)';                   Host = 'delivery.mp.microsoft.com' }
    @{ Display = 'Delivery Optimization (TLU)';                  Host = 'tlu.dl.delivery.mp.microsoft.com' }
    @{ Display = 'Delivery Optimization (Traffic Shaping)';      Host = 'tsfe.trafficshaping.dsp.mp.microsoft.com' }
    @{ Display = 'Delivery Optimization (Prod)';                 Host = 'prod.do.dsp.mp.microsoft.com' }
    @{ Display = 'Windows Update Download (AU)';                 Host = 'au.download.windowsupdate.com' }
    @{ Display = 'Windows Content CDN';                          Host = 'cdn.content.prod.cms.msn.com' }
    @{ Display = 'Windows Content (Legacy)';                     Host = 'content.windows.microsoft.com' }

    # --- Microsoft Store & App Updates ---
    @{ Display = 'Microsoft Store CDN';                          Host = 'store.rg-cdn.smcloud.net' }
    @{ Display = 'Microsoft Store Content CDN';                  Host = 'img-prod-cms-rt-microsoft-com.akamaized.net' }
    @{ Display = 'Microsoft Store Licensing';                    Host = 'licensing.mp.microsoft.com' }
    @{ Display = 'Display Catalog';                              Host = 'displaycatalog.mp.microsoft.com' }

    # --- Telemetry and Diagnostic Data ---
    @{ Display = 'Telemetry Vortex';                             Host = 'vortex.data.microsoft.com' }
    @{ Display = 'Telemetry Vortex (Win)';                       Host = 'vortex-win.data.microsoft.com' }
    @{ Display = 'Telemetry Core';                               Host = 'telemetry.microsoft.com' }
    @{ Display = 'Settings Windows Data';                        Host = 'settings-win.data.microsoft.com' }

    # --- Microsoft 365 / Office 365 (Core Services) ---
    @{ Display = 'Office CDN';                                   Host = 'officecdn.microsoft.com' }
    @{ Display = 'Office CDN (EdgeSuite)';                       Host = 'officecdn.microsoft.com.edgesuite.net' }
    @{ Display = 'Login Microsoft Online (AAD)';                 Host = 'login.microsoftonline.com' }
    @{ Display = 'Login Windows Net (AAD Redir)';                Host = 'login.windows.net' }
    @{ Display = 'Microsoft Graph API';                          Host = 'graph.microsoft.com' }
    @{ Display = 'Office 365 Portal';                            Host = 'portal.office.com' }
    @{ Display = 'Office 365 Admin Center';                      Host = 'admin.microsoft.com' }
    @{ Display = 'Exchange Online (Outlook)';                    Host = 'outlook.office365.com' }
    @{ Display = 'Microsoft Teams';                              Host = 'teams.microsoft.com' }
    @{ Display = 'OneDrive Consumer';                            Host = 'onedrive.live.com' }
    @{ Display = 'SharePoint Online (Example Tenant)';           Host = 'yourtenant.sharepoint.com' }
    @{ Display = 'OneDrive for Business (Example Tenant)';       Host = 'yourtenant-my.sharepoint.com' }
    @{ Display = 'Docs Microsoft';                               Host = 'docs.microsoft.com' }

    # --- Microsoft Intune / Endpoint Manager ---
    @{ Display = 'Intune Management';                            Host = 'manage.microsoft.com' }
    @{ Display = 'Azure AD Graph (Legacy)';                      Host = 'graph.windows.net' }

    # --- Certificate Revocation Lists (CRLs) and OCSP ---
    @{ Display = 'Microsoft CRL';                                Host = 'mscrl.microsoft.com' }
    @{ Display = 'DigiCert OCSP';                                Host = 'ocsp.digicert.com' }
    @{ Display = 'DigiCert CRL 3';                               Host = 'crl3.digicert.com' }
    @{ Display = 'DigiCert CRL 4';                               Host = 'crl4.digicert.com' }
    @{ Display = 'Microsoft Time CRL';                           Host = 'www.microsoft.com/pki/certs/microsofttime.crl' }

    # --- Time Services ---
    @{ Display = 'Windows Time Service';                         Host = 'time.windows.com' }

    # --- Network Connectivity Status Indicator (NCSI) ---
    @{ Display = 'NCSI Test';                                    Host = 'www.msftconnecttest.com' }
)

Function Test-MicrosoftConnectivity() {
    <#
    .SYNOPSIS
    Tests connectivity to Microsoft endpoints from MS_connecttest.ps1

    .DESCRIPTION
    Checks DNS + TCP reachability for key Microsoft endpoints including Windows Update,
    Microsoft 365, Azure AD, Store, Telemetry, and more.

    .PARAMETER Ports
    TCP ports to test. Default is 443.

    .PARAMETER VerboseProgress
    Show verbose progress output.

    .PARAMETER TraceRoute
    Perform traceroute on connection failures.

    .EXAMPLE
    Test-MicrosoftConnectivity

    .EXAMPLE
    Test-MicrosoftConnectivity -Ports 80,443 -TraceRoute -VerboseProgress
    #>
    [CmdletBinding()]
    Param(
        [int[]]$Ports = @(443),
        [switch]$VerboseProgress,
        [switch]$TraceRoute
    )

    $allResults = @()
    $totalTargets = $script:MSTargets.Count
    $currentTarget = 0
    $startTime = Get-Date
    $successCount = 0
    $failCount = 0

    Write-LogMessage -Message "Starting Microsoft connectivity tests ($totalTargets endpoints)" -Level 'INFO'
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  MICROSOFT CONNECTIVITY TEST" -ForegroundColor Cyan
    Write-Host "  Endpoints: $totalTargets | Ports: $($Ports -join ', ')" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan

    try {
        foreach ($target in $script:MSTargets) {
            $currentTarget++
            $percentComplete = [math]::Round(($currentTarget / $totalTargets) * 100)
            
            Write-TestProgress -Activity "Testing Microsoft Connectivity" -Status "Testing $($target.Display)" -CurrentOperation $currentTarget -TotalOperations $totalTargets

            if ($VerboseProgress) {
                Write-Host ("`n[{0}] [{1}/{2}] Resolving {3} ({4})" -f (Get-Date -Format "HH:mm:ss"), $currentTarget, $totalTargets, $target.Display, $target.Host) -ForegroundColor DarkYellow
            } else {
                Write-Host "`n[$currentTarget/$totalTargets] Testing $($target.Display)..." -ForegroundColor DarkYellow
            }

            $dnsResolved = $false
            $resolvedAddress = $null
            $tcpResults = @()
            $targetSuccess = $false

            # DNS Resolution
            try {
                Write-Verbose -Message "Performing DNS resolution for $($target.Host)"
                $dnsResolution = Resolve-DnsName -Name $target.Host -ErrorAction Stop
                $dnsResult = $dnsResolution | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
                if (-not $dnsResult) {
                    $dnsResult = $dnsResolution | Where-Object { $_.Type -eq 'AAAA' } | Select-Object -First 1
                }

                if ($dnsResult) {
                    $dnsResolved = $true
                    $resolvedAddress = $dnsResult.IPAddress
                    Write-Host "  DNS: Resolved to $resolvedAddress" -ForegroundColor Green
                } else {
                    Write-Host "  DNS: No IP address found (CNAME only or empty response)" -ForegroundColor Yellow
                }
            }
            catch [System.ComponentModel.Win32Exception] {
                Write-Host "  DNS: FAILED - Host not found" -ForegroundColor Red
                Write-Verbose -Message "DNS resolution failed for $($target.Host): $($_.Exception.Message)"
            }
            catch {
                Write-Host "  DNS: FAILED - $($_.Exception.Message)" -ForegroundColor Red
                Write-Verbose -Message "Unexpected DNS error for $($target.Host): $($_.Exception.Message)"
            }

            # TCP Port Tests
            if ($dnsResolved -and $resolvedAddress) {
                foreach ($port in $Ports) {
                    $tcpClient = $null
                    try {
                        Write-Verbose -Message "Testing TCP connection to $resolvedAddress`:$port"
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        $connection = $tcpClient.BeginConnect($resolvedAddress, $port, $null, $null)
                        $success = $connection.AsyncWaitHandle.WaitOne(5000, $false)

                        if ($success -and $tcpClient.Connected) {
                            Write-Host "  TCP Port $port`: OPEN" -ForegroundColor Green
                            $tcpResults += @{ Port = $port; Reachable = $true }
                            $targetSuccess = $true
                        }
                        else {
                            Write-Host "  TCP Port $port`: CLOSED/TIMEOUT" -ForegroundColor Yellow
                            $tcpResults += @{ Port = $port; Reachable = $false; Error = 'Connection timeout' }

                            # Optional traceroute on failure
                            if ($TraceRoute) {
                                Write-Host "  Running traceroute to $resolvedAddress..." -ForegroundColor Cyan
                                try {
                                    $traceResult = Test-NetConnection -ComputerName $resolvedAddress -TraceRoute -InformationLevel Quiet -ErrorAction SilentlyContinue
                                    if ($traceResult.TraceRoute) {
                                        $hops = $traceResult.TraceRoute.Count
                                        Write-Host "    Traceroute: $hops hops completed" -ForegroundColor Gray
                                    }
                                }
                                catch {
                                    Write-Host "    Traceroute failed: $($_.Exception.Message)" -ForegroundColor Yellow
                                }
                            }
                        }
                    }
                    catch [System.Net.Sockets.SocketException] {
                        Write-Host "  TCP Port $port`: SOCKET ERROR - $($_.Exception.Message)" -ForegroundColor Red
                        $tcpResults += @{ Port = $port; Reachable = $false; Error = $_.Exception.Message }
                    }
                    catch {
                        Write-Host "  TCP Port $port`: ERROR - $($_.Exception.Message)" -ForegroundColor Red
                        $tcpResults += @{ Port = $port; Reachable = $false; Error = $_.Exception.Message }
                    }
                    finally {
                        if ($null -ne $tcpClient) {
                            try { $tcpClient.Close() } catch { }
                        }
                    }
                }
            }
            else {
                Write-Host "  TCP: SKIPPED (DNS resolution failed)" -ForegroundColor Yellow
                foreach ($port in $Ports) {
                    $tcpResults += @{ Port = $port; Reachable = $false; Error = 'DNS failed' }
                }
            }

            if ($targetSuccess) { $successCount++ } else { $failCount++ }

            # Determine if blocked (DNS failed or TCP failed)
            $tcpSuccess = @($tcpResults | Where-Object { $_.Reachable -eq $true }).Count -gt 0
            $isBlocked = -not $dnsResolved -or (-not $tcpSuccess -and $dnsResolved)

            # Normalize output to match HTTP test format
            $allResults += [PSCustomObject]@{
                TestUrl = "https://$($target.Host)"
                UnblockUrl = $target.Host
                UrlType = 'DNS/TCP'
                Resolved = $dnsResolved
                IpAddresses = @($resolvedAddress)
                DnsAliases = @()
                Description = $target.Display
                ActualStatusCode = if ($tcpSuccess) { 200 } else { 0 }
                ExpectedStatusCode = 200
                UnexpectedStatus = -not $tcpSuccess
                StatusMessage = ''
                DetailedStatusMessage = ''
                Blocked = $isBlocked
                ServerCertificate = $null
                BlueCoat = $null
            }
        }

        Write-TestProgress -Activity "Testing Microsoft Connectivity" -Completed
    }
    catch {
        Write-LogMessage -Message "Critical error during Microsoft connectivity test: $($_.Exception.Message)" -Level 'ERROR'
        Write-TestProgress -Activity "Testing Microsoft Connectivity" -Completed
        throw
    }

    # Display summary
    $elapsed = (Get-Date) - $startTime
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Total Endpoints:  $totalTargets" -ForegroundColor White
    Write-Host "  Successful:       $successCount" -ForegroundColor Green
    Write-Host "  Failed:           $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  Duration:         $($elapsed.ToString('mm\:ss'))" -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Cyan
    Write-LogMessage -Message "Microsoft connectivity test completed: $successCount passed, $failCount failed" -Level $(if ($failCount -gt 0) { 'WARN' } else { 'SUCCESS' })

    return $allResults
}

#endregion

#region Windows Update Connectivity

Function Test-WindowsUpdateConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Windows Update.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $results = New-Object System.Collections.Generic.List[pscustomobject]
    $startTime = Get-Date

    Write-LogMessage -Message "Starting Windows Update connectivity test" -Level 'INFO'
    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "  WINDOWS UPDATE CONNECTIVITY TEST" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan

    try {
        $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

        # https://docs.microsoft.com/en-us/windows/privacy/manage-windows-endpoints#windows-update
        $data.Add(@{ TestUrl = 'http://windowsupdate.microsoft.com'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://windowsupdate.microsoft.com'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://geo-prod.do.dsp.mp.microsoft.com'; UrlPattern = 'https://*.do.dsp.mp.microsoft.com'; ExpectedStatusCode = 403; Description = 'Updates for applications and the OS on Windows 10 1709 and later.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'http://download.windowsupdate.com'; Description = 'Download operating system patches and updates'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'http://au.download.windowsupdate.com'; UrlPattern = 'http://*.au.download.windowsupdate.com'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://cds.d2s7q6s2.hwcdn.net'; UrlPattern = 'https://cds.*.hwcdn.net'; ExpectedStatusCode = 504; Description = 'Highwinds CDN used for Windows Update on Windows 10 1709 and later'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'http://cs9.wac.phicdn.net'; UrlPattern = 'http://*.wac.phicdn.net'; Description = 'Verizon CDN used for Windows Update on Windows 10 1709 and later'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://cs491.wac.edgecastcdn.net'; UrlPattern = 'https://*.wac.edgecastcdn.net'; ExpectedStatusCode = 404; Description = 'Verizon CDN used for Windows Update on Windows 10 1709 and later'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'http://dl.delivery.mp.microsoft.com'; UrlPattern = 'http://*.dl.delivery.mp.microsoft.com'; ExpectedStatusCode = 403; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'http://tlu.dl.delivery.mp.microsoft.com'; UrlPattern = 'http://*.tlu.dl.delivery.mp.microsoft.com'; ExpectedStatusCode = 403; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://emdl.ws.microsoft.com'; ExpectedStatusCode = 503; Description = 'Update applications from the Microsoft Store'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://fe2.update.microsoft.com'; UrlPattern = 'https://*.update.microsoft.com'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://sls.update.microsoft.com'; UrlPattern = 'https://*.update.microsoft.com'; ExpectedStatusCode = 403; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://fe3.delivery.mp.microsoft.com'; UrlPattern = 'https://*.delivery.mp.microsoft.com'; ExpectedStatusCode = 403; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://tsfe.trafficshaping.dsp.mp.microsoft.com'; UrlPattern = 'https://*.dsp.mp.microsoft.com'; ExpectedStatusCode = 403; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

        $totalUrls = $data.Count
        $currentUrl = 0

        foreach ($testParams in $data) {
            $currentUrl++
            Write-TestProgress -Activity "Testing Windows Update Connectivity" -Status "Testing URL $currentUrl of $totalUrls" -CurrentOperation $currentUrl -TotalOperations $totalUrls
            
            try {
                $connectivity = Get-HttpConnectivity @testParams
                $results.Add($connectivity)
            }
            catch {
                Write-LogMessage -Message "Error testing $($testParams.TestUrl): $($_.Exception.Message)" -Level 'WARN'
            }
        }

        Write-TestProgress -Activity "Testing Windows Update Connectivity" -Completed
    }
    catch {
        Write-LogMessage -Message "Critical error during Windows Update connectivity test: $($_.Exception.Message)" -Level 'ERROR'
        Write-TestProgress -Activity "Testing Windows Update Connectivity" -Completed
        throw
    }

    $elapsed = (Get-Date) - $startTime
    $blockedCount = ($results | Where-Object { $_.Blocked -eq $true }).Count
    Write-LogMessage -Message "Windows Update test completed in $($elapsed.ToString('mm\:ss')) - $($results.Count) URLs tested, $blockedCount blocked" -Level $(if ($blockedCount -gt 0) { 'WARN' } else { 'SUCCESS' })

    return $results
}

#endregion

#region Third-Party Connectivity Tests

Function Test-ARMUpdateConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Adobe Reader updates.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    $data.Add(@{ TestUrl = 'http://armmf.adobe.com'; ExpectedStatusCode = 404; Description = 'Adobe update metadata download'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://armmf.adobe.com'; ExpectedStatusCode = 404; Description = 'Adobe update metadata download'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://ardownload.adobe.com'; ExpectedStatusCode = 404; Description = 'Adobe updates download'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ardownload.adobe.com'; ExpectedStatusCode = 404; Description = 'Adobe updates download'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://ardownload2.adobe.com'; ExpectedStatusCode = 404; Description = 'Adobe incremental updates download'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ardownload2.adobe.com'; ExpectedStatusCode = 404; Description = 'Adobe incremental updates download'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://crl.adobe.com'; ExpectedStatusCode = 404; Description = 'Adobe Certificate Revocation List'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    return Invoke-HttpConnectivityTest -TestName 'Adobe Reader Updates' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

Function Test-MacOSUpdateConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for macOS updates.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    $data.Add(@{ TestUrl = 'https://swscan.apple.com'; ExpectedStatusCode = 403; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://swcdnlocator.apple.com'; ExpectedStatusCode = 501; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://swdownload.apple.com'; ExpectedStatusCode = 403; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://swcdn.apple.com'; ExpectedStatusCode = 404; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://swdist.apple.com'; ExpectedStatusCode = 403; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    $results = New-Object System.Collections.Generic.List[pscustomobject]
    $data | ForEach-Object { $results.Add((Get-HttpConnectivity @_)) }
    return $results
}

Function Test-ChromeUpdateConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Chrome updates.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    $data.Add(@{ TestUrl = 'http://redirector.gvt1.com'; UrlPattern = 'http://*.gvt1.com'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://redirector.gvt1.com'; UrlPattern = 'https://*.gvt1.com'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://update.googleapis.com/service/update2'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://update.googleapis.com/service/update2'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://clients2.google.com'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://clients5.google.com'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://tools.google.com'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://dl.google.com'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    return Invoke-HttpConnectivityTest -TestName 'Chrome Updates' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

Function Test-FirefoxUpdateConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Firefox updates.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    $data.Add(@{ TestUrl = 'https://aus3.mozilla.org'; ExpectedStatusCode = 404; Description = 'Firefox update check'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://aus4.mozilla.org'; ExpectedStatusCode = 404; Description = 'Firefox update check'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://aus5.mozilla.org'; ExpectedStatusCode = 404; Description = 'Firefox update check'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://download.cdn.mozilla.net'; Description = 'Firefox update download'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://archive.mozilla.org'; Description = 'Firefox update download'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ftp.mozilla.org'; Description = 'Firefox update download'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://versioncheck.addons.mozilla.org'; ExpectedStatusCode = 403; Description = 'Firefox add-on/extension update check'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://versioncheck-bg.addons.mozilla.org'; ExpectedStatusCode = 403; Description = 'Firefox add-on/extension update check'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    return Invoke-HttpConnectivityTest -TestName 'Firefox Updates' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

#endregion

#region Microsoft Service Connectivity Tests

Function Test-AADSSPRConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Azure Active Directory Self Service Password Reset.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    # https://docs.microsoft.com/en-us/azure/active-directory/authentication/tutorial-sspr-windows#limitations
    $data.Add(@{ TestUrl = 'https://passwordreset.microsoftonline.com'; ExpectedStatusCode = 200; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose})
    $data.Add(@{ TestUrl = 'https://ajax.aspnetcdn.com'; ExpectedStatusCode = 200; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose})

    return Invoke-HttpConnectivityTest -TestName 'Azure AD SSPR' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

Function Test-WindowsAnalyticsUpdateComplianceConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Windows Analytics Update Compliance.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    # https://docs.microsoft.com/en-us/windows/deployment/update/windows-analytics-get-started#enable-data-sharing
    $data.Add(@{ TestUrl = 'https://v10.events.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Connected User Experience and Diagnostic component endpoint for use with Windows 10 1803 and later'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://v10.vortex-win.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Connected User Experience and Diagnostic component endpoint for Windows 10 1709 and earlier'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://vortex.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Connected User Experience and Diagnostic component endpoint for operating systems older than Windows 10'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://v10c.events.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Connected User Experience and Diagnostic component endpoint for use with Windows 10 releases that have the September 2018, or later, Cumulative Update installed'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://settings-win.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Enables the compatibility update to send data to Microsoft.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://adl.windows.com'; ExpectedStatusCode = 404; Description = 'Allows the compatibility update to receive the latest compatibility data from Microsoft.'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://watson.telemetry.microsoft.com'; ExpectedStatusCode = 404; Description = 'Windows Error Reporting (WER)'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://oca.telemetry.microsoft.com'; ExpectedStatusCode = 404; Description = 'Online Crash Analysis'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ceuswatcab01.blob.core.windows.net'; ExpectedStatusCode = 400; Description = 'Windows Error Reporting (WER) Central US data center #1.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ceuswatcab02.blob.core.windows.net'; ExpectedStatusCode = 400; Description = 'Windows Error Reporting (WER) Central US data center #2.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://eaus2watcab01.blob.core.windows.net'; ExpectedStatusCode = 400; Description = 'Windows Error Reporting (WER) Eastern US data center #1.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://eaus2watcab02.blob.core.windows.net'; ExpectedStatusCode = 400; Description = 'Windows Error Reporting (WER) Eastern US data center #2.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://weus2watcab01.blob.core.windows.net'; ExpectedStatusCode = 400; Description = 'Windows Error Reporting (WER) Western US data center #1.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://weus2watcab02.blob.core.windows.net'; ExpectedStatusCode = 400; Description = 'Windows Error Reporting (WER) Western US data center #2.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    return Invoke-HttpConnectivityTest -TestName 'Windows Analytics Update Compliance' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

Function Test-WindowsAnalyticsUpgradeReadinessConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Windows Analytics Upgrade Readiness.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    # https://docs.microsoft.com/en-us/windows/deployment/update/windows-analytics-get-started#enable-data-sharing
    $data.Add(@{ TestUrl = 'https://v10.events.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Connected User Experience and Diagnostic component endpoint for use with Windows 10 1803 and later'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://v10.vortex-win.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Connected User Experience and Diagnostic component endpoint for Windows 10 1709 and earlier'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://vortex.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Connected User Experience and Diagnostic component endpoint for operating systems older than Windows 10'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://v10c.events.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Connected User Experience and Diagnostic component endpoint for use with Windows 10 releases that have the September 2018, or later, Cumulative Update installed'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://settings-win.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Enables the compatibility update to send data to Microsoft.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://adl.windows.com'; ExpectedStatusCode = 404; Description = 'Allows the compatibility update to receive the latest compatibility data from Microsoft.'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    return Invoke-HttpConnectivityTest -TestName 'Windows Analytics Upgrade Readiness' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

Function Test-WDATPConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Windows Defender Advanced Threat Protection.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup,
        [ValidateSet('All','Endpoint','SecurityCenter',IgnoreCase=$true)]
        [string]$UrlType = 'All',
        [string]$WorkspaceId
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $parameters = $PSBoundParameters
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    if ($UrlType.ToLower() -in @('all','endpoint')) {
        # https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/configure-proxy-internet-windows-defender-advanced-threat-protection
        $data.Add(@{ TestUrl = 'https://onboardingpackagescusprd.blob.core.windows.net/'; UrlPattern = 'https://*.blob.core.windows.net'; ExpectedStatusCode = 400; Description='Azure Blob storage. Eastern US data center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://onboardingpackageseusprd.blob.core.windows.net/'; UrlPattern = 'https://*.blob.core.windows.net'; ExpectedStatusCode = 400; Description='Azure Blob storage. Central US data center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'http://crl.microsoft.com'; ExpectedStatusCode = 400; Description='Microsoft Certificate Revocation List responder URL'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'http://ctldl.windowsupdate.com'; Description='Microsoft Certificate Trust List download URL'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://events.data.microsoft.com'; ExpectedStatusCode = 404; Description='WDATP event channel'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://us.vortex-win.data.microsoft.com/collect/v1'; ExpectedStatusCode = 400; Description='WDATP data channel'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://us-v20.events.data.microsoft.com'; ExpectedStatusCode = 404; Description='WDATP event channel for 1803+'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://winatp-gw-eus.microsoft.com/test'; Description='WDATP heartbeat/C&C channel. Eastern US data center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://winatp-gw-cus.microsoft.com/test'; Description='WDATP heartbeat/C&C channel. Central US data center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://us.vortex-win.data.microsoft.com/health/keepalive'; Description='WDATP data channel.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    }

    if ($UrlType.ToLower() -in @('all','securitycenter')) {
        $data.Add(@{ TestUrl = 'https://onboardingpackagescusprd.blob.core.windows.net/'; UrlPattern = 'https://*.blob.core.windows.net'; ExpectedStatusCode = 400; Description='Azure Blob storage. Eastern US data center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://onboardingpackageseusprd.blob.core.windows.net/'; UrlPattern = 'https://*.blob.core.windows.net'; ExpectedStatusCode = 400; Description='Azure Blob storage. Central US data center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://securitycenter.windows.com'; Description='Windows Defender Security Center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://login.windows.net/'; Description='Azure AD authentication'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://secure.aadcdn.microsoftonline-p.com'; UrlPattern = 'https://*.microsoftonline-p.com'; ExpectedStatusCode = 400; Description='Azure AD Connect / Azure MFA / Azure ADFS'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://login.microsoftonline.com'; Description='Azure AD authentication'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://winatpmanagement-us.securitycenter.windows.com'; UrlPattern = 'https://*.securitycenter.windows.com'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://threatintel-eus.securitycenter.windows.com'; UrlPattern = 'https://*.securitycenter.windows.com'; ExpectedStatusCode = 404; Description='Threat Intel. Eastern US data center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://threatintel-cus.securitycenter.windows.com'; UrlPattern = 'https://*.securitycenter.windows.com'; ExpectedStatusCode = 404; Description='Threat Intel. Central US data center'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://static2.sharepointonline.com'; UrlPattern = 'https://static2.sharepointonline.com'; ExpectedStatusCode = 400; Description='Host for Microsoft Fabric Assets'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    }

    if ($parameters.ContainsKey('WorkspaceId')) {
        $data.Add(@{ TestUrl = "https://$WorkspaceId.oms.opinsights.azure.com"; UrlPattern = 'https://*.oms.opinsights.azure.com'; ExpectedStatusCode = 403; Description='Microsoft Management Agent communication'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = "https://$WorkspaceId.ods.opinsights.azure.com"; UrlPattern = 'https://*.ods.opinsights.azure.com'; ExpectedStatusCode = 403; Description='Azure OMS data collection'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://scus-agentservice-prod-1.azure-automation.net'; UrlPattern = 'https://*.azure-automation.net'; ExpectedStatusCode = 400; Description='Azure Automation. Process and workflow automation'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
        $data.Add(@{ TestUrl = 'https://scadvisorcontent.blob.core.windows.net'; UrlPattern = 'https://*.blob.core.windows.net'; ExpectedStatusCode = 400; Description='System Center Advisor content'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    }

    # Remove duplicates and create unique test data
    $uniqueUrls = @($data | ForEach-Object { [pscustomobject]$_ } | Select-Object -Property TestUrl -ExpandProperty TestUrl -Unique)
    $uniqueData = New-Object System.Collections.Generic.List[System.Collections.Hashtable]
    $data | Where-Object { ([pscustomobject]$_).TestUrl -in $uniqueUrls } | ForEach-Object { $uniqueData.Add($_) }

    # Check proxy configuration
    try {
        $authenticatedProxyValue = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\DataCollection' -ErrorAction SilentlyContinue | Select-Object -Property DisableEnterpriseAuthProxy -ExpandProperty DisableEnterpriseAuthProxy -ErrorAction SilentlyContinue
        $useAuthenticatedProxy = $null -eq $authenticatedProxyValue -or $authenticatedProxyValue -eq 0
        $isRunningAsSystem = [bool](&"$env:systemroot\system32\whoami.exe" | Select-String -Pattern '^nt authority\\system$' -Quiet)

        if ($useAuthenticatedProxy -and $isRunningAsSystem) {
            Write-LogMessage -Message 'Running as SYSTEM but authenticated proxy is configured - results may be inaccurate' -Level 'WARN'
        }

        if (!$useAuthenticatedProxy -and !$isRunningAsSystem) {
            Write-LogMessage -Message 'Not running as SYSTEM but no authenticated proxy - results may be inaccurate' -Level 'WARN'
        }
    }
    catch {
        Write-Verbose -Message "Could not check proxy configuration: $($_.Exception.Message)"
    }

    return Invoke-HttpConnectivityTest -TestName 'Windows Defender ATP' -TestData $uniqueData -PerformBluecoatLookup:$PerformBluecoatLookup
}

Function Test-WDAVConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Windows Defender Antivirus.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/configure-network-connections-windows-defender-antivirus
    $data.Add(@{ TestUrl = 'https://wdcp.microsoft.com'; ExpectedStatusCode = 503; Description = 'Windows Defender Antivirus cloud-delivered protection service (MAPS)'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://wdcpalt.microsoft.com'; ExpectedStatusCode = 503; Description = 'Windows Defender Antivirus cloud-delivered protection service (MAPS)'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://update.microsoft.com'; UrlPattern='https://*.update.microsoft.com'; Description = 'Microsoft Update Service (MU). Signature and product updates.'; IgnoreCertificateValidationErrors=$true; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://download.microsoft.com'; UrlPattern='https://*.download.microsoft.com'; Description = 'Alternate location for Windows Defender Antivirus definition updates'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://onboardingpackageseusprd.blob.core.windows.net'; UrlPattern='https://*.blob.core.windows.net'; Description = 'Malware submission storage.'; ExpectedStatusCode = 400; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://www.microsoft.com/pkiops/crl'; ExpectedStatusCode = 404; Description = 'Microsoft Certificate Revocation List (CRL)'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://www.microsoft.com/pkiops/certs'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://crl.microsoft.com/pki/crl/products'; ExpectedStatusCode = 404; Description = 'Microsoft Certificate Revocation List (CRL)'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://www.microsoft.com/pki/certs'; ExpectedStatusCode = 404; Description = 'Microsoft certificates.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://msdl.microsoft.com/download/symbols'; Description = 'Microsoft Symbol Store'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://vortex-win.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Used by Windows to send client diagnostic data'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://settings-win.data.microsoft.com'; ExpectedStatusCode = 400; Description = 'Used by Windows to send client diagnostic data'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://definitionupdates.microsoft.com'; Description = 'Windows Defender Antivirus definition updates for Windows 10 1709+'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://unitedstates.cp.wd.microsoft.com'; ExpectedStatusCode = 503; Description = 'Geo-affinity URL for wdcp.microsoft.com'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://adldefinitionupdates-wu.azurewebsites.net'; ExpectedStatusCode = 200; Description = 'Alternative to https://adl.windows.com'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'http://ctldl.windowsupdate.com'; Description='Microsoft Certificate Trust List download URL'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    return Invoke-HttpConnectivityTest -TestName 'Windows Defender Antivirus' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

Function Test-WDSSConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Windows Defender SmartScreen.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    # https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-smartscreen/windows-defender-smartscreen-overview
    $data.Add(@{ TestUrl = 'https://apprep.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose})
    $data.Add(@{ TestUrl = 'https://ars.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by Windows Defender SmartScreen'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://c.urs.microsoft.com'; UrlPattern='https://*.urs.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by Internet Explorer and Edge'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://feedback.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 403; Description = 'SmartScreen URL used by users to report feedback'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://nav.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by Windows Defender SmartScreen'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://nf.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by Windows Defender Antivirus NIS'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ping.nav.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by Windows Defender SmartScreen'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ping.nf.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by NIS and SmartScreen'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://t.nav.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by Windows Defender SmartScreen'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://t.nf.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by NIS'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://unitedstates.smartscreen.microsoft.com'; UrlPattern='https://unitedstates.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by NIS and SmartScreen'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://unitedstates.smartscreen-prod.microsoft.com'; UrlPattern='https://unitedstates.smartscreen-prod.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by NIS and SmartScreen'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://t.urs.microsoft.com'; UrlPattern='https://*.urs.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by IE and Edge'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://urs.microsoft.com' ; UrlPattern='https://urs.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by Internet Explorer'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://urs.smartscreen.microsoft.com'; UrlPattern='https://*.smartscreen.microsoft.com'; ExpectedStatusCode = 404; Description = 'SmartScreen URL used by NIS, SmartScreen, and Exploit Guard'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    return Invoke-HttpConnectivityTest -TestName 'Windows Defender SmartScreen' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

Function Test-WindowsTelemetryConnectivity() {
    <#
    .SYNOPSIS
    Gets connectivity information for Windows Telemetry.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[pscustomobject]])]
    Param(
        [switch]$PerformBluecoatLookup
    )

    $isVerbose = $VerbosePreference -eq 'Continue'
    $data = New-Object System.Collections.Generic.List[System.Collections.Hashtable]

    # https://docs.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization#endpoints
    $data.Add(@{ TestUrl = 'https://v10.vortex-win.data.microsoft.com/collect/v1'; ExpectedStatusCode = 400; Description = 'Diagnostic/telemetry data for Windows 10 1607 and later.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://v20.vortex-win.data.microsoft.com/collect/v1'; ExpectedStatusCode = 400; Description = 'Diagnostic/telemetry data for Windows 10 1703 and later.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://settings-win.data.microsoft.com'; ExpectedStatusCode = 404; Description = 'Used by applications to dynamically update configuration.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://watson.telemetry.microsoft.com'; ExpectedStatusCode = 404; Description = 'Windows Error Reporting.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ceuswatcab01.blob.core.windows.net'; ExpectedStatusCode = 404; Description = 'Windows Error Reporting Central US 1.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://ceuswatcab02.blob.core.windows.net'; ExpectedStatusCode = 404; Description = 'Windows Error Reporting Central US 2.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://eaus2watcab01.blob.core.windows.net'; ExpectedStatusCode = 404; Description = 'Windows Error Reporting East US 1.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://eaus2watcab02.blob.core.windows.net'; ExpectedStatusCode = 404; Description = 'Windows Error Reporting East US 2.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://weus2watcab01.blob.core.windows.net'; ExpectedStatusCode = 404; Description = 'Windows Error Reporting West US 1.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://weus2watcab02.blob.core.windows.net'; ExpectedStatusCode = 404; Description = 'Windows Error Reporting West US 2.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://oca.telemetry.microsoft.com'; ExpectedStatusCode = 404; Description = 'Online Crash Analysis.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })
    $data.Add(@{ TestUrl = 'https://vortex.data.microsoft.com/collect/v1'; ExpectedStatusCode = 400; Description = 'OneDrive app for Windows 10.'; PerformBluecoatLookup=$PerformBluecoatLookup; Verbose=$isVerbose })

    return Invoke-HttpConnectivityTest -TestName 'Windows Telemetry' -TestData $data -PerformBluecoatLookup:$PerformBluecoatLookup
}

#endregion

#region Main Execution - Interactive Menu

Function Show-Menu() {
    Clear-Host
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "        CONNECTION TEST SUITE v2.0" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Microsoft Connectivity (DNS/TCP)" -ForegroundColor White
    Write-Host "  [2] Windows Update (HTTP)" -ForegroundColor White
    Write-Host "  [3] Windows Defender Antivirus" -ForegroundColor White
    Write-Host "  [4] Windows Defender ATP" -ForegroundColor White
    Write-Host "  [5] Windows Defender SmartScreen" -ForegroundColor White
    Write-Host "  [6] Windows Telemetry" -ForegroundColor White
    Write-Host "  [7] Azure AD SSPR" -ForegroundColor White
    Write-Host "  [8] Chrome Updates" -ForegroundColor White
    Write-Host "  [9] Firefox Updates" -ForegroundColor White
    Write-Host "  [10] Adobe Updates" -ForegroundColor White
    Write-Host ""
    Write-Host "  [11] Run ALL Tests" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [0] Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
}

Function Invoke-TestSelection() {
    <#
    .SYNOPSIS
    Executes the selected connectivity test with error handling.
    #>
    [CmdletBinding()]
    param([int]$Choice)

    $results = $null
    $testName = ''
    $startTime = Get-Date

    try {
        switch ($Choice) {
            1 { 
                $testName = 'Microsoft Connectivity'
                $results = Test-MicrosoftConnectivity
                break 
            }
            2 { 
                $testName = 'Windows Update'
                $results = Test-WindowsUpdateConnectivity
                break 
            }
            3 { 
                $testName = 'Windows Defender Antivirus'
                $results = Test-WDAVConnectivity
                break 
            }
            4 { 
                $testName = 'Windows Defender ATP'
                $results = Test-WDATPConnectivity
                break 
            }
            5 { 
                $testName = 'Windows Defender SmartScreen'
                $results = Test-WDSSConnectivity
                break 
            }
            6 { 
                $testName = 'Windows Telemetry'
                $results = Test-WindowsTelemetryConnectivity
                break 
            }
            7 { 
                $testName = 'Azure AD SSPR'
                $results = Test-AADSSPRConnectivity
                break 
            }
            8 { 
                $testName = 'Chrome Updates'
                $results = Test-ChromeUpdateConnectivity
                break 
            }
            9 { 
                $testName = 'Firefox Updates'
                $results = Test-FirefoxUpdateConnectivity
                break 
            }
            10 { 
                $testName = 'Adobe Updates'
                $results = Test-ARMUpdateConnectivity
                break 
            }
            11 {
                $testName = 'All Connectivity Tests'
                Write-LogMessage -Message "Starting comprehensive connectivity test suite" -Level 'INFO'
                Write-Host "`n" -NoNewline
                Write-Host "########################################################" -ForegroundColor Magenta
                Write-Host "##          RUNNING ALL CONNECTIVITY TESTS            ##" -ForegroundColor Magenta
                Write-Host "########################################################" -ForegroundColor Magenta
                
                $allStartTime = Get-Date
                $allResults = @()
                $testCount = 10
                $currentTest = 0
                
                $tests = @(
                    @{ Name = 'Microsoft Connectivity'; Function = { Test-MicrosoftConnectivity } },
                    @{ Name = 'Windows Update'; Function = { Test-WindowsUpdateConnectivity } },
                    @{ Name = 'Windows Defender Antivirus'; Function = { Test-WDAVConnectivity } },
                    @{ Name = 'Windows Defender ATP'; Function = { Test-WDATPConnectivity } },
                    @{ Name = 'Windows Defender SmartScreen'; Function = { Test-WDSSConnectivity } },
                    @{ Name = 'Windows Telemetry'; Function = { Test-WindowsTelemetryConnectivity } },
                    @{ Name = 'Azure AD SSPR'; Function = { Test-AADSSPRConnectivity } },
                    @{ Name = 'Chrome Updates'; Function = { Test-ChromeUpdateConnectivity } },
                    @{ Name = 'Firefox Updates'; Function = { Test-FirefoxUpdateConnectivity } },
                    @{ Name = 'Adobe Updates'; Function = { Test-ARMUpdateConnectivity } }
                )
                
                foreach ($test in $tests) {
                    $currentTest++
                    Write-TestProgress -Activity "Running All Tests" -Status "[$currentTest/$testCount] $($test.Name)" -CurrentOperation $currentTest -TotalOperations $testCount
                    
                    try {
                        $testResults = & $test.Function
                        $allResults += $testResults
                    }
                    catch {
                        Write-LogMessage -Message "Error in $($test.Name): $($_.Exception.Message)" -Level 'ERROR'
                    }
                }
                
                Write-TestProgress -Activity "Running All Tests" -Completed
                $results = $allResults
                
                $allElapsed = (Get-Date) - $allStartTime
                $totalBlocked = ($allResults | Where-Object { $_.Blocked -eq $true }).Count
                $totalPassed = $allResults.Count - $totalBlocked
                
                Write-Host "`n" -NoNewline
                Write-Host "########################################################" -ForegroundColor Magenta
                Write-Host "##              ALL TESTS COMPLETED                   ##" -ForegroundColor Magenta
                Write-Host "########################################################" -ForegroundColor Magenta
                Write-Host "  Total URLs Tested:  $($allResults.Count)" -ForegroundColor White
                Write-Host "  Passed:             $totalPassed" -ForegroundColor Green
                Write-Host "  Blocked/Failed:     $totalBlocked" -ForegroundColor $(if ($totalBlocked -gt 0) { 'Red' } else { 'Green' })
                Write-Host "  Total Duration:     $($allElapsed.ToString('mm\:ss'))" -ForegroundColor White
                Write-Host "########################################################" -ForegroundColor Magenta
                
                Write-LogMessage -Message "All tests completed: $totalPassed passed, $totalBlocked blocked/failed" -Level $(if ($totalBlocked -gt 0) { 'WARN' } else { 'SUCCESS' })
                break
            }
            0 { 
                Write-LogMessage -Message "Exiting Connection Test Suite" -Level 'INFO'
                exit 0 
            }
            default { 
                Write-LogMessage -Message "Invalid selection: $Choice" -Level 'WARN'
            }
        }
    }
    catch {
        Write-LogMessage -Message "Error during $testName test: $($_.Exception.Message)" -Level 'ERROR'
        Write-Host "`nStack Trace:" -ForegroundColor DarkGray
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }

    # Save results if path specified
    if ($SavePath -and $results) {
        try {
            $results | Export-Csv -Path $SavePath -NoTypeInformation -Force -ErrorAction Stop
            Write-LogMessage -Message "Results saved to: $SavePath" -Level 'SUCCESS'
        }
        catch {
            Write-LogMessage -Message "Failed to save results to $SavePath`: $($_.Exception.Message)" -Level 'ERROR'
        }
    }

    return $results
}

# Main execution logic
Write-LogMessage -Message "Connection Test Suite v2.0 started" -Level 'INFO'
Write-LogMessage -Message "PowerShell Version: $($PSVersionTable.PSVersion)" -Level 'DEBUG'
Write-LogMessage -Message "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -Level 'DEBUG'

try {
    if ($MenuChoice -gt 0 -and $MenuChoice -le 11) {
        Write-LogMessage -Message "Running test selection: $MenuChoice (command-line mode)" -Level 'INFO'
        $null = Invoke-TestSelection -Choice $MenuChoice
    }
    else {
        do {
            Show-Menu
            $selection = Read-Host "Enter your choice (0-11)"
            try {
                $choice = [int]$selection
                if ($choice -ge 0 -and $choice -le 11) {
                    $null = Invoke-TestSelection -Choice $choice

                    if ($choice -ne 0) {
                        Write-Host "`nPress any key to continue..." -ForegroundColor Gray
                        try {
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        catch {
                            # Handle non-interactive mode
                            Start-Sleep -Seconds 3
                        }
                    }
                }
                else {
                    Write-LogMessage -Message "Invalid choice entered: $choice" -Level 'WARN'
                    Start-Sleep -Seconds 2
                }
            }
            catch [System.FormatException] {
                Write-LogMessage -Message "Invalid input format: '$selection'" -Level 'WARN'
                Start-Sleep -Seconds 2
            }
            catch {
                Write-LogMessage -Message "Error processing input: $($_.Exception.Message)" -Level 'ERROR'
                Start-Sleep -Seconds 2
            }
        } while ($choice -ne 0)
    }
}
catch {
    Write-LogMessage -Message "Critical error in main execution: $($_.Exception.Message)" -Level 'ERROR'
    Write-Host "`nStack Trace:" -ForegroundColor DarkGray
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 1
}
finally {
    Write-LogMessage -Message "Connection Test Suite completed" -Level 'INFO'
}

#endregion
