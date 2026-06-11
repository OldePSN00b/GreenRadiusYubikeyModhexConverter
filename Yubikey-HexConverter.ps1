<#
.SYNOPSIS
    Look up YubiKey assignments in GreenRADIUS.

.DESCRIPTION
    This script queries the GreenRADIUS Management API to locate a YubiKey
    assignment using one of the following input types:

        - Decimal serial number printed on the back of a YubiKey
        - Full YubiKey OTP
        - 12-character YubiKey public ID

    If a decimal serial number is provided, the script converts it from:

        Decimal -> Hexadecimal -> ModHex

    If a full OTP is provided, the script extracts the first 12 characters,
    which represent the YubiKey public ID.

.NOTES
    Requires:
        - PowerShell 7+ for -SkipCertificateCheck
        - GreenRADIUS Management API access
        - Valid API credentials

    GreenRADIUS API endpoint used:
        /gras-api/v2/mgmt/tokenassignment

.LINK
    https://guide.greenrocketsecurity.com/management-apis.html
#>

#region Configuration

# GreenRADIUS server FQDN or IP address.
$serverHOST = '<GreenRADIUS server FQDN or IP>'

#endregion Configuration

#region User Input

# Accept a decimal serial number, full OTP, or existing 12-character public ID.
$inputValue = Read-Host "Enter YubiKey decimal serial, full OTP, or token/public ID"
$inputValue = $inputValue.Trim()

# Store one or more possible token IDs to search.
$tokenCandidates = @()

#endregion User Input

#region Identifier Conversion

if ($inputValue -match '^\d+$') {

    # A numeric-only value is treated as the decimal serial printed on the YubiKey.
    $decimalSerial = [UInt64]$inputValue

    # Convert decimal serial to hexadecimal.
    $hexSerial = '{0:x}' -f $decimalSerial

    <#
        Yubico OTP uses ModHex rather than standard hexadecimal.

        Hex:    0123456789abcdef
        ModHex: cbdefghijklnrtuv

        GreenRADIUS commonly stores YubiKey public IDs in ModHex format.
    #>
    $modhexMap = @{
        '0' = 'c'
        '1' = 'b'
        '2' = 'd'
        '3' = 'e'
        '4' = 'f'
        '5' = 'g'
        '6' = 'h'
        '7' = 'i'
        '8' = 'j'
        '9' = 'k'
        'a' = 'l'
        'b' = 'n'
        'c' = 'r'
        'd' = 't'
        'e' = 'u'
        'f' = 'v'
    }

    # Convert each hexadecimal character to its ModHex equivalent.
    $modhexSerial = -join ($hexSerial.ToCharArray() | ForEach-Object {
            $modhexMap[[string]$_]
        })

    # Public IDs are typically 12 characters. ModHex 'c' represents hex zero.
    $tokenCandidates += $modhexSerial
    $tokenCandidates += $modhexSerial.PadLeft(12, 'c')

    Write-Output ("Decimal Serial : {0}" -f $decimalSerial)
    Write-Output ("Hex Serial     : {0}" -f $hexSerial)
    Write-Output ("Modhex Serial  : {0}" -f $modhexSerial)
    Write-Output ("Padded Modhex  : {0}" -f $modhexSerial.PadLeft(12, 'c'))
}
else {

    # Non-numeric input is treated as either a full OTP or a public ID.
    # The first 12 characters of a YubiKey OTP are the public ID.
    if ($inputValue.Length -gt 12) {
        $inputValue = $inputValue.Substring(0, 12)
    }

    $tokenCandidates += $inputValue
}

# Remove duplicate candidates before querying the API.
$tokenCandidates = $tokenCandidates | Select-Object -Unique

Write-Output ""
Write-Output "Searching token candidate(s):"

$tokenCandidates | ForEach-Object {
    Write-Output ("- {0}" -f $_)
}

#endregion Identifier Conversion

#region GreenRADIUS API Setup

# GreenRADIUS token assignment lookup endpoint.
$uri = 'https://{0}/gras-api/v2/mgmt/tokenassignment' -f $serverHOST

# Basic authentication header.
# Replace the placeholder with a valid API username and password.
$headers = @{
    'Authorization' = 'Basic ' + [Convert]::ToBase64String(
        [Text.Encoding]::ASCII.GetBytes('<API username:API password>')
    )
    'Content-Type'  = 'application/json'
}

# GreenRADIUS expects token_id as an array.
$jsonBody = @{
    token_id = $tokenCandidates
} | ConvertTo-Json -Depth 10

#endregion GreenRADIUS API Setup

#region GreenRADIUS Lookup

try {
    # Query GreenRADIUS for token assignment details.
    $response = Invoke-RestMethod `
        -SkipCertificateCheck `
        -Uri $uri `
        -Method Get `
        -Headers $headers `
        -Body $jsonBody `
        -ErrorAction Stop

    $records = $response.records_with_mappings.records

    if (-not $records) {
        Write-Output ""
        Write-Output "No user mapping found."
        return
    }

    Write-Output ""
    Write-Output "Token/key found:"
    Write-Output "================"

    # GreenRADIUS returns token IDs as property names under the records object.
    foreach ($tokenProperty in $records.PSObject.Properties) {
        $tokenId = $tokenProperty.Name
        $token = $tokenProperty.Value

        Write-Output ("Token ID: {0}" -f $tokenId)
        Write-Output ("Token Type: {0}" -f $token.token_type)

        # user_mappings is returned as indexed properties containing user details.
        foreach ($userProperty in $token.user_mappings.PSObject.Properties) {
            $userData = $userProperty.Value

            Write-Output ("User: {0}" -f $userData.user)
            Write-Output ("Status: {0}" -f $userData.status)
            Write-Output ("Directory State: {0}" -f $userData.state_in_directory_server)

            # assigned_on is returned as a Unix timestamp.
            if ($userData.assigned_on) {
                $assignedDate = [DateTimeOffset]::FromUnixTimeSeconds([int64]$userData.assigned_on).LocalDateTime
                Write-Output ("Assigned On: {0}" -f $assignedDate)
            }

            Write-Output ""
        }
    }
}
catch {
    Write-Error "Error: $($_.Exception.Message)"

    if ($_.Exception.InnerException) {
        Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
    }
}
