Import-Module -Name MsrcSecurityUpdates -Force

function Get-ExploitedCVE {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)] $period,
        [switch]$return_object = $fasle
    )

    $ParameterList = (Get-Command -Name Get-MsrcCvrfDocument).Parameters
    $ids = $ParameterList["ID"].Attributes.ValidValues

    if ($period -notin $ids) {
        Write-Host 'Period format is not valid please use like: "2023-Nov" '
        return $null
    }

    try {
        $data = Get-MsrcCvrfDocument -ID $period | Get-MsrcCvrfExploitabilityIndex | Where-Object { $_.Exploited -eq 'Yes' }
        $data = $data | Select-Object -Property CVE
    }
    catch {
        Write-Host 'Internale error'
    }

    if ($return_object) {
        return $data
    }
    
    return ($data | Format-Table)
}

function Get-DataJobs {
    param(
        [parameter(Mandatory = $true)]$IDs,
        [parameter(Mandatory = $true)]$MaxThreads,
        $SleepTime = 1000
    )

    $Scriptblock = {
        param($id)
        return (Get-MsrcCvrfDocument -ID $id |  Get-MsrcCvrfAffectedSoftware)
    }

    $Jobs = @()
    $SoftwareList = New-Object System.Collections.ArrayList
    Foreach ($id in $IDs) {
        Write-Verbose -Message "Processing $id"
        # Wait for running jobs to finnish if MaxThreads is reached
        While ((Get-Job -State Running).count -ge $MaxThreads) {
            Write-Verbose -Message 'Waiting for jobs to finish before starting new ones'
            Start-Sleep -Milliseconds $SleepTime 
        }

        # Start new jobs
        $Jobs += Start-Job -ScriptBlock $Scriptblock -ArgumentList $id -Name $id -OutVariable LastJob
        Write-Verbose -Message "Job with id: $($LastJob.Id) just started."
    }

    # All jobs have now been started
    Write-Verbose -Message "All jobs have been started $(Get-Date)"

    # Wait for jobs to finish
    While ((Get-Job -State Running).count -gt 0) {
        Start-Sleep -Milliseconds $SleepTime
    }

    # Output
    Write-Verbose -Message 'Recieving jobs'
    Get-job | Receive-Job | ForEach-Object { $SoftwareList.Add($_) | Out-Null }

    # Cleanup
    Get-job | Remove-Job

    return $SoftwareList
}


function Get-ExploitabilityRaiting {
    [CmdletBinding()]
    param(
        $IDs = $null,
        $MaxThreads = 0,
        $SleepTime = 1000,
        [switch]$return_object = $fasle
    )

    if ($null -eq $IDs) {
        $ParameterList = (Get-Command -Name Get-MsrcCvrfDocument).Parameters
        $IDs = $ParameterList["ID"].Attributes.ValidValues
    }

    Write-Verbose "IDs list: $($IDs)"

    if ($MaxThreads -eq 0) {
        $MaxThreads = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    }

    Write-Verbose 'Data query Jobs'
    $SoftwareList = Get-DataJobs $IDs $MaxThreads $SleepTime

    $hash = @{}
    Write-Verbose 'Before foreach'
    foreach ($list in $SoftwareList) {
        $list | Where-Object { $hash[$_.FullProductName] += 1 }
    }
    Write-Verbose 'After foreach'

    $data = $hash.GetEnumerator() | 
    Sort-Object -Property  @{Expression = { $_.Value }; Descending = $true }, @{Expression = { $_.Name } ; Descending = $false } | ForEach-Object { [PSCustomObject]@{
            'Raiting'        = ''
            'Softwate Name'  = $_.Key
            'Affected Count' = $_.Value
        } }
    
    if ($data.Count) {
        $raiting = 1
        $data[$data.Count - 1].Raiting = $raiting
        for ($i = $data.Count - 1; $i -gt 0; ) {
            if ($data[$i - 1].'Affected Count' -eq $data[$i].'Affected Count') {
                $data[--$i].Raiting = $raiting
            }
            else {
                $data[--$i].Raiting = ++$raiting
            }
        }   
    }

    if ($return_object) {
        return $data 
    }

    return ($data | Format-Table)
}

function Get-KBbyCVE {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]$cve_name,
        [AllowEmptyString()]
        [switch]$return_object
    )

    $id = Get-MsrcSecurityUpdate -Vulnerability $cve_name | Select-Object -ExpandProperty ID
    if ($null -eq $id) {
        Write-Host 'Failed to find CVE with name provided'
        return $null
    }

    $results = New-Object System.Collections.ArrayList
     
    $cvrfDoc = Get-MsrcCvrfDocument -ID $id
    
    $cve = $cvrfDoc.Vulnerability | Where-Object { $_.CVE -eq $cve_name }
    
    foreach ($Remediation in $cve.Remediations) {
        $kb = "KB$($Remediation.Description.Value)"
        $product = ($cvrfDoc.ProductTree.FullProductName | Where-Object { $_.ProductID -eq $Remediation.ProductID } | Select-Object -ExpandProperty Value) 
        $obj = [PSCustomObject]@{
            KB      = $kb
            Product = $product
        }
        $results.Add($obj) | Out-Null
    }
    
    if ($return_object) {
        return $results 
    }

    return ($results | Format-Table)
}

Export-ModuleMember -Function Get-KBbyCVE, Get-ExploitabilityRaiting, Get-ExploitedCVE