# $VerbosePreference = 'continue'
Import-Module -Name .\HandyCves.psm1 -force

#Test for Get-ExploitedCVE
$id = '2019-Nov'
$path_t1 = Join-Path -Path $PWD.Path -ChildPath "TestData/ExploitedCVE_$($id).xml"

if (Test-Path -Path $path_t1) {
    
    $obj1 = Get-ExploitedCVE $id -return_object
    $obj2 = Import-CliXml $path_t1

    if (Compare-Object -ReferenceObject $obj1 -DifferenceObject $obj2) {
        Write-Error 'Get-ExploitedCVE returned unexpected result'
    }
    else {
        Write-Host 'Get-ExploitedCVE test OK'
    }
}
else {
    Write-Warning 'No file for Get-ExploitedCVE test'
}


#Test for Get-ExploitabilityRaiting
$path_t2 = Join-Path -Path $PWD.Path -ChildPath "TestData/Get-ExploitabilityRaiting_6M.xml"
if (Test-Path -Path $path_t2) {
    $IDs = @('2017-Nov', '2018-Nov', '2019-Nov', '2020-Nov', '2021-Nov', '2022-Nov')

    $obj1 = Get-ExploitabilityRaiting $IDs -return_object
    $obj2 = Import-CliXml $path_t2

    if (Compare-Object -ReferenceObject $obj1 -DifferenceObject $obj2) {
        Write-Error 'Get-ExploitabilityRaiting returned unexpected result'
    }
    else {
        Write-Host 'Get-ExploitabilityRaiting test OK'
    }
}
else {
    Write-Warning 'No file for Get-ExploitabilityRaiting test'
}

#Test for Get-KBbyCVE
$path_t3 = Join-Path -Path $PWD.Path -ChildPath 'TestData/Get-KBbyCVE_CVE-2017-0003.xml'
if (Test-Path -Path $path_t3) {
    $obj1 = Get-KBbyCVE 'CVE-2017-0003' -return_object
    $obj2 = Import-CliXml $path_t3

    if (Compare-Object -ReferenceObject $obj1 -DifferenceObject $obj2) {
        Write-Error 'Get-KBbyCVE returned unexpected result'
    }
    else {
        Write-Host 'Get-KBbyCVE test OK'
    }
}
else {
    Write-Warning 'No file for Get-KBbyCVE test'
}
