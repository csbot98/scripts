Import-Module -Name ${PSScriptRoot}\AnyBox-master\Anybox -Verbose

$errorcode=0;
$efidrive = "W:"
$legacydrive = "B:"
$osdrive = "R:"
$oslist = @(
			( "Windows 10 Home", "boot.wim", "efi.wim", "home.wim" ),
			( "Windows 10 Pro", "boot.wim", "efi.wim", "pro.wim" )
		)
		
[System.Collections.ArrayList]$ositem = @()
foreach($os in $oslist) {
	$ositem.Add($os[0])
}

$anybox = New-Object AnyBox.AnyBox
$anybox.Prompts = @(
  New-AnyBoxPrompt -InputType Text -Message "Hostname prefix:" -Name "PCName" -DefaultValue 'DESKTOP'
  New-AnyBoxPrompt -InputType Text -Message "OS Type:" -Name "OSType" -ValidateSet $ositem -ShowSetAs Radio
  New-AnyBoxPrompt -InputType Text -Message "BOOT Type:" -Name "BOOType" -ValidateSet 'EFI','Legacy'  -ShowSetAs Radio
  New-AnyBoxPrompt -InputType Text -Message "Partitioning:" -Name "DiskSize" -ValidateSet 'Full','Partial' -ShowSetAs Radio
  New-AnyBoxPrompt -InputType Checkbox -Message "Auto restart if completed without errors" -Name "CheckBox" -DefaultValue $false
)
$anybox.Icon = 'Question'
$anybox.ContentAlignment = 'Left'
$anybox.Buttons = 'Cancel','Submit'
$response = $anybox | Show-AnyBox


$PCName=$response['PCName']
$OSType=$response['OSType']
$BOOType=$response['BOOType']
$DiskSize=$response['DiskSize']

foreach($os in $oslist) {
	if ($OSType -eq $os[0]) {
		$bootimage = $os[1]
		$efiimage = $os[2]
		$sysimage = $os[3]
		break
	}
}

if ($response['submit'] -eq $true) {
	# Partitioning
	if($BOOType -eq 'Legacy' -And $DiskSize -eq 'Full'){
		diskpart /s "${PSScriptRoot}\part-schemes\diskpart-legacy-rendszer-full.txt"
		if($?){
			Write-Host "Partitioning Command: Legacy-Full Success"
		}
		else
		{
			Write-Host "Partitioning Command: Legacy-Full Not Success"
			$errorcode++;
		}
	}
    ElseIf($BOOType -eq 'Legacy' -And $DiskSize -eq 'Partial'){
		diskpart /s "${PSScriptRoot}\part-schemes\diskpart-legacy-rendszer-tarhely.txt"
		if($?){
			Write-Host "Partitioning Command: Legacy-Partial Success"
		}
		else
		{
			Write-Host "Partitioning Command: Legacy-Partial Not Success"
			$errorcode++;
		}
	}
    ElseIf($BOOType -eq 'EFI' -And $DiskSize -eq 'Partial'){
		diskpart /s "${PSScriptRoot}\part-schemes\diskpart-efi-rendszer-tarhely.txt"
		if($?){
			Write-Host "Partitioning Command: EFI-Partial Success"
		}
		else
		{
			Write-Host "Partitioning Command: EFI-Partial Not Success"
			$errorcode++;
		}
	}
    Else{
		diskpart /s "${PSScriptRoot}\part-schemes\diskpart-efi-rendszer-full.txt"
		if($?){
			Write-Host "Partitioning Command: EFI-Full Success"
		}
		else
		{
			Write-Host "Partitioning Command: EFI-Full Not Success"
			$errorcode++;
		}
	}

	# Boot image
	if ($BOOType -eq "Legacy") {
		dism /apply-image /imagefile:"${PSScriptRoot}\images\${bootimage}" /applydir:"${legacydrive}\" /index:1
		if($?){
			Write-Host "Boot image apply: Legacy Success"
		}
		else
		{
			Write-Host "Boot image apply: Legacy Not Success"
			$errorcode++;
		}
		# MBR on legacy boot
		bootsect /nt60 "${osdrive}" /mbr
		
	} else {
		dism /apply-image /imagefile:"${PSScriptRoot}\images\${efiimage}" /applydir:"${efidrive}\" /index:1
		if($?){
			Write-Host "Boot image apply: EFI Success"
		}
		else
		{
			Write-Host "Boot image apply: EFI Not Success"
			$errorcode++;
		}
	}

	# System image
	dism /apply-image /imagefile:"${PSScriptRoot}\images\${sysimage}" /applydir:"${osdrive}\" /index:1
	if($?){
			Write-Host "System image apply: Success"
		}
		else
		{
			Write-Host "System image apply: Not Success"
			$errorcode++;
		}

	# Hostname postfix generation
	$hostprefix = ($PCName,$hostprefix)[[bool]$hostprefix]
	$hostrandom = -join ((48..57) + (65..90) | Get-Random -Count 6 | % {[char]$_})
	$systemhostname = $hostprefix + '-' + $hostrandom

	# Removing Scripts directory and create a new empty one
	Remove-Item -Path "${osdrive}\Windows\Setup\Scripts" -ErrorAction Ignore
	New-Item -Path "${osdrive}\Windows\Setup\" -Name "Scripts" -ItemType "directory" -Force

	# Copying postinstall config files to the system
	(Get-Content -Path "${PSScriptRoot}\postinstall\unattend.xml" -Raw) -replace 'Teszt1', $systemhostname | Set-Content -Path "${osdrive}\Windows\System32\Sysprep\unattend.xml" -Force
	Copy-Item "${PSScriptRoot}\postinstall\SetupComplete.cmd" -Destination "${osdrive}\Windows\Setup\Scripts\" -Force
	Copy-Item "${PSScriptRoot}\postinstall\SetupComplete-NOOP.ps1" -Destination "${osdrive}\Windows\Setup\Scripts\" -Force
	
	#Auto reboot
	if (($response['CheckBox'] -eq $true) -and $errorcode -eq '0') {
	    Restart-Computer
	}
    ElseIf($errorcode -eq '0'){
        Write-Host "A telepítés sikeres."
    }
	else{
		Write-Host "Hiba!!! Nézd vissza fentebb hol a hiba!"
		Write-Host "$errorcode";
	}
}
