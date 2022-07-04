###################################################################
######################OnlySet-Permissions##########################
###################################################################
######Ezeket kell átírni, ha máshol akarjuk használni a scriptet###
##
#Módosítani kívánt mappa
$FolderName="\\192.168.91.4\Share\Scan"
#A felolvasni való CSV file.
$CSVPath="$env:APPDATA\folderlist2.csv"
#
##
######A lentebb látható kódhoz ne nyúlj bele, ha nem fontos########
###################################################################

Write-Host "Módosításra kerülő mappa:" $FolderName

Write-Host "Beimportált CSV File:" $CSVPath

#Az aktuálisan logged in user, aki majd a mappa/mappák tulajdonosa lesz a script idejére.
$TempOwner= [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "A script futtatója: $($TempOwner)"

#A végső mappa tulajdonos. (Én a Domain Admins-t adtam meg)
$DomainAdmin="\Domain Admins"
$FinalOwner=$env:userdnsdomain + $DomainAdmin

##Things for ACL
$inherit = [system.security.accesscontrol.InheritanceFlags]"ObjectInherit",[system.security.accesscontrol.InheritanceFlags]"ContainerInherit"
$propagation = [system.security.accesscontrol.PropagationFlags]"None"

###A már létező MEGFELELŐ CSV File beolvasása###
$csv = Import-Csv -Path $CSVPath
ForEach ($item In $csv) {
    
    #Ideiglenesen átveszi a scriptet futtató személy a mappák Tulajdonos jogát.
    $ACL = Get-ACL $item.FolderName
    $Owner = New-Object System.Security.Principal.NTAccount($TempOwner)
    $ACL.SetOwner($Owner)
    Set-Acl -Path $item.FolderName -AclObject $ACL
    Write-Host -ForegroundColor Cyan " $($item.FolderName) $($TempOwner) is the Temp Owner for now."
    
    #A megfelelő jogokat tartalmazó CSV file beimportálása és jog kiosztás
    $AddPerm = New-Object System.Security.AccessControl.FileSystemAccessRule($item.ADUser, $item.Permissions, $inherit, $propagation, ’Allow’) 
    $acl.SetAccessRule($AddPerm)
	Get-ChildItem $item.FolderName -recurse -Force | Set-Acl -AclObject $acl #Ez kiosztja a fájlokra is a jogokat.
    $acl | Set-Acl $item.FolderName
    Write-Host -ForegroundColor Green " $($item.FolderName) $($item.ADUser) $($item.Permissions) permisson granted!"
    
    #Give Ownership to Domain Admins group
    $ACL = Get-ACL $item.FolderName
    $Owner = New-Object System.Security.Principal.NTAccount($FinalOwner)
    $ACL.SetOwner($Owner)
	Get-ChildItem $item.FolderName -recurse -Force | Set-Acl -AclObject $ACL #Ez kiadja mindenre is a parancsot. Minden almappa, file a DomainAdmin tulajdona lesz.
    Set-Acl -Path $item.FolderName -AclObject $ACL
    Write-Host -ForegroundColor Yellow " $($item.FolderName) $($FinalOwner) is the Owner now."
    
}