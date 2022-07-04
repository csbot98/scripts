###Delete Permissions###
#Kiolvassa a felhasználók jogait és törli, csak a szükségesek maradnak
###################################################################
######Ezeket kell átírni, ha máshol akarjuk használni a scriptet###
##
#Módosítani kívánt mappa
$FolderName="\\192.168.91.4\Share\Teszt"
#
#
##
######A lentebb látható kódhoz ne nyúlj bele, ha nem fontos########
###################################################################

Write-Host "Módosításra kerülő mappa:" $FolderName

#A temporary CSV file helye
$CSVDel="$env:APPDATA\del.csv"
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

##A mappa aktuális user permission-öket kiexportálja egy temporary csv-be
$FolderPath = dir -Directory -Path $FolderName -Recurse -Force
$Report = @()
Foreach ($Folder in $FolderPath) {
    $Acl = Get-Acl -Path $Folder.FullName
        foreach ($Access in $acl.Access)
            {
                $Properties = [ordered]@{'FolderName'=$Folder.FullName;'ADUser'=$Access.IdentityReference;'Permissions'=$Access.FileSystemRights;'Inherited'=$Access.IsInherited}
                $Report += New-Object -TypeName PSObject -Property $Properties
            }
    }
$Report | Export-Csv -path $CSVDel -Encoding UTF8
Write-Host "Az ideiglenes CSV fájl létrejött, ami tartalmazza a jelenlegi felhasználókat és a hozzájuk tartozó jogokat."

##A temporary CSV-t beimportálja és törli a felhasználókat + a hozzájuk tartozó permissiont.
$csvtemp = Import-Csv -Path $CSVDel
ForEach ($item In $csvtemp) {

    #Ideiglenesen átveszi a scriptet futtató személy a mappák Tulajdonos jogát.
    $ACL = Get-ACL $item.FolderName
    $Owner = New-Object System.Security.Principal.NTAccount($TempOwner)
    $ACL.SetOwner($Owner)
    Set-Acl -Path $item.FolderName -AclObject $ACL
    Write-Host -ForegroundColor Cyan " $($item.FolderName) $($TempOwner) is the Temp Owner for now."##Szedd ki!

    #Remove inheritance
    $acl = Get-Acl $item.FolderName
    $acl.SetAccessRuleProtection($true,$true)
    Set-Acl $item.FolderName $acl

    ##Delete Permissions
    $RemoveRule= New-Object System.Security.AccessControl.FileSystemAccessRule($item.ADUser, $item.Permissions, $inherit, $propagation,’Allow’)
    #$acl.Access 
    $acl.RemoveAccessRuleAll($RemoveRule)
	Get-ChildItem $item.FolderName -recurse -Force | Set-Acl -AclObject $acl #Ez a fájloktól is elveszi a jogokat.
    Set-Acl $item.FolderName $acl
    Write-Host -ForegroundColor Yellow " $($item.FolderName) $($item.ADUser) Inheritance  deleted."
    Write-Host -ForegroundColor Red " $($item.FolderName) $($item.ADUser) user permissions deleted."
    
    #Give Ownership to Domain Admins group
    $ACL = Get-ACL $item.FolderName
    $Owner = New-Object System.Security.Principal.NTAccount($FinalOwner)
    $ACL.SetOwner($Owner)
    Set-Acl -Path $item.FolderName -AclObject $ACL
    Write-Host -ForegroundColor Yellow " $($item.FolderName) $($FinalOwner) is the Owner now."
    #get-acl -Path $FolderName  | Format-List *
    }
    #end of tisztogatás