###########Export Folder Permisson##############
#Kiexportálja a mappa/mappák felhasználók jogait.
##
#Ezeket átírhatod
$FolderName="\\192.168.91.4\Share\Teszt"
$CSVPath="$env:APPDATA\perm.csv"
##
#
##Ehhez már ne nyúlj!
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
$Report | Export-Csv -path $CSVPath -Encoding UTF8
Write-Host "A CSV export elkészült: $CSVPath"
