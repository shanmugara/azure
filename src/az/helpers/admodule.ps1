param($groupname)

asnp quest*

# a simple func to return all users direct and indirect from AD group
function get-groupmembers {
    param($groupname)
    try {
            $groupmems = get-qadgroupmember $groupname -indirect -type user
            $samname = @()
            $groupmems|%{
                $samname += $_.samaccountname
            }
            return $samname
        }
    catch {
            Write-Error "Error while getting group $groupname"
            return $false
        }
}

get-groupmembers -groupname $groupname
