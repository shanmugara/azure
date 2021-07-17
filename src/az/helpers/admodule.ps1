param($groupname)

asnp quest*

# a simple func to return all users direct and indirect from AD group
function get-groupmembers {
    param($groupname)
    try {
            $groupmems = get-qadgroupmember $groupname -indirect -type user -sizelimit 50000
            $samname = @()
            $groupmems|%{
                $samname += $_.samaccountname
            }
            return $samname
        }
    catch {
            write-host "failed_to_get_members"
            return $false
        }
}

get-groupmembers -groupname $groupname
