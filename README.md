# FilterEvent

$LogName = 'Security'
$EventIDsToMonitor = @(
    4624, # Successful Logon
    4625, # Failed Logon
    4634, # Logoff
    4647, # User-initiated Logoff
    4656, # A handle to an object was requested (often precursor to 4663)
    4663, # An attempt was made to access an object (File/Folder Access)
    4688  # A new process has been created
)

# Define a function to extract the username from various event properties
function Get-EventUserName {
    param($Event)
    $username = $null
    # Common properties where usernames are found, in order of commonality/relevance
    $usernameProperties = @('TargetUserName', 'SubjectUserName', 'ClientUserName', 'AccountName')

    foreach ($propName in $usernameProperties) {
        $prop = $Event.Properties | Where-Object {$_.Name -eq $propName}
        if ($prop) {
            $username = $prop.Value
            # Filter out common system accounts if you only want real users
            if ($username -notin @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON', 'Window Manager\DWM-1', 'UMFD-1')) {
                return $username
            }
        }
    }
    return $null # Return null if no suitable username found
}

# Get events, no time limit for the 'most recent'
# We'll order them by time descending right away to make picking the latest easier
$AllRelevantEvents = Get-WinEvent -LogName $LogName -FilterHashTable @{
    LogName = $LogName;
    ID      = $EventIDsToMonitor;
} -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Descending

$MostRecentEventPerUser = [System.Collections.Generic.List[PSObject]]::new()
$ProcessedUsers = @{} # Hashtable to keep track of users we've already added

foreach ($Event in $AllRelevantEvents) {
    $UserName = Get-EventUserName -Event $Event

    if ($UserName -and -not $ProcessedUsers.ContainsKey($UserName)) {
        # This is the most recent event for this user, add it to our list
        $MostRecentEventPerUser.Add(
            [PSCustomObject]@{
                UserName       = $UserName
                EventID        = $Event.ID
                EventMessage   = $Event.Message.Split("`n")[0] # Get first line of message for summary
                TimeCreated    = $Event.TimeCreated
                Source         = $Event.ProviderName
            }
        )
        $ProcessedUsers[$UserName] = $true # Mark this user as processed
    }
}

# Sort the final list by UserName for readability
$MostRecentEventPerUser | Sort-Object UserName | Format-Table -AutoSize -Wrap
