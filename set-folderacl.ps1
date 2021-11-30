####################################################################################
#.Synopsis 
#
#
#.Parameter Path 
#.Parameter Username
#   
#
#
#Requires Powershell -Version 2.0
#
#.Notes 
#  Author:  Garrett Wehner 
# Version:  2.0
# Updated:  6/22/16
#   LEGAL: PUBLIC DOMAIN.  SCRIPT PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF 
#          ANY KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR
#          A PARTICULAR PURPOSE.  ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF
#          THE AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF
#          ANY SUCH DAMAGE.  IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
#          LIABILITY, THEN DELETE THIS FILE SINCE YOU ARE NOW PROHIBITED TO HAVE IT.
####################################################################################

    
Function Set-FolderACL {

[CmdletBinding()]
Param(
 	[Parameter(ValueFromPipeline=$true,Mandatory=$true,
    HelpMessage="The folder path")] 
 	[string]$path,
	[Parameter(ValueFromPipeline=$false,Mandatory=$true,
    HelpMessage="The user's Accountname")] 
	[string]$username,
	[Parameter(ValueFromPipeline=$False,Mandatory=$false,
    HelpMessage="The permission to allow(example: FullControl)")] 
	[string]$permission="FullControl")
 
Begin {}

Process {
#set home folder permissions
$principal=new-object system.security.principal.NTAccount("$username")
$acl=get-acl $path
$RuleToAdd=new-object System.Security.AccessControl.FileSystemAccessRule($principal,$permission,"ContainerInherit,ObjectInherit","None","Allow")   
$acl.SetAccessRule($RuleToAdd)
set-acl -Path $path -AclObject $acl

#set home folder permissions System account
$SYSTEMAC=New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
$RuleToAdd=new-object System.Security.AccessControl.FileSystemAccessRule("$SYSTEMAC",$permission,"ContainerInherit,ObjectInherit","None","Allow")        
$acl.SetAccessRule($RuleToAdd)
set-acl -Path $path -AclObject $acl

#set home folder permissions Creator owner account
$CREATORAC=New-Object System.Security.Principal.NTAccount("NT AUTHORITY\CREATOR OWNER")
$RuleToAdd=new-object System.Security.AccessControl.FileSystemAccessRule("$CREATORAC",$permission,"ContainerInherit,ObjectInherit","None","Allow")        
$acl.SetAccessRule($RuleToAdd)
set-acl -Path $path -AclObject $acl

#set home folder permissions Domain Admins account
$DomainAdmins=New-Object System.Security.Principal.NTAccount("Domain Admins")
$RuleToAdd=new-object System.Security.AccessControl.FileSystemAccessRule("$DomainAdmins",$permission,"ContainerInherit,ObjectInherit","None","Allow")        
$acl.SetAccessRule($RuleToAdd)
set-acl -Path $path -AclObject $acl

#set owner of folder to the user
$acl.SetOwner($principal)
set-acl -Path $path -AclObject $acl
}

End {}
} #end Function
