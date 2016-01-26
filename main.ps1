<# 
.SYNOPSIS 
    Script multi usage et de paramétrage multiples server 2012
.DESCRIPTION
    Back up  
    Installations automatisées de : Active Directory, Exchange, DHCP, DNS
.NOTES 
    Auteur : Jessy BERTAUD   - jessy.bertaud@hotmail.fr
	Inspiré de   : Thierry HAUYE - thierry.hauye@imie.fr
Version 1.0 Le 30/07/2015
#>
cls
write-host "╔════════════════════════════════════════════╗"
Write-Host "║       Script Installations Multiples       ║"
Write-Host "║────────────────────────────────────────────║"
Write-Host "║        Nom d'hote   :   "(hostname )"        ║"
Write-Host "║        Architecture :    " -NoNewline
Write-Host (Get-WMIObject win32_OperatingSystem).OSArchitecture -ForegroundColor Yellow -NoNewline
Write-Host "           ║" -ForegroundColor White
Write-Host "║        Noyau NT     :    " -NoNewline
write-host (Get-WMIObject win32_OperatingSystem).Version -ForegroundColor Green -NoNewline
Write-Host "          ║" -ForegroundColor White
Write-Host "╚════════════════════════════════════════════╝"
Write-Host "[1]- Fonction Installation Powershell v3"
Write-Host "[2]- Fonction Backup parametres"
Write-Host "[3]- Fonction Sauvegarde Fichiers"
Write-Host "[4]  Fonction Creation / Gestion ADDS"
Write-Host "[5]- Fonction Creation DHCP"
Write-Host "[6]- Fonction Creation DNS"
Write-Host "[7]- Fonction en attente de Creation "
Write-Host "[8]  Fonction Rapport Hardware"
Write-Host "[9]  Fonction Exit"

$function = Read-Host "Choisissez une fonction : 1- 9"
        
        Switch ($function)
        {
            1 {powershell_v3}
            2 {backup}
            3 {backupfiles}
            4 {menu_active_directory}
            5 {create_DHCP}
            6 {create_DNS}
            7 {}
            8 {hardware}
            9 {end_of_script}
            default {menu_default}
            
        }
        write-host "Vous avez choisi " $function



Function powershell_v3()
{
	write-host "╔════════════════════════════════════════════╗"
	Write-Host "║               Powershell V3                ║"
	write-Host "╚════════════════════════════════════════════╝"
	Write-Host ""
	Write-Host "1) Sans Proxy"
	Write-Host '2) Avec Proxy'
	Write-Host "3) Retour au menu précédent"
	$opt = Read-Host "Choix [1-3]? "

	switch ($opt)    
	{
		1 
		{
			Import-Module BitsTransfer 
			Start-BitsTransfer -Source http://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-x64.msu 
			Start-Process "Windows6.1-KB2506143-x64.msu"
		}
		2 { avec_proxy }
		3 { menu_default }
	}
}

Function backup()
{

	Write-Host "╔════════════════════════════════════════════╗"
	Write-Host "║           Backup server parameters         ║"
	Write-Host "╚════════════════════════════════════════════╝"
	Write-Host ""
	Write-Host "1) Sauvegarder les paramètres suivant: ADDS | DHCP | DNS | GPO | RAPPORT HARDWARE"
	Write-Host "2) Rapport ordinateur" 
	Write-Host "3) Retour au menu précédent"
	Write-Host ""
	$opt = Read-Host "Choix [1-3]? "
    $mycomputer=HOSTNAME.EXE

	switch ($opt)
	{
		1 
		{ 
			    
                $script = {
				#Main-function
				#### APPEL DES DIFFERENTES FONCTIONS ####
				######################################################
				###            DECLARATION OF VARIABLES            ###
				######################################################
				Get-Command -module pscx
				$date = Get-Date -Format yyyyMMdd
				$path = Split-Path -parent "C:\powershell backup\Backups\addsBackups\*.*"
				$domaine="$tld"
				function main {
					Write-Host "Bienvenue dans le script de back-up" -ForegroundColor Green
					Write-Host "Ce script va automatiquement créer des fichiers de back-up" -ForegroundColor Green
					Write-Host "L'ensemble des données seront dans C:\powershell backup\" -ForegroundColor Green
					Start-Sleep -s 2
					directory
					get-tld
					execution-policy
					adds-users
					gpo-config
					dns-export
					dhcp-config
					hardware
					
				}

				#Making directory
				function directory {
					######################################################
					###           Make DEPOSITORY BACKUPS              ###
					######################################################
					$source = "C:\powershell backup"
					If(Test-path $source) 
					{
						Remove-item $source -Force
					}
					else
					{
						Set-Location "C:\"
						New-Item -Name "powershell backup" -ItemType directory
						Set-Location "C:\powershell backup"
						New-Item -Name "Backups" -ItemType directory
						Set-Location "C:\powershell backup\Backups"
						New-Item -Name "addsBackups" -ItemType directory
						New-Item -Name "gpoBackups" -ItemType directory
						New-Item -Name "dnsBackups" -ItemType directory
						New-Item -Name "dhcpBackups" -ItemType directory
					}
					Write-Host "Vous avez créé les répertoires de back-up" -ForegroundColor Green
					#Start-Sleep -s 2
					# End of Script
					#——————————————————————————————-#
				}
				
					######################################################
					###                      GET TLD                   ###
					######################################################
				function get-tld {
					$split= @()
					$dc=Get-ADDomainController
					$split=$dc.Forest.Split(".")[0,1]
					$tld = "DC="+ $split[0] + ",DC=" + $split[1]
					#$tld
					Write-Host "Vous êtes sur le domaine "$tld -ForegroundColor Green
					#Start-Sleep -s 2
					# End of Script
					#——————————————————————————————-#
				}

					######################################################
					###             Set Execution Policy               ###
					######################################################
				function execution-policy {
					### Set of the execution policy ###
					Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
					Write-Host "Vous avez l'authorization nécessaire pour exécuter le script de back-up" -ForegroundColor Green
					#Start-Sleep -s 2
					# End of Script
					#——————————————————————————————-#
				}
				
					#######################################################
					###                EXPORT ADDS USERS               ###
					######################################################
				function adds-users {
					$logDate="$date"
					### Exportation of the ADDS in CSV file ###
					$csvfile = $path + "\export_$logDate.csv"
					$user=Get-ADUser -filter * -SearchBase $domaine
					#$user
					Get-ADUser -filter * | Out-File $csvfile
					Write-Host "Vous avez exporter avec succès les utilisateurs" -ForegroundColor Green
					#Start-Sleep -s 2
					# End of Script
					#——————————————————————————————-#
				}

					######################################################
					###                EXPORT GPO CONFIG               ###
					######################################################
				function gpo-config {
					Backup-GPO -All -Path "C:\powershell backup\Backups\gpoBackups\"
					Write-Host "Vous avez exporter avec succès les GPO" -ForegroundColor Green
					#Start-Sleep -s 2
					# End of Script
					#——————————————————————————————-#
				}
					######################################################
					###                EXPORT DNS CONFIG               ###
					######################################################
				function dns-export {
					#– DEFINE VARIABLE——#

					#– DEFINE VARIABLE——#

					# Get Name of the server with env variable

					$DNSSERVER=get-content env:computername

					#—Define folder where to store backup  —–#
					$BkfFolder=”C:\powershell backup\Backups\dnsBackups”

					#—Define file name where to store Dns Settings
					$StrFile=Join-Path $BkfFolder “input.csv”

					#—-Check if folder exists. if exists, delete contents–#
					if (-not(test-path $BkfFolder)) {
					new-item $BkfFolder -Type Directory | Out-Null
					} else {

					Remove-Item $BkfFolder”\*” -recurse
					}

					#—- GET DNS SETTINGS USING WMI OBJECT ——–#
					#– Line wrapped should be only one line –#
					$List = get-WmiObject -ComputerName $DNSSERVER -Namespace root\MicrosoftDNS -Class MicrosoftDNS_Zone

					#—-Export information into input.csv file —#
					#– Line wrapped should be only one line –#
					$list | Select Name,ZoneType,AllowUpdate,@{Name=”MasterServers”;Expression={$_.MasterServers}},
					DsIntegrated | Export-csv $strFile -NoTypeInformation

					#— Call Dnscmd.exe to export dns zones
					$list | foreach {
					$path=”backup\”+$_.name
					$cmd=”dnscmd {0} /ZoneExport {1} {2}” -f $DNSSERVER,$_.Name,$path
					Invoke-Expression $cmd
					}
					Write-Host "Vous avez exporter avec succès les paramètres DNS" -ForegroundColor Green
					#Start-Sleep -s 2
					# End of Script
					#——————————————————————————————-#
				}
				######################################################
				###               EXPORT DHCP CONFIG               ###
				######################################################
				function dhcp-config {
					### Display IPv4 table ###
					$scope = Get-DhcpServerv4Scope | fl
					### IPv4 backup export ###
					Backup-DhcpServer -path "C:\powershell backup\Backups\dhcpBackups"
					Write-Host "Vous avez exporter avec succès les paramètres DHCP" -ForegroundColor Green
					#Start-Sleep -s 2
					# End of Script
					#——————————————————————————————-#
				}

				######################################################
				###                 IP PUBLIQUE                    ###
				######################################################
				function ippublic {
					#Variables
					# I am defining website url in a variable;
					$url = "http://checkip.dyndns.com" 
					# Creating a new .Net Object names a System.Net.Webclient
					$webclient = New-Object System.Net.WebClient
					# In this new webdownlader object we are telling $webclient to download the
					# url $url 
					$Ip = $webclient.DownloadString($url)
					# Just a simple text manuplation to get the ipadress form downloaded URL
					# If you want to know what it contain try to see the variable $Ip
					$Ip2 = $Ip.ToString()
					$ip3 = $Ip2.Split(" ")
					$ip4 = $ip3[5]
					$ip5 = $ip4.replace("</body>","")
					$FinalIPAddress = $ip5.replace("</html>","")

				#Write Ip Addres to the console
					$FinalIPAddress
					# End of Script
					#——————————————————————————————-#
				}
				######################################################
				###           EXPORT HARDWARE CONFIG               ###
				######################################################
				<#function hardware {
					$computerSystem = Get-CimInstance CIM_ComputerSystem
					$computerBIOS = Get-CimInstance CIM_BIOSElement
					$computerOS = Get-CimInstance CIM_OperatingSystem
					$computerCPU = Get-CimInstance CIM_Processor
					$computerHDD1 = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = 'C:'"
					$computerHDD2 = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = 'D:'"
					$licence = powershell "(Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey"
					$dhcp = Get-DhcpServerv4Scope
					
					# I am defining website url in a variable;
					$url = "http://checkip.dyndns.com" 
					# Creating a new .Net Object names a System.Net.Webclient
					$webclient = New-Object System.Net.WebClient
					# In this new webdownlader object we are telling $webclient to download the
					# url $url 
					$Ip = $webclient.DownloadString($url)
					# Just a simple text manuplation to get the ipadress form downloaded URL
					# If you want to know what it contain try to see the variable $Ip
					$Ip2 = $Ip.ToString()
					$ip3 = $Ip2.Split(" ")
					$ip4 = $ip3[5]
					$ip5 = $ip4.replace("</body>","")
					$FinalIPAddress = $ip5.replace("</html>","")
					$ippublic = $FinalIPAddress
					Clear-Host

					echo "System Information for: " $computerSystem.Name > "C:\powershell backup\Backups\rapport.txt"
					"Manufacturer: " + $computerSystem.Manufacturer >> "C:\powershell backup\Backups\rapport.txt"
					"Model: " + $computerSystem.Model >> "C:\powershell backup\Backups\rapport.txt"
					"Serial Number: " + $computerBIOS.SerialNumber >> "C:\powershell backup\Backups\rapport.txt"
					"CPU: " + $computerCPU.Name >> "C:\powershell backup\Backups\rapport.txt" 
					"HDD C: Capacity: "  + "{0:N2}" -f ($computerHDD1.Size/1GB) + "GB" >> "C:\powershell backup\Backups\rapport.txt"
					"HDD C: Space: " + "{0:P2}" -f ($computerHDD1.FreeSpace/$computerHDD1.Size) + " Free (" + "{0:N2}" -f ($computerHDD1.FreeSpace/1GB) + "GB)" >> "C:\powershell backup\Backups\rapport.txt"
					"HDD D: Capacity: "  + "{0:N2}" -f ($computerHDD2.Size/1GB) + "GB" >> "C:\powershell backup\Backups\rapport.txt"
					"HDD D: Space: " + "{0:P2}" -f ($computerHDD2.FreeSpace/$computerHDD2.Size) + " Free (" + "{0:N2}" -f ($computerHDD2.FreeSpace/1GB) + "GB)" >> "C:\powershell backup\Backups\rapport.txt"
					"RAM: " + "{0:N2}" -f ($computerSystem.TotalPhysicalMemory/1GB) + "GB" >> "C:\powershell backup\Backups\rapport.txt"
					"Operating System: " + $computerOS.caption + ", Service Pack: " + $computerOS.ServicePackMajorVersion >> "C:\powershell backup\Backups\rapport.txt"
					"Operating System Licence: " + $licence >> "C:\powershell backup\Backups\rapport.txt"
					"Public IP is: " + $ippublic >> "C:\powershell backup\Backups\rapport.txt"
					"DHCP Scope is:" + $scope >> "C:\powershell backup\Backups\rapport.txt"
					"DHCP IPv4 start:"  + $dhcp.StartRange.IPAddressToString >> "C:\powershell backup\Backups\rapport.txt"
					"DHCP IPv4 stop: " + $dhcp.EndRange.IPAddressToString >> "C:\powershell backup\Backups\rapport.txt"
					"DHCP Subnet: " + $dhcp.SubnetMask.IPAddressToString >> "C:\powershell backup\Backups\rapport.txt"
					"Last Reboot: " + $computerOS.LastBootUpTime >> "C:\powershell backup\Backups\rapport.txt"
				}    
				#Entry point
				main#>
			}

			Invoke-Command -ComputerName $mycomputer -Scriptblock $script
    	}
        2 {
        systeminfo > info.txt }
		3 
		{ menu_default }

	}
}

Function backupfiles()
{
	write-host "╔════════════════════════════════════════════╗"
	Write-Host "║               Backup Files                 ║"
	write-Host "╚════════════════════════════════════════════╝"
	Write-Host ""
	Write-Host "1) Sauvegarder votre repertoire"
	Write-Host '2) Not Disponible'
	Write-Host "3) Retour au menu précédent"
	$opt = Read-Host "Choix [1-3]? "

	switch ($opt)    
	{
		1 
		{
			Clear-Host

            function Test_Dossier
            {# déclaration des paramètres utilisés (chemin et dossier)
                param([string]$chem,[string]$rep)
            # traitement : test existence du dossier et création
                if(!(Test-Path ($chem+"\"+$rep))){
                    New-Item -Path $chem -name $rep -ItemType directory | Out-Null
                }
            }

            Clear-Host
            $lect = Read-Host "Indiquer le lecteur de destination de la sauvegarde"
            $rep  = Read-Host "Indiquer le répertoire de la sauvegarde"
            if(!(test-path ($lect+":\"+$rep))){
                Clear-Host
                Write-Host ("Le répertoire de sauvegarde " + $lect.ToUpper() + ":\" + $rep.ToUpper() + " n'existe pas")
                Write-Host "Procédure de sauvegarde annulée ..."
            }
        else {
            Clear-Host
            $user=Get-ItemProperty -Path 'registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
            $nom=(get-item Env:\USERNAME).value
            $save=($lect+":\"+$rep).ToUpper()

            Write-Host ("   Sauvegarde en cours de " + $save)
            Write-Host ("   Vers "+$save+"\"+$annee+"\"+$mois+"\"+$jour+"\"+(Get-Item Env:\USERNAME).value)
            Write-Host "   Merci de patienter quelques instants SVP ..."

            # extraction année, mois, jour pour arborescence sauvegarde
            $annee   = Get-Date -UFormat %Y
            $mois    = Get-Date -UFormat %m
            $jour    = Get-Date -UFormat %d
   
            # test existence des dossiers de sauvegarde (année, mois, jour, user)
    
            $chemin = $save
            Test_Dossier $chemin $annee
    
            $chemin = ($save+"\"+$annee)
            Test_Dossier $chemin $mois

            $chemin = ($chemin+"\"+$mois)
            Test_Dossier $chemin $jour

            $chemin = ($chemin+"\"+$jour)
            Test_Dossier $chemin $nom

            # sauvegarde
            Copy-Item ($user.personal) -Destination ($chemin+"\"+$nom) -Recurse -ErrorAction SilentlyContinue

            Clear-Host
            Write-Host "Sauvegarde Terminée ..." -ForegroundColor Red
        }
		}
		3 { menu_default }

	}
}

Function menu_active_directory()
{

	write-host "╔════════════════════════════════════════════╗"
	Write-Host "║              Active Directory              ║"
	Write-Host "╚════════════════════════════════════════════╝"
	Write-Host ""
	Write-Host "1) Création du domaine"
	Write-Host "2) Création des utilisateurs" 
	Write-Host "3) Retour au menu précédent"
	$opt = Read-Host "Choix [1-3]? "

	switch ($opt)    
	{
		1 { create_Domain }
		2 { create_AD_user }
		3 { menu_default }
	}
}

Function create_Domain()
{
	$domaine = read-host("Nom de domaine ?  (Exemple: domaine.tld)")
	write-host "Choix du Niveau fonctionnel"
	write-host 
	write-host "1) Windows Server 2003/R2"
	write-host "2) Windows Server 2008R2"
	write-host "3) Windows Server 2008/R2"
	write-host "4) Windows Server 2012"
    write-host "5) Windows Server 2012/R2"
	
	$choix = Read-Host "Choix [1-5]?"
	switch ($choix)  
	{ 
		1 {$niveau_fonctionnel = "Win2003"}
		2 {$niveau_fonctionnel = "Win2008"}
		3 {$niveau_fonctionnel = "Win2008R2"}
		4 {$niveau_fonctionnel = "Win2012"}
        5 {$niveau_fonctionnel = "Win2012R2"}
		6 { menu_default } 
	}

	$netbios = $domaine.Split(".")
	$netbios1 = $netbios[0]
	if ((Get-WMIObject win32_OperatingSystem).Version -ge '6.2') #Si windows server 2012 et suivant....
	{
		Add-WindowsFeature AD-Domain-Services
		Import-Module ADDSDeployment
		Install-ADDSForest `
			-CreateDnsDelegation:$false `
			-DatabasePath "C:\Windows\NTDS" `
			-DomainMode $niveau_fonctionnel `
			-DomainName $domaine `
			-DomainNetbiosName $netbios1 `
			-ForestMode $niveau_fonctionnel `
			-InstallDns:$true `
			-LogPath "C:\Windows\NTDS" `
			-NoRebootOnCompletion:$false `
			-SysvolPath "C:\Windows\SYSVOL" `
			-Force:$true
	}
	else #Si windows server 2003/R2 - 2008/R2
	{ 
		if ($choix -eq 1) {$niveau_fonctionnel = "1"}
		elseif ($choix -eq 2) {$niveau_fonctionnel = "2"} 
		elseif ($choix -eq 3) {$niveau_fonctionnel = "3"} 
		$mot_de_passe = Read-Host "Mot de passe Administrateur ?"
		
		#Si noyau NT inférieur à windows server 2008
		if ((Get-WMIObject win32_OperatingSystem).Version -lt '6.1')
		{ 
			echo [DCINSTALL] > rep.txt
			echo ReplicaOrNewDomain=Domain >> rep.txt
			echo TreeOrChild=Tree >> rep.txt
			echo CreateOrJoin=Create >>rep.txt
			echo NewDomainDNSName=$domaine >> rep.txt
			echo DNSOnNetwork=yes >> rep.txt
			echo DomainNetbiosName=$netbios1 >> rep.txt
			echo AutoConfigDNS=yes >> rep.txt
			echo SiteName=$netbios1 >> rep.txt
			echo AllowAnonymousAccess=no >> rep.txt
			echo DatabasePath=C:\Windows\ntds >> rep.txt
			echo LogPath=C:\Windows\ntds >> rep.txt
			echo SYSVOLPath=C:\Windows\sysvol >> rep.txt
			echo SafeModeAdminPassword=$mot_de_passe >> rep.txt
			echo CriticalReplicationOnly=No >> rep.txt
			echo RebootOnSuccess=yes >> rep.txt
			dcpromo /answer:.\rep.txt
			del rep.txt
		}
		else #Si noyau NT supérieur à windows server 2003R2
		{
			echo [DCINSTALL] > rep.txt
			echo ReplicaOrNewDomain=Domain >> rep.txt
			echo NewDomain=forest >> rep.txt
			echo InstallDNS=yes >> rep.txt
			echo NewDomainDNSName=$domaine >> rep.txt
			echo DomainNetbiosName=$netbios1 >> rep.txt
			echo ForestLevel=$niveau_fonctionnel >> rep.txt
			echo DomainLevel=$niveau_fonctionnel >> rep.txt
			echo SiteName=$netbios1 >> rep.txt
			echo DatabasePath=%systemroot%\ntds >> rep.txt
			echo LogPath=%systemroot%\ntds >> rep.txt
			echo SYSVOLPath=%systemroot%\sysvol >> rep.txt
			echo SafeModeAdminPassword=$mot_de_passe >> rep.txt
			echo RebootOnCompletion=Yes >> rep.txt
			dcpromo /unattend:.\rep.txt
			del rep.txt
		}
	}
}

Function create_AD_user()
{

	write-host "╔═════════════════════════════════════╗"
	Write-Host "║     AD Création des utilisateurs    ║"
	Write-Host "╚═════════════════════════════════════╝"

	Write-Host "1) Importer avec un fichier CSV (entête du type LastName,FirstName,Groupe,OU,Password)"
	Write-Host "2) Not disponible" 
	Write-Host "3) Retour au menu précédent"
	$opt = Read-Host "Choix [1-3]? "

	switch ($opt)    
	{
		1 
		{ 
        	Import-Module ActiveDirectory
        	[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        	$objForm = New-Object System.Windows.Forms.OpenFileDialog
        	$objForm.showHelp = $true
        	$objForm.Title = "Emplacement du fichier CSV :"
        	$objForm.FilterIndex = 3
        	$objForm.Filter = "Fichier CSV |*.CSV"
        	$Show = $objForm.ShowDialog()
 
        	If ($Show -eq "Cancel")
        	{
        		echo "Annulé par l'utilisateur"
        	} 
        	else
        	{                
        		# Variables ###
		        $DC1 = $domaine.Split(".")
		        $dc = "DC="+$DC1[0]+",DC="+$DC1[1]
		        [int]$compte = 0
		        [string]$liste = ""
		        ################

		        $SourceDonnees=import-csv $objForm.FileName  
		        $liste_ou = new-object string[] $SourceDonnees.Count

		        #Création des OU
		        for ($i=0;$i -lt $SourceDonnees.Count; $i++) 
		        {                
		        	$liste_ou[$i] = enlever_accents($SourceDonnees[$i].OU)              
		        } 

				#Suppression des doublons
        		$liste_ou = $liste_ou | select -uniq 
                
        		foreach($ouou in $liste_ou)
        		{
            
        			[string]$ouexiste = Get-ADOrganizationalUnit -Filter {Name -like $ouou}
                    
        			if($ouexiste.Length -eq 0)
        			{		
				        Write-Host "Création de l'OU $ouou" -ForegroundColor Green; Write-Host""
				        New-ADOrganizationalUnit -Name $ouou
                    }
        			else
        			{		
        				Write-Host "L'OU $ouou existe déjà --> on passe" -ForegroundColor Yellow; Write-Host""
        			}
        		}
                
        		#Création des groupes
        		$liste_groupe = new-object string[] $SourceDonnees.Count
                
        		for ($i=0;$i -lt $SourceDonnees.Count; $i++) 
        		{                
			        $liste_groupe[$i] = enlever_accents($SourceDonnees[$i].Groupe)              
		        } 

        		$liste_groupe = $liste_groupe | select -uniq #Supression des doublons
                
        		foreach($groupepe in $liste_groupe)
        		{
		        	[string]$groupexiste = Get-ADGroup -LDAPFilter "(name=$groupepe)"
		        	if($groupexiste.Length -eq 0)
		        	{
		        		Write-Host "Création du Groupe $groupepe" -ForegroundColor Green ; Write-Host""                  
		        		New-ADGroup -Name $groupepe -GroupScope Global -GroupCategory Security -Description "Groupe $groupepe"
		        	}
		        	else
		        	{
		        		Write-Host "Le groupe $groupepe existe déjà --> on passe" -ForegroundColor Yellow; Write-Host""
		        	}
		        }


        		foreach($donnee in $SourceDonnees)
        		{
        			$nom=enlever_accents($donnee.LastName)
			        $prenom=enlever_accents($donnee.FirstName)
			        $ou1=enlever_accents($donnee.OU)
			        $groupe=enlever_accents($donnee.Groupe)

        			### Création d'un utilisateur

			        $dc = "DC="+$DC1[0]+",DC="+$DC1[1]
			        $dom = $domaine
			        $ou = "OU=$ou1"
			        $gp = $groupe                
			        $sn=$prenom
			        $cn=$prenom + " " + $nom
			        $nomsam=($prenom + "." + $nom).ToLower()
			        $upn=($nomsam + "@" + $dom).ToLower()
			        $chemin="ou=" + $ou1 + "," + $dc
			        $password = ConvertTo-SecureString "Pa@ssword" -AsPlainText -Force

			        [string]$userexiste = Get-ADUser -LDAPFilter "(name=$cn)"
        			if($userexiste.Length -eq 0)
        			{
				        Write-Host  ""
				        Write-Host  "Création de l'utilisateur $cn" -ForegroundColor Green;
				        New-ADUser -Name $cn -AccountPassword $password -Enabled 1 -EmailAddress $upn -ChangePasswordAtLogon 1 -SamAccountName $nomsam -UserPrincipalName $upn -Path $chemin
				        $liste = $liste + $cn + ", "
				        $compte++
				    }
        			else
        			{
				        Write-Host  ""
				        Write-Host "L'utilisateur $cn existe déja --> on passe" -ForegroundColor Yellow
        			}             

        			#vérification de l'appartenance de l'utilisateur au groupe                
			        if (!(Get-ADGroupMember -Identity  $gp | Where-Object name -Match $cn))
			        {
			        	#Ajout de l'utilisateur au groupe
			        	Write-Host "Ajout de l'utilisateur $cn au groupe $gp" -ForegroundColor Green
			        	Add-ADGroupMember -Identity $gp –Member $nomsam
			        }
        			else
        			{
			        	Write-Host "L'utilisateur $cn est déjà dans le groupe $gp --> on passe" -ForegroundColor Yellow
			        } 
			    }

        		if($liste.Length -ne 0)
        		{
        			echo ""
        			if ($compte -eq 1)
					{ 
						$liste=$liste.Replace(',',''); write-host "$compte utilisateur (" $liste ") à été créer" -ForegroundColor Cyan; echo ""
					}
        			else
					{ 
						write-host "$compte utilisateurs (" $liste ") ont été crés" -ForegroundColor Cyan; echo ""
					}
        		}
        		else
        		{
        			echo ""
        			write-host "Pas de nouveaux utilisateurs" -ForegroundColor green
        			echo ""
                }
            }
        }

	3 
	{ 
		menu_default }
		default {write-host $msg}
	}
}

Function create_DHCP()
{
	write-host "╔════════════════════════════════════════════╗"
	Write-Host "║               Creation DHCP                ║"
	write-Host "╚════════════════════════════════════════════╝"
	Write-Host ""
	Write-Host "1) Creation d'etendue DHCP"
	Write-Host "2) Not Disponible"
	Write-Host "3) Retour au menu précédent"
	$opt = Read-Host "Choix [1-3]? "

	switch ($opt)    
	{
		1 
		{
            Write-host "Veuillez renseigner le nom de l'etendue a creer"
            $scopename = Read-host
            Write-host "Veuillez renseigner la description de l'etendue a creer"
            $scopedesc = Read-host
            do
            {
                Write-host "Veuillez renseigner l'IP de départ"
                $scopestartrange = Read-host
                if($scopestartrange -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
                {
                    Write-Host "SUCCESS - Right format !" -ForegroundColor Green
                    $ok = $true
                }
                else
                {
                    Write-Host "FAIL - Wrong format !" -ForegroundColor Red
                    $ok = $false
                }
            }
            until($ok)
            do
            {
                Write-host "Veuillez renseigner l'IP de fin"
                $scopeendrange = Read-host
                if($scopeendrange -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
                {
                    Write-Host "SUCCESS - Right format !" -ForegroundColor Green
                    $ok = $true
                }
                else
                {
                    Write-Host "FAIL - Wrong format !" -ForegroundColor Red
                    $ok = $false
                }
            }
            until($ok)
            do
            {
                Write-host "Veuillez renseigner le masque de sous-reseau"
                $scopenetmask = Read-host
                if($scopenetmask -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
                {
                    Write-Host "SUCCESS - Right format !" -ForegroundColor Green
                    $ok = $true
                }
                else
                {
                    Write-Host "FAIL - Wrong format !" -ForegroundColor Red
                    $ok = $false
                }
            }
            until($ok)
            do
            {
                Write-host "Veuillez renseigner le DNS primaire"
                $dns1 = Read-Host
                if($dns1 -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
                {
                    Write-Host "SUCCESS - Right format !" -ForegroundColor Green
                    $ok = $true
                }
                else
                {
                    Write-Host "FAIL - Wrong format !" -ForegroundColor Red
                    $ok = $false
                }
            }
            until($ok)
            do
            {
                Write-host "Veuillez renseigner le DNS secondaire"
                $dns2 = Read-Host
                if($dns2 -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
                {
                    Write-Host "SUCCESS - Right format !" -ForegroundColor Green
                    $ok = $true
                }
                else
                {
                    Write-Host "FAIL - Wrong format !" -ForegroundColor Red
                    $ok = $false
                }
            }
            until($ok)
                       
            # Tableau de DNS
            $dnsArray = @($dns1 , $dns2)


            ## INSTALLATION

            $result = Install-WindowsFeature -Name "DHCP" -IncludeAllSubFeature -IncludeManagementTools
            if($result.ExitCode -like "Success")
            {
                Write-Host "SUCESS : L'installation du rôle ServerDHCP a réussi" -ForegroundColor Green
            }
            else
            {
                Write-Host "FAIL : Echec de l'installation du rôle ServerDHCP - Code de retour = `""$result.ExitCode"`"" -ForegroundColor Red
            }

            # PARAMETRAGE

            # On crée le scope mais on le laisse inactif par défaut afin de réaliser d'autres paramétrages
            Add-DhcpServerv4Scope -Name $scopename -Description $scopedesc `
                                    -StartRange $scopestartrange -EndRange $scopeendrange `
                                    -SubnetMask $scopenetmask -State InActive

            # On récupère le scope crée
            $scope = Get-DhcpServerv4Scope | Where-Object {$_.Name -like $scopename}

            # On injecte l'option server dns dans pour le scope DHCP crée
            Set-DhcpServerv4OptionValue -ScopeId $scope.ScopeId -OptionId 5 $dnsArray

            # On passe le scope du server dhcp en "Active"
            Set-DhcpServerv4Scope -ScopeId $scope.ScopeId -State Active

            # FIN DE L'INSTALLATION
            # DEMARRAGE / REDEMARRAGE DU SERVICE

            $isDHCPRunning = ((Get-Service -Name "DHCPServer").Status -like "Running")
            if($isDHCPRunning)
            {
                # Si running, on redémarre
                Restart-Service -Name "DHCPServer"
            }
            else
            {
                # Sinon on démarre le service
                Start-Service -Name "DHCPServer"
            }
            
        }
		
		3 { menu_default }
	        
    }
}

Function create_DNS()
{
	write-host "╔════════════════════════════════════════════╗"
	Write-Host "║               Creation DNS                 ║"
	write-Host "╚════════════════════════════════════════════╝"
	Write-Host ""
	Write-Host "1) Creation de zone DNS"
	Write-Host "2) Not Disponible"
	Write-Host "3) Retour au menu précédent"
	$opt = Read-Host "Choix [1-3]? "

	switch ($opt)    
	{
		1 
		{
            #Si le DNS n'a pas été installé avec l'ADDS suivre ces étapes
            Get-WindowsFeature -Name "*dns*"
            Install-WindowsFeature -Name "DNS" -IncludeAllSubFeature -IncludeManagementTools
            write-host "Les composants du DNS ont été installés" -ForegroundColor Green
            Get-DnsServer
            Write-Host "Veuillez renseigner le nom de la zone primaire"
            $domain = Read-Host
            Add-DnsServerPrimaryZone -Name $domain -ReplicationScope Domain 
            #Add-DnsServerPrimaryZone -NetworkId "192.168.57.1/24" #-ZoneFile "57.168.192.in-addr.arpa
            Add-DnsServerPrimaryZone  -NetworkId "192.168.57.0/24"
            write-host "Le serveur DNS a été installé et les zones direct et inverses configurés" -ForegroundColor Green
            
        }
		
		3 { menu_default }
	        
    }
}

function hardware() 
{
        $computerSystem = Get-CimInstance CIM_ComputerSystem
        $computerBIOS = Get-CimInstance CIM_BIOSElement
        $computerOS = Get-CimInstance CIM_OperatingSystem
        $computerCPU = Get-CimInstance CIM_Processor
        $computerHDD1 = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = 'C:'"
        $computerHDD2 = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = 'D:'"
        $licence = powershell "(Get-WmiObject -query ‘select * from SoftwareLicensingService’).OA3xOriginalProductKey"
        $dhcp = Get-DhcpServerv4Scope
        
        # I am defining website url in a variable;
	    $url = "http://checkip.dyndns.com" 
	    # Creating a new .Net Object names a System.Net.Webclient
	    $webclient = New-Object System.Net.WebClient
	    # In this new webdownlader object we are telling $webclient to download the
	    # url $url 
	    $Ip = $webclient.DownloadString($url)
	    # Just a simple text manuplation to get the ipadress form downloaded URL
        # If you want to know what it contain try to see the variable $Ip
	    $Ip2 = $Ip.ToString()
	    $ip3 = $Ip2.Split(" ")
	    $ip4 = $ip3[5]
	    $ip5 = $ip4.replace("</body>","")
	    $FinalIPAddress = $ip5.replace("</html>","")
        $ippublic = $FinalIPAddress
        Clear-Host

        Write-Host "Ou souhaitez-vous sauvegarder le rapport"
        $paths = Read-Host
        Set-Location $paths
        Write-Host "Comment nommez-vous le rapport"
        $report = Read-Host
        $sum = $paths  +  $report

        echo "System Information for: " $computerSystem.Name > $sum
        "Manufacturer: " + $computerSystem.Manufacturer >> $sum
        "Model: " + $computerSystem.Model >> $sum
        "Serial Number: " + $computerBIOS.SerialNumber >> $sum
        "CPU: " + $computerCPU.Name >> $sum
        "HDD C: Capacity: "  + "{0:N2}" -f ($computerHDD1.Size/1GB) + "GB" >> $sum
        "HDD C: Space: " + "{0:P2}" -f ($computerHDD1.FreeSpace/$computerHDD1.Size) + " Free (" + "{0:N2}" -f ($computerHDD1.FreeSpace/1GB) + "GB)" >> $sum
        "HDD D: Capacity: "  + "{0:N2}" -f ($computerHDD2.Size/1GB) + "GB" >> $sum
        "HDD D: Space: " + "{0:P2}" -f ($computerHDD2.FreeSpace/$computerHDD2.Size) + " Free (" + "{0:N2}" -f ($computerHDD2.FreeSpace/1GB) + "GB)" >> $sum
        "RAM: " + "{0:N2}" -f ($computerSystem.TotalPhysicalMemory/1GB) + "GB" >> $sum
        "Operating System: " + $computerOS.caption + ", Service Pack: " + $computerOS.ServicePackMajorVersion >> $sum
        "Operating System Licence: " + $licence >> $sum
        "Public IP is: " + $ippublic >> $sum
        "DHCP IPv4 start:"  + $dhcp.StartRange.IPAddressToString >> $sum
        "DHCP IPv4 stop: " + $dhcp.EndRange.IPAddressToString >> $sum
        "DHCP Subnet: " + $dhcp.SubnetMask.IPAddressToString >> $sum
        "Last Reboot: " + $computerOS.LastBootUpTime >> $sum
}    

Function end_of_script()
{
    cls
    exit
}
