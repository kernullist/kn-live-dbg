param(
    [string]$Root = (Get-Location).Path,

    [string]$ArticleHtml = "",

    [string]$ArticleUrl = "",

    [string]$ArticleOutPath = ""
)

$ErrorActionPreference = "Stop"

function Read-TextFile
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path))
    {
        throw "file not found: $Path"
    }

    return Get-Content -LiteralPath $Path -Raw
}

function New-ParentDirectoryIfMissing
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent))
    {
        return
    }
    if (-not (Test-Path -LiteralPath $parent))
    {
        New-Item -ItemType Directory -Path $parent | Out-Null
    }
}

function Save-ArticleHtmlFromUrl
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    New-ParentDirectoryIfMissing -Path $Path
    Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
}

function Test-RequiredText
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Needle,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [System.Collections.Generic.List[string]]$Failures
    )

    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)
    {
        $Failures.Add("missing ${Name}: $Needle")
    }
}

function Test-ForbiddenText
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Needle,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [System.Collections.Generic.List[string]]$Failures
    )

    if ($Text.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    {
        $Failures.Add("unexpected ${Name}: $Needle")
    }
}

function Test-OrderedText
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string[]]$Needles,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [System.Collections.Generic.List[string]]$Failures
    )

    $offset = 0
    foreach ($needle in $Needles)
    {
        $match = $Text.IndexOf($needle, $offset, [System.StringComparison]::OrdinalIgnoreCase)
        if ($match -lt 0)
        {
            $Failures.Add("missing ordered ${Name}: $needle")
            return
        }

        $offset = $match + $needle.Length
    }
}

function Get-IocTuple
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Sha1
    )

    $needle = "L`"$($Sha1.ToLowerInvariant())`""
    $start = $Source.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase)
    if ($start -lt 0)
    {
        return $null
    }

    $end = $Source.IndexOf("}", $start, [System.StringComparison]::Ordinal)
    if ($end -lt 0)
    {
        return $null
    }

    return $Source.Substring($start, $end - $start + 1)
}

function Get-HtmlTableTexts
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Html
    )

    $texts = @()
    $tables = [regex]::Matches($Html, "<table[\s\S]*?</table>", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($table in $tables)
    {
        $text = [regex]::Replace($table.Value, "<[^>]+>", " ")
        $text = [System.Net.WebUtility]::HtmlDecode($text)
        $text = [regex]::Replace($text, "\s+", " ").Trim()
        $texts += $text
    }

    return $texts
}

function Get-EsetArticleSha1s
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$TableTexts
    )

    if ($TableTexts.Count -lt 5)
    {
        return @()
    }

    return @(
        [regex]::Matches($TableTexts[4], "\b([0-9A-Fa-f]{20})\s+([0-9A-Fa-f]{20})\b") |
            ForEach-Object { ($_.Groups[1].Value + $_.Groups[2].Value).ToLowerInvariant() } |
            Sort-Object -Unique
    )
}

function Get-EsetArticleTable2Targets
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$TableTexts
    )

    if ($TableTexts.Count -lt 2)
    {
        return @()
    }

    return @(
        [regex]::Matches(
            $TableTexts[1],
            "\b[A-Za-z0-9_.-]+\.exe\b",
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) |
            ForEach-Object { $_.Value.ToLowerInvariant() } |
            Sort-Object -Unique
    )
}

function Get-EsetArticleTable34ProcessIndicators
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$TableTexts
    )

    if ($TableTexts.Count -lt 4)
    {
        return @()
    }

    $combined = "$($TableTexts[2]) $($TableTexts[3])"
    return @(
        [regex]::Matches(
            $combined,
            "[A-Za-z0-9]+(?:<suffix>)?\.exe",
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) |
            ForEach-Object { $_.Value.ToLowerInvariant() } |
            Sort-Object -Unique
    )
}

function Get-EsetArticleTable34DriverIndicators
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$TableTexts
    )

    if ($TableTexts.Count -lt 4)
    {
        return @()
    }

    $combined = "$($TableTexts[2]) $($TableTexts[3])"
    $drivers = [System.Collections.Generic.List[string]]::new()
    foreach ($match in [regex]::Matches(
            $combined,
            "[A-Za-z0-9_()|.-]+\.sys",
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
    {
        $value = $match.Value.ToLowerInvariant()
        if ($value -eq "stpm_(old|new).sys")
        {
            $drivers.Add("stpm_old.sys")
            $drivers.Add("stpm_new.sys")
        }
        else
        {
            $drivers.Add($value)
        }
    }

    if ($combined.IndexOf("IMFForceDelete", [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    {
        $drivers.Add("imfforcedelete")
    }
    if ($combined.IndexOf("PoisonX", [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
    {
        $drivers.Add("poisonx")
    }

    return @($drivers | Sort-Object -Unique)
}

$hunterPath = Join-Path $Root "user\UserModeHunter.cpp"
$mainPath = Join-Path $Root "user\main.cpp"
$wfpScannerPath = Join-Path $Root "user\WfpScanner.cpp"
$wfpScannerHeaderPath = Join-Path $Root "user\WfpScanner.h"
$targetPath = Join-Path $Root "hunt_test_target\KnLiveDbgHuntTarget.cpp"
$readmePath = Join-Path $Root "README.md"
$testDocPath = Join-Path $Root "docs\HUNT_TEST_TARGET.md"
$coveragePath = Join-Path $Root "docs\WINDBG_COMMAND_COVERAGE.md"
$architecturePath = Join-Path $Root "docs\ARCHITECTURE.md"
$readinessPath = Join-Path $Root "tools\validate-hunt-readiness.ps1"
$e2eRunnerPath = Join-Path $Root "tools\run-eset-hunt-e2e.ps1"
$e2eArtifactValidatorPath = Join-Path $Root "tools\validate-eset-hunt-e2e-artifacts.ps1"
$e2eBundleMakerPath = Join-Path $Root "tools\make-eset-hunt-e2e-vm-bundle.ps1"

if (-not [string]::IsNullOrWhiteSpace($ArticleUrl))
{
    if ([string]::IsNullOrWhiteSpace($ArticleOutPath))
    {
        if ([string]::IsNullOrWhiteSpace($ArticleHtml))
        {
            $ArticleOutPath = Join-Path $Root ".build\eset-article-current.html"
        }
        else
        {
            $ArticleOutPath = $ArticleHtml
        }
    }
    if (-not [System.IO.Path]::IsPathRooted($ArticleOutPath))
    {
        $ArticleOutPath = Join-Path $Root $ArticleOutPath
    }

    Save-ArticleHtmlFromUrl -Url $ArticleUrl -Path $ArticleOutPath
    $ArticleHtml = $ArticleOutPath
}

$hunter = Read-TextFile -Path $hunterPath
$main = Read-TextFile -Path $mainPath
$wfpScanner = Read-TextFile -Path $wfpScannerPath
$wfpScannerHeader = Read-TextFile -Path $wfpScannerHeaderPath
$targetSource = Read-TextFile -Path $targetPath
$readme = Read-TextFile -Path $readmePath
$testDoc = Read-TextFile -Path $testDocPath
$coverage = Read-TextFile -Path $coveragePath
$architecture = Read-TextFile -Path $architecturePath
$readiness = Read-TextFile -Path $readinessPath
$e2eRunner = Read-TextFile -Path $e2eRunnerPath
$e2eArtifactValidator = Read-TextFile -Path $e2eArtifactValidatorPath
$e2eBundleMaker = Read-TextFile -Path $e2eBundleMakerPath

$expected = @(
    [pscustomobject]@{ Sha1 = "8ae6bd18b129061f63642531f1b684cf0383c75d"; File = "Kasps.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "ba914fe77b177b45799403b16dd14765c510a074"; File = "eb.sys"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "d605994fc72a2bb59b5cfb1624a1b9170eca73a2"; File = "FaceIT1.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "b0b912a3fd1c05d72080848ec4c92880004021a1"; File = "nseckrnl.sys"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "5aa3124e5c4921e5edfc60133b5d71da21b07da3"; File = "Valorant2.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "7556ae58c215b8245a43f764f0676c7a8f0fdd1a"; File = "vgk.sys"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "331879f5eec8892bbd896f90bdbb1bad0bf63bd6"; File = "EASolo2Light.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "f11aebccb9a86a7e2e653f90baec697f233c255f"; File = "EASOLO1clear.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "ef9cd06683159397f099caa244e94e6eaad96eba"; File = "EAAntiCheatLight.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "711ef221526997039e804a18db9647c91680bbe2"; File = "stpm_old.sys"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "68fec379f2ae76c3d2ce913f7be650cea1d06990"; File = "stpm_new.sys"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "a11ee9cdc59e5caa59aefd27b30d104f3ad68e62"; File = "BitD1.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "96f0dbf52aed0afd43e44500116b04b674f7358e"; File = "dmx.sys"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "2f86898528c6cab3540c486a9bfaa0c029b73950"; File = "MB2.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "9ad51ad97c01e97ab59214116740785e0f6320a8"; File = "360netmon_wfp.sys"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "a19117175dbc9ba4d23b5dce8415e299a2e32192"; File = "Deletor.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "12500f6c87ce62712a0ed6652c57468d15c14223"; File = "IMFForceDelete"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "d29670e684e40ddc89b47010c37cbc96737035b6"; File = "Symantec.exe"; Family = "GentleKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "56bee9df5833a637f5c54d5911df98b0812fe643"; File = "G11.sys"; Family = "GentleKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "cf4d74df17a91b4a36a2911b22afec5d8fa93a01"; File = "Avast.exe"; Family = "HexKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "ec296f9501ad71e430810cb5cdc38d954d4ba536"; File = "googleApiUtil64.sys"; Family = "HexKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "7131b377e96016dc1911020c9f95b1b4d042d7b4"; File = "Sent.exe"; Family = "ThrottleBlood"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "82ed942a52cdcf120a8919730e00ba37619661a3"; File = "ThrottleBlood.sys"; Family = "ThrottleBlood"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "f0537cbb773ae12100b36731e7c39f5a9d852b14"; File = "Sophos.exe"; Family = "HavocKiller"; Process = $true; Driver = $false; Credential = $false },
    [pscustomobject]@{ Sha1 = "1fa071303fb846308571e64727501fb98b1c2be6"; File = "havoc.sys"; Family = "HavocKiller"; Process = $false; Driver = $true; Credential = $false },
    [pscustomobject]@{ Sha1 = "a5cf917ec4a7dfbdfa43621398604805d860c718"; File = "buildx641.exe"; Family = "OxideHarvest"; Process = $true; Driver = $false; Credential = $true },
    [pscustomobject]@{ Sha1 = "d4b19141102015d436321e6f26976e98183cfd27"; File = "buildx64.exe"; Family = "OxideHarvest"; Process = $true; Driver = $false; Credential = $true }
)

$expectedProcessProfiles = @(
    "kasps.exe",
    "kasp1.exe",
    "faceit1.exe",
    "valorant2.exe",
    "easolo2light.exe",
    "easolo1clear.exe",
    "eaanticheatlight.exe",
    "bitd1.exe",
    "mb2.exe",
    "deletor.exe",
    "g11.exe",
    "symantec.exe",
    "avast.exe",
    "sent.exe",
    "sophos.exe",
    "hwaudkiller.exe",
    "buildx641.exe",
    "buildx64.exe"
)

$expectedProcessSuffixBases = @(
    "kasps",
    "kasp",
    "faceit",
    "valorant",
    "easolo",
    "eaanticheat",
    "bitd",
    "mb",
    "g11",
    "symantec",
    "avast",
    "sent",
    "sophos"
)

$expectedDriverProfiles = @(
    "eb.sys",
    "nseckrnl.sys",
    "vgk.sys",
    "gamedriverx64.sys",
    "stpm_old.sys",
    "stpm_new.sys",
    "dmx.sys",
    "360netmon_wfp.sys",
    "360netmon.sys",
    "imfforcedelete",
    "poisonx",
    "poisonx.sys",
    "g11.sys",
    "googleapiutil64.sys",
    "throttleblood.sys",
    "havoc.sys"
)

$expectedArticleTable34ProcessIndicators = @(
    "kasp<suffix>.exe",
    "faceit<suffix>.exe",
    "valorant<suffix>.exe",
    "eaanticheat<suffix>.exe",
    "easolo<suffix>.exe",
    "bitd<suffix>.exe",
    "mb<suffix>.exe",
    "deletor.exe",
    "g11<suffix>.exe",
    "symantec<suffix>.exe",
    "avast<suffix>.exe",
    "sent<suffix>.exe",
    "hwaudkiller.exe",
    "sophos<suffix>.exe"
)

$expectedArticleTable34DriverIndicators = @(
    "eb.sys",
    "nseckrnl.sys",
    "gamedriverx64.sys",
    "stpm_old.sys",
    "stpm_new.sys",
    "dmx.sys",
    "360netmon_wfp.sys",
    "imfforcedelete",
    "poisonx",
    "googleapiutil64.sys",
    "throttleblood.sys",
    "havoc.sys"
)

$expectedSecurityProductTargets = @(
    "acronis_agent.exe",
    "backupandrecoveryagent.exe",
    "managementagenthost.exe",
    "mms.exe",
    "alienvault-agent.exe",
    "osqueryd.exe",
    "afwserv.exe",
    "aswengsrv.exe",
    "aswidsagent.exe",
    "aswtoolssvc.exe",
    "avastsvc.exe",
    "avastui.exe",
    "bccavsvc.exe",
    "wsc_proxy.exe",
    "avgui.exe",
    "avgsvc.exe",
    "avgnt.exe",
    "avgsvca.exe",
    "avgtoolssvc.exe",
    "binarydefenseagent.exe",
    "arrakis3.exe",
    "bdavscanner.exe",
    "bdfstray.exe",
    "bdfileserver.exe",
    "bdlived2.exe",
    "bdlogger.exe",
    "bdscheduler.exe",
    "bdstatistics.exe",
    "bdagent.exe",
    "bdemsrv.exe",
    "bdntwrk.exe",
    "bdredline.exe",
    "bdregsvr2.exe",
    "bdservicehost.exe",
    "blumiraagent.exe",
    "bromiumdaemon.exe",
    "brdifxapi.exe",
    "cb.exe",
    "cbcomms.exe",
    "cbdefense.exe",
    "carbonsensor.exe",
    "repmgr.exe",
    "cfrutil.exe",
    "ciscoampcefwdriver.exe",
    "cisco_amp_connector.exe",
    "immunet.exe",
    "arwsrvc.exe",
    "arcupdate.exe",
    "csfalconcontainer.exe",
    "csfalconservice.exe",
    "csfalconui.exe",
    "csfalcondataprotect.exe",
    "csfalcondaterepair.exe",
    "reprsvc.exe",
    "cyneteps.exe",
    "cynetms.exe",
    "cynetsvc.exe",
    "activeconsole.exe",
    "cybereason.exe",
    "cybereasonactiveprobe.exe",
    "cybereasoncr.exe",
    "cyveraconsole.exe",
    "cyveraservice.exe",
    "cyvragentsvc.exe",
    "cyvrfsflt.exe",
    "cylancesvc.exe",
    "darktracetsa.exe",
    "deepinstinct.exe",
    "deepinstinctservice.exe",
    "diagentservice.exe",
    "a2guard.exe",
    "a2service.exe",
    "eamonm.exe",
    "eamsi.exe",
    "ecls.exe",
    "efwd.exe",
    "egui.exe",
    "eguiproxy.exe",
    "ekrn.exe",
    "ekrnepfw.exe",
    "eraagent.exe",
    "eraagentsvc.exe",
    "firesvc.exe",
    "firetray.exe",
    "fortitray.exe",
    "fortiedr.exe",
    "fw.exe",
    "gddserver.exe",
    "qhpisvr.exe",
    "quhlpsvc.exe",
    "sapissvc.exe",
    "heimdalsecurityagent.exe",
    "huntressagent.exe",
    "huntressrmm.exe",
    "avp.exe",
    "avpsus.exe",
    "avpui.exe",
    "kavfs.exe",
    "kavfsscs.exe",
    "kavfswh.exe",
    "kavfswp.exe",
    "kavtray.exe",
    "klactprx.exe",
    "klcsldcl.exe",
    "klcsweb.exe",
    "klnagent.exe",
    "klnagchk.exe",
    "klscctl.exe",
    "klserver.exe",
    "klwtblfs.exe",
    "kpf4ss.exe",
    "ksde.exe",
    "ksdeui.exe",
    "vapm.exe",
    "logprocessorservice.exe",
    "agmservice.exe",
    "agsservice.exe",
    "masvc.exe",
    "macmnsvc.exe",
    "mcafeeagent.exe",
    "mcshield.exe",
    "mfeann.exe",
    "mfevtps.exe",
    "mfetp.exe",
    "mfeepehost.exe",
    "mfefire.exe",
    "mfemactl.exe",
    "mfemacsvc.exe",
    "mfemgr.exe",
    "mfemms.exe",
    "mgntsvc.exe",
    "modulecoreservice.exe",
    "tepfsvc.exe",
    "msascui.exe",
    "msascuil.exe",
    "mpdefendercoreservice.exe",
    "msmpeng.exe",
    "msmpsvc.exe",
    "mssense.exe",
    "msseces.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "sensecncproxy.exe",
    "senseir.exe",
    "sensendr.exe",
    "sensesampleuploader.exe",
    "smartscreen.exe",
    "windefend.exe",
    "morphisecservice.exe",
    "ccapp.exe",
    "ccsvchst.exe",
    "ns.exe",
    "nsservice.exe",
    "nortonsecurity.exe",
    "rtvscan.exe",
    "sepmasterservice.exe",
    "sepwscsvc64.exe",
    "smc.exe",
    "smcgui.exe",
    "snac.exe",
    "symcorpui.exe",
    "symwsc.exe",
    "ossec-agent.exe",
    "wazuh-agent.exe",
    "cortexservice.exe",
    "trapsagent.exe",
    "trapsd.exe",
    "traps.exe",
    "panda_url_filtering.exe",
    "pavfnsvr.exe",
    "pavsrv.exe",
    "psanhost.exe",
    "pselamsvc.exe",
    "psuamain.exe",
    "psuaservice.exe",
    "pangps.exe",
    "qualys-cloud-agent.exe",
    "qualysagent.exe",
    "ir_agent.exe",
    "rapid7_endpoint.exe",
    "redcanaryagent.exe",
    "csaagent.exe",
    "csaservice.exe",
    "sangforagent.exe",
    "sangforcsa.exe",
    "sangforedr.exe",
    "sangforinterface.exe",
    "sangformonitor.exe",
    "sangforprotect.exe",
    "sangforservice.exe",
    "sangfortray.exe",
    "sangforud.exe",
    "sentinel.exe",
    "sentinelagent.exe",
    "sentinelagentworker.exe",
    "sentinelctl.exe",
    "sentinelhelperservice.exe",
    "sentinelmemoryscanner.exe",
    "sentinelpowershellextension.exe",
    "sentinelranger.exe",
    "sentinelservicehost.exe",
    "sentinelstaticengine.exe",
    "sentinelstaticenginescanner.exe",
    "sentinelui.exe",
    "sonicwallclientprotectionservice.exe",
    "swc_service.exe",
    "hmpalert.exe",
    "mcsagent.exe",
    "mcsclient.exe",
    "savapi.exe",
    "savadminservice.exe",
    "savservice.exe",
    "sedservice.exe",
    "sophosadsyncservice.exe",
    "sophosclean.exe",
    "sophoscleanm64.exe",
    "sophosfimservice.exe",
    "sophosfs.exe",
    "sophoshealth.exe",
    "sophoslivequeryservice.exe",
    "sophosmtr.exe",
    "sophosmtrextension.exe",
    "sophosnetfilter.exe",
    "sophosntpservice.exe",
    "sophososquery.exe",
    "sophososqueryextension.exe",
    "sophos.policyevaluation.service.exe",
    "sophossafestore64.exe",
    "sophosui.exe",
    "sophosupdatemgr.exe",
    "sophosav.exe",
    "sophossps.exe",
    "sspservice.exe",
    "taniumclient.exe",
    "taniumcx.exe",
    "tanclient.exe",
    "threatlockerconsent.exe",
    "threatlockerservice.exe",
    "threatlockertray.exe",
    "coreframeworkhost.exe",
    "coreserviceshell.exe",
    "ntrtscan.exe",
    "ofcservice.exe",
    "ofcddasvr.exe",
    "pccntmon.exe",
    "pccnt.exe",
    "tisafe.exe",
    "tisafesvc.exe",
    "tmccsf.exe",
    "tmicagentsetting.exe",
    "tmbmsrv.exe",
    "tm_netsrv.exe",
    "tmlisten.exe",
    "tmntsrv.exe",
    "tmpfw.exe",
    "tmproxy.exe",
    "tmprefilter.exe",
    "tmssclient.exe",
    "tmsainstance64.exe",
    "tmwscsvc.exe",
    "voneagentconsole.exe",
    "voneagentconsoletray.exe",
    "vectoragent.exe",
    "uptycsagent.exe",
    "datadvantage.exe",
    "varonisagent.exe",
    "wlcsservice.exe",
    "wrsa.exe",
    "wrskyclient.exe",
    "wrsvc.exe",
    "sysmon.exe",
    "sysmon64.exe",
    "zlclient.exe"
)

$failures = [System.Collections.Generic.List[string]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$seenSecurityTargets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$articleTableCount = $null
$articleSha1Count = $null
$articleTargetCount = $null
$articleTable34ProcessCount = $null
$articleTable34DriverCount = $null

# The public HTML Table 2 currently exposes 286 process tokens / 274 unique
# lower-case image names. The article prose says "more than 400 processes"; this
# gate intentionally tracks the published table rows that can be independently
# scraped from the article.
if ($expectedSecurityProductTargets.Count -ne 274)
{
    $failures.Add("expected 274 lower-cased unique ESET Table 2 targets, got $($expectedSecurityProductTargets.Count)")
}

if ($expected.Count -ne 27)
{
    $failures.Add("expected 27 ESET file IoCs, got $($expected.Count)")
}

$expectedProcessCount = @($expected | Where-Object { $_.Process }).Count
$expectedDriverCount = @($expected | Where-Object { $_.Driver }).Count
$expectedCredentialCount = @($expected | Where-Object { $_.Credential }).Count
if ($expectedProcessCount -ne 15)
{
    $failures.Add("expected 15 ESET process-image IoCs, got $expectedProcessCount")
}
if ($expectedDriverCount -ne 12)
{
    $failures.Add("expected 12 ESET driver-image IoCs, got $expectedDriverCount")
}
if ($expectedCredentialCount -ne 2)
{
    $failures.Add("expected 2 ESET OxideHarvest credential-tool IoCs, got $expectedCredentialCount")
}
if ($expectedProcessProfiles.Count -ne 18)
{
    $failures.Add("expected 18 ESET process profiles, got $($expectedProcessProfiles.Count)")
}
if ($expectedProcessSuffixBases.Count -ne 13)
{
    $failures.Add("expected 13 ESET process suffix bases, got $($expectedProcessSuffixBases.Count)")
}
if ($expectedDriverProfiles.Count -ne 16)
{
    $failures.Add("expected 16 ESET driver profiles, got $($expectedDriverProfiles.Count)")
}
if ($expectedArticleTable34ProcessIndicators.Count -ne 14)
{
    $failures.Add("expected 14 ESET Table 3/4 process indicators, got $($expectedArticleTable34ProcessIndicators.Count)")
}
if ($expectedArticleTable34DriverIndicators.Count -ne 12)
{
    $failures.Add("expected 12 ESET Table 3/4 driver indicators, got $($expectedArticleTable34DriverIndicators.Count)")
}

foreach ($ioc in $expected)
{
    if (-not $seen.Add($ioc.Sha1))
    {
        $failures.Add("duplicate expected sha1: $($ioc.Sha1)")
    }

    $tuple = Get-IocTuple -Source $hunter -Sha1 $ioc.Sha1
    if ($null -eq $tuple)
    {
        $failures.Add("missing ESET SHA1 tuple: $($ioc.Sha1) $($ioc.File)")
        continue
    }

    Test-RequiredText -Text $tuple -Needle "L`"$($ioc.File)`"" -Name "filename for $($ioc.Sha1)" -Failures $failures
    Test-RequiredText -Text $tuple -Needle "L`"$($ioc.Family)`"" -Name "family for $($ioc.Sha1)" -Failures $failures

    $expectedFlags = ", $($ioc.Process.ToString().ToLowerInvariant()), $($ioc.Driver.ToString().ToLowerInvariant()), $($ioc.Credential.ToString().ToLowerInvariant())"
    Test-RequiredText -Text $tuple -Needle $expectedFlags -Name "type flags for $($ioc.Sha1)" -Failures $failures
}

foreach ($profile in $expectedProcessProfiles)
{
    Test-RequiredText -Text $hunter -Needle "L`"$profile`"" -Name "ESET process profile" -Failures $failures
}

foreach ($suffixBase in $expectedProcessSuffixBases)
{
    Test-RequiredText -Text $hunter -Needle "L`"$suffixBase`"" -Name "ESET process suffix base" -Failures $failures
}

foreach ($driver in $expectedDriverProfiles)
{
    Test-RequiredText -Text $hunter -Needle "L`"$driver`"" -Name "ESET driver profile" -Failures $failures
}

foreach ($securityTarget in $expectedSecurityProductTargets)
{
    if (-not $seenSecurityTargets.Add($securityTarget))
    {
        $failures.Add("duplicate ESET Table 2 security product target: $securityTarget")
    }

    Test-RequiredText -Text $hunter -Needle "L`"$securityTarget`"" -Name "ESET Table 2 security product target" -Failures $failures
}

if (-not [string]::IsNullOrWhiteSpace($ArticleHtml))
{
    if (-not (Test-Path -LiteralPath $ArticleHtml))
    {
        $failures.Add("article HTML file not found: $ArticleHtml")
    }
    else
    {
        $articleText = Read-TextFile -Path $ArticleHtml
        $articleTables = @(Get-HtmlTableTexts -Html $articleText)
        $articleTableCount = $articleTables.Count
        if ($articleTables.Count -lt 6)
        {
            $failures.Add("expected at least 6 tables in ESET article HTML, got $($articleTables.Count)")
        }

        $articleSha1s = @(Get-EsetArticleSha1s -TableTexts $articleTables)
        $articleSha1Count = $articleSha1s.Count
        $expectedSha1s = @($expected | ForEach-Object { [string]$_.Sha1.ToLowerInvariant() } | Sort-Object -Unique)
        $missingArticleSha1s = @($expectedSha1s | Where-Object { $articleSha1s -notcontains $_ })
        $unexpectedArticleSha1s = @($articleSha1s | Where-Object { $expectedSha1s -notcontains $_ })
        if ($missingArticleSha1s.Count -ne 0 -or $unexpectedArticleSha1s.Count -ne 0)
        {
            $failures.Add("ESET article Table 5 SHA-1 set mismatch; missing=$($missingArticleSha1s -join ',') unexpected=$($unexpectedArticleSha1s -join ',')")
        }

        $articleTargets = @(Get-EsetArticleTable2Targets -TableTexts $articleTables)
        $articleTargetCount = $articleTargets.Count
        $expectedTargets = @($expectedSecurityProductTargets | Sort-Object -Unique)
        $missingArticleTargets = @($expectedTargets | Where-Object { $articleTargets -notcontains $_ })
        $unexpectedArticleTargets = @($articleTargets | Where-Object { $expectedTargets -notcontains $_ })
        if ($missingArticleTargets.Count -ne 0 -or $unexpectedArticleTargets.Count -ne 0)
        {
            $failures.Add("ESET article Table 2 target set mismatch; missing=$($missingArticleTargets -join ',') unexpected=$($unexpectedArticleTargets -join ',')")
        }

        $articleTable34Processes = @(Get-EsetArticleTable34ProcessIndicators -TableTexts $articleTables)
        $articleTable34ProcessCount = $articleTable34Processes.Count
        $expectedTable34Processes = @($expectedArticleTable34ProcessIndicators | Sort-Object -Unique)
        $missingTable34Processes = @($expectedTable34Processes | Where-Object { $articleTable34Processes -notcontains $_ })
        $unexpectedTable34Processes = @($articleTable34Processes | Where-Object { $expectedTable34Processes -notcontains $_ })
        if ($missingTable34Processes.Count -ne 0 -or $unexpectedTable34Processes.Count -ne 0)
        {
            $failures.Add("ESET article Table 3/4 process indicator mismatch; missing=$($missingTable34Processes -join ',') unexpected=$($unexpectedTable34Processes -join ',')")
        }

        $articleTable34Drivers = @(Get-EsetArticleTable34DriverIndicators -TableTexts $articleTables)
        $articleTable34DriverCount = $articleTable34Drivers.Count
        $expectedTable34Drivers = @($expectedArticleTable34DriverIndicators | Sort-Object -Unique)
        $missingTable34Drivers = @($expectedTable34Drivers | Where-Object { $articleTable34Drivers -notcontains $_ })
        $unexpectedTable34Drivers = @($articleTable34Drivers | Where-Object { $expectedTable34Drivers -notcontains $_ })
        if ($missingTable34Drivers.Count -ne 0 -or $unexpectedTable34Drivers.Count -ne 0)
        {
            $failures.Add("ESET article Table 3/4 driver indicator mismatch; missing=$($missingTable34Drivers -join ',') unexpected=$($unexpectedTable34Drivers -join ',')")
        }
    }
}

$sourceRequired = @(
    "eset_exact_file_sha1_ioc",
    "edr_killer_exact_file_sha1_ioc",
    "oxideharvest_exact_file_sha1_ioc",
    "loaded_driver_file_hash_ioc",
    "driver_service_file_hash_ioc",
    "driver_service_installed",
    "native_api_driver_control",
    "deviceiocontrol_or_driver_object_activity",
    "defense_impairment_telemetry",
    "known_security_product_process_target",
    "edr_killer_invalid_code_signature",
    "edr_killer_version_info_impersonation_evidence",
    "edr_killer_icon_impersonation_evidence",
    "edr_killer_packer_section_evidence",
    "AddEsetFileHashProcessFinding(result, process, &processSha1Cache);",
    "AddEsetLoadedDriverHashHuntFindings(result, byovd);",
    "FindEsetFileSha1Ioc(serviceHash.Sha1, false, true)",
    "TrimServiceImagePathWhitespace",
    "trimmed.front() == L'`"'",
    "DriverServiceKnownExtensionlessImagePath",
    "gentlekiller_security_target_list",
    "openprocess",
    "desiredaccess",
    "allocvm",
    "protectvm",
    "readvm",
    "writevm",
    "mapview",
    "queueuserapc",
    "setthreadcontext",
    "suspend",
    "resume",
    "bool addEvasionReasons",
    "addEvasionReasons && metadata.SignaturePresent && !metadata.SignatureValid",
    "addEvasionReasons && !metadata.PackerSectionNames.empty()",
    "metadataEvasionEvidence",
    "profile == nullptr &&",
    "!metadataEvasionEvidence",
    '{ L"hwaudkiller.exe", nullptr'
)

foreach ($needle in $sourceRequired)
{
    Test-RequiredText -Text $hunter -Needle $needle -Name "hunt source coverage" -Failures $failures
}

Test-ForbiddenText -Text $hunter -Needle '{ L"hwaudkiller.exe", L"hwaudkiller"' -Name "stale HwAudKiller suffix-normalized profile" -Failures $failures

Test-RequiredText -Text $main -Needle 'StartsWithNoCase(lowered, L"eset_")' -Name "console high-signal ESET prefix" -Failures $failures
Test-RequiredText -Text $main -Needle 'StartsWithNoCase(lowered, L"gentlekiller_")' -Name "console high-signal GentleKiller prefix" -Failures $failures
Test-RequiredText -Text $main -Needle 'lowered == L"known_security_product_process_target"' -Name "console high-signal security-product target reason" -Failures $failures
Test-RequiredText -Text $main -Needle 'PrintHuntConclusion(result, warningCount);' -Name "console hunt conclusion renderer" -Failures $failures
Test-RequiredText -Text $main -Needle 'PrintHuntAssessment(result);' -Name "console hunt assessment renderer" -Failures $failures
Test-RequiredText -Text $main -Needle 'PrintHuntSummaryLine(result);' -Name "console hunt summary renderer" -Failures $failures
Test-RequiredText -Text $main -Needle 'PrintHuntHighSignalTable(result);' -Name "console hunt high-signal renderer" -Failures $failures
Test-RequiredText -Text $main -Needle 'PrintHuntTriageTables(result);' -Name "console hunt top triage renderer" -Failures $failures
Test-RequiredText -Text $main -Needle 'verdict = result.Findings.size() >= 1000 ? L"alert_noisy" : L"alert";' -Name "console noisy alert verdict" -Failures $failures
Test-RequiredText -Text $hunter -Needle '\"edr_killer_driver_services\"' -Name "hunt JSON EDR-killer driver-service summary" -Failures $failures
Test-RequiredText -Text $hunter -Needle '\"threat_intel_correlations\"' -Name "hunt JSON threat-intel correlation summary" -Failures $failures
Test-RequiredText -Text $hunter -Needle "ResolveEprocessMainSectionBackingPath" -Name "hunt EPROCESS main section resolver" -Failures $failures
Test-RequiredText -Text $hunter -Needle "main_section_object_vad_backing_mismatch" -Name "hunt main section object VAD mismatch reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "kernel_main_section_swap_evidence" -Name "hunt kernel main section swap reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle '"main_section_backing_path"' -Name "hunt JSON main section backing path" -Failures $failures
Test-RequiredText -Text $main -Needle "main_section_object_vs_vad_backing_mismatch" -Name "console main section object mismatch label" -Failures $failures
Test-RequiredText -Text $hunter -Needle "ControlAreaBackingDetails" -Name "hunt control-area backing detail resolver" -Failures $failures
Test-RequiredText -Text $hunter -Needle "process_tampering_primitive_evidence" -Name "hunt process tampering primitive reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "main_image_vad_file_delete_pending" -Name "hunt main image delete-pending reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "main_section_object_file_section_object_pointer_mismatch" -Name "hunt section-object-pointer mismatch reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "module_stomping_permission_evidence" -Name "hunt module-stomping permission evidence reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "module_entrypoint_write_permission_drift" -Name "hunt module entrypoint write drift reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "AddWfpHuntFindings" -Name "hunt WFP integration" -Failures $failures
Test-RequiredText -Text $hunter -Needle "security_tool_communication_blocking" -Name "hunt WFP communication-blocking reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "wfp_security_product_block_filter" -Name "hunt WFP security-product block reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "wfp_anticheat_block_filter" -Name "hunt WFP anti-cheat block reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle "wfp_appid_block_condition" -Name "hunt WFP AppId block reason" -Failures $failures
Test-RequiredText -Text $hunter -Needle '\"suspicious_wfp_filters\"' -Name "hunt JSON suspicious WFP summary" -Failures $failures
Test-RequiredText -Text $wfpScannerHeader -Needle "AppIdText" -Name "WFP record AppId field" -Failures $failures
Test-RequiredText -Text $wfpScannerHeader -Needle "ConditionsText" -Name "WFP record condition text field" -Failures $failures
Test-RequiredText -Text $wfpScanner -Needle "FWPM_CONDITION_ALE_APP_ID" -Name "WFP ALE AppId condition decoder" -Failures $failures
Test-RequiredText -Text $wfpScanner -Needle "FormatFilterConditionsText" -Name "WFP filter condition formatter" -Failures $failures
Test-RequiredText -Text $main -Needle "process_tampering_primitive_evidence" -Name "console process tampering primitive label" -Failures $failures
Test-RequiredText -Text $main -Needle "module_stomping_permission_evidence" -Name "console module-stomping permission label" -Failures $failures
Test-RequiredText -Text $main -Needle "security_tool_communication_blocking" -Name "console WFP communication-blocking label" -Failures $failures
Test-RequiredText -Text $main -Needle "security_communication_blocking" -Name "console WFP assessment kind" -Failures $failures
Test-RequiredText -Text $main -Needle 'kind = L"process_tampering"' -Name "console process tampering assessment kind" -Failures $failures
Test-RequiredText -Text $main -Needle 'kind = L"module_stomping"' -Name "console module-stomping assessment kind" -Failures $failures
Test-RequiredText -Text $main -Needle 'kind = L"mapped_code_or_loader_evasion"' -Name "console mapped-code assessment kind" -Failures $failures
Test-RequiredText -Text $main -Needle "process main image or section backing was swapped" -Name "console process tampering assessment text" -Failures $failures
Test-RequiredText -Text $main -Needle "loaded module code or section permissions indicate module stomping" -Name "console module-stomping assessment text" -Failures $failures
Test-RequiredText -Text $readme -Needle "kernel_main_section_swap_evidence" -Name "README main section swap documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "process_tampering_primitive_evidence" -Name "README process tampering primitive documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "module_stomping_permission_evidence" -Name "README module stomping permission documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "security_tool_communication_blocking" -Name "README WFP communication-blocking documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "kernel_main_section_swap_evidence" -Name "hunt target main section swap documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "process_tampering_primitive_evidence" -Name "hunt target process tampering primitive documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "security_tool_communication_blocking" -Name "hunt target WFP communication-blocking documentation" -Failures $failures
Test-RequiredText -Text $coverage -Needle "kernel_main_section_swap_evidence" -Name "command coverage main section swap documentation" -Failures $failures
Test-RequiredText -Text $coverage -Needle "process_tampering_primitive_evidence" -Name "command coverage process tampering primitive documentation" -Failures $failures
Test-RequiredText -Text $coverage -Needle "module_stomping_permission_evidence" -Name "command coverage module stomping permission documentation" -Failures $failures
Test-RequiredText -Text $coverage -Needle "security_tool_communication_blocking" -Name "command coverage WFP communication-blocking documentation" -Failures $failures
Test-OrderedText `
    -Text $main `
    -Needles @(
        'PrintHuntConclusion(result, warningCount);',
        'PrintHuntAssessment(result);',
        'PrintHuntSummaryLine(result);',
        'if (summaryOnly)',
        'PrintHuntHighSignalTable(result);',
        'PrintHuntTriageTables(result);'
    ) `
    -Name "hunt console answer-before-raw-table render order" `
    -Failures $failures
Test-RequiredText -Text $targetSource -Needle "/hunt-parser-check" -Name "quoted SCM ImagePath test fixture" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "/hunt-parser-check-unquoted-extensionless" -Name "unquoted extensionless SCM ImagePath test fixture" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "/stop-event" -Name "hunt target graceful stop-event option" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "WaitForMultipleObjects(waitCount, waitHandles, FALSE, waitMs)" -Name "hunt target external stop-event wait" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "Available hunt target experiments:" -Name "hunt target interactive experiment menu" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "Select a focused experiment. Each item explains what the target creates" -Name "hunt target operator-readable menu intro" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "category: " -Name "hunt target menu category field" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "creates : " -Name "hunt target menu artifact field" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "hunt    : " -Name "hunt target menu hunt expectation field" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "should explain process masquerading and staging evidence" -Name "hunt target readable process-profile expectation" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "should report both loader-view evasion and module stomping" -Name "hunt target readable complex-scenario expectation" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "Without a scenario flag, it opens the numbered experiment menu below." -Name "hunt target no-flag interactive contract" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "PromptScenarioMenuSelection" -Name "hunt target interactive selection parser" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "the target prints a numbered experiment menu" -Name "hunt target interactive menu documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "Each menu entry explains the category" -Name "hunt target readable menu documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "runs only the selected experiment set" -Name "hunt target selected-only documentation" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "expected_class" -Name "hunt target expected class manifest field" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "expected_risk" -Name "hunt target expected risk manifest field" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "expected_confidence" -Name "hunt target expected confidence manifest field" -Failures $failures
Test-RequiredText -Text (Read-TextFile -Path (Join-Path $Root "tools\validate-hunt-target.ps1")) -Needle '[string[]]$ExpectedEvidenceKeys = @()' -Name "hunt target validator accepts empty evidence-key arrays" -Failures $failures
Test-RequiredText -Text (Read-TextFile -Path (Join-Path $Root "tools\validate-hunt-target.ps1")) -Needle '[hashtable]$ExpectedEvidence = @{}' -Name "hunt target validator accepts empty evidence maps" -Failures $failures
Test-RequiredText -Text $readiness -Needle "New-SyntheticEsetDriverServiceValidationFiles" -Name "readiness synthetic service generator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "New-SyntheticEsetFullValidationFiles" -Name "readiness synthetic full ESET generator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "Get-EsetProcessScenarioNames" -Name "readiness shared ESET process scenario list" -Failures $failures
Test-RequiredText -Text $readiness -Needle "Assert-ManifestScenarioNames" -Name "readiness exact manifest scenario set gate" -Failures $failures
Test-RequiredText -Text $readiness -Needle "edr-killer-suffix-name-easolo-2light" -Name "readiness actual EASolo2Light scenario name" -Failures $failures
Test-RequiredText -Text $readiness -Needle "hunt-readiness-service-synthetic" -Name "readiness synthetic service output" -Failures $failures
Test-RequiredText -Text $readiness -Needle "synthetic ESET full artifact validator" -Name "readiness full ESET artifact validator smoke" -Failures $failures
Test-RequiredText -Text $readiness -Needle "hunt-readiness-full-synthetic" -Name "readiness full ESET synthetic output" -Failures $failures
Test-RequiredText -Text $readiness -Needle "/hunt-parser-check-unquoted-extensionless" -Name "readiness unquoted extensionless synthetic fixture" -Failures $failures
Test-RequiredText -Text $readiness -Needle 'expected_class = "edr_killer_driver_service"' -Name "readiness class contract" -Failures $failures
Test-RequiredText -Text $readiness -Needle 'expected_risk = $risk' -Name "readiness risk contract" -Failures $failures
Test-RequiredText -Text $readiness -Needle 'expected_confidence = $confidence' -Name "readiness confidence contract" -Failures $failures
Test-RequiredText -Text $readiness -Needle "Invoke-HuntTargetValidatorExpectedFailure" -Name "readiness validator mutated-negative helper" -Failures $failures
Test-RequiredText -Text $readiness -Needle "Invoke-EsetArtifactValidatorExpectedFailure" -Name "readiness artifact validator mutated-negative helper" -Failures $failures
Test-RequiredText -Text $readiness -Needle "interactive menu baseline smoke" -Name "readiness hunt target interactive menu smoke" -Failures $failures
Test-RequiredText -Text $readiness -Needle 'echo 1| `"$releaseTarget`" /seconds 1 /manifest `"$manifest`"' -Name "readiness hunt target interactive baseline selection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "stop-event target cleanup smoke" -Name "readiness stop-event target cleanup smoke" -Failures $failures
Test-RequiredText -Text $readiness -Needle "hunt-readiness-service-synthetic-mutated-class" -Name "readiness class mutation negative" -Failures $failures
Test-RequiredText -Text $readiness -Needle "hunt-readiness-service-synthetic-mutated-risk" -Name "readiness risk mutation negative" -Failures $failures
Test-RequiredText -Text $readiness -Needle "hunt-readiness-service-synthetic-mutated-confidence" -Name "readiness confidence mutation negative" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected duplicate_scenario=yes" -Name "readiness artifact duplicate-scenario rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected scenario_count=yes" -Name "readiness artifact scenario-count rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected summary_high=yes" -Name "readiness artifact summary-count rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "validate-eset-hunt-e2e-artifacts.ps1" -Name "readiness ESET artifact validator smoke" -Failures $failures
Test-RequiredText -Text $readiness -Needle '-Manifest ".build\hunt-readiness-service-synthetic-manifest.json"' -Name "readiness root-relative artifact manifest path" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle "/edr-killer-suffix-name" -Name "ESET E2E suffix fixture runner" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle "/oxideharvest-cli" -Name "ESET E2E OxideHarvest fixture runner" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle "/edr-killer-driver-service" -Name "ESET E2E driver-service fixture runner" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle "!hunt /deep /summary /json" -Name "ESET E2E scripted hunt command" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle "validate-eset-hunt-e2e-artifacts.ps1" -Name "ESET E2E artifact validator runner" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '-RunnerLog $runnerLog' -Name "ESET E2E runner-log validator input" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[int]$Seconds = 300' -Name "ESET E2E target lifetime default" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[int]$KnLiveDbgTimeoutSeconds = 180' -Name "ESET E2E KnLiveDbg timeout default" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[int]$TargetLifetimePaddingSeconds = 60' -Name "ESET E2E target lifetime padding default" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '$minimumTargetSeconds = $KnLiveDbgTimeoutSeconds + $TargetLifetimePaddingSeconds' -Name "ESET E2E lifetime race guard" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'target_seconds=$Seconds kn_timeout_seconds=$KnLiveDbgTimeoutSeconds target_padding_seconds=$TargetLifetimePaddingSeconds' -Name "ESET E2E lifetime diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '$Handle.Process.WaitForExit()' -Name "ESET E2E process-handle drain before disposal" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'runner.log' -Name "ESET E2E durable runner log" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[switch]$ReuseExistingTarget' -Name "ESET E2E reuse existing target switch" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[string]$ExistingStopEventName = ""' -Name "ESET E2E existing stop-event parameter" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[string]$ArticleHtml = ""' -Name "ESET E2E article HTML parameter" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[string]$ArticleUrl = ""' -Name "ESET E2E article URL parameter" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[string]$ArticleOutPath = ""' -Name "ESET E2E article output parameter" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'validate-eset-hunt-iocs.ps1' -Name "ESET E2E article currentness validator runner" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '$script:EsetHuntE2ERunnerContract = "e2e-auto-knlivedbg-article-currentness-v2"' -Name "ESET E2E runner contract value" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '$script:EsetHuntE2EExpectedScenarios = 35' -Name "ESET E2E expected scenario value" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'runner_contract=$script:EsetHuntE2ERunnerContract' -Name "ESET E2E runner contract diagnostic" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'expected_scenarios=$script:EsetHuntE2EExpectedScenarios' -Name "ESET E2E expected scenario diagnostic" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'Write-BundleInfoStatus' -Name "ESET E2E bundle-info diagnostic helper" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'manifest_progress scenarios=' -Name "ESET E2E manifest progress diagnostic" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'manifest_stopped_one_short' -Name "ESET E2E one-short manifest diagnostic" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'elevated=$isAdministrator' -Name "ESET E2E elevation diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'output_dir=$outputDir runner_log=$runnerLog' -Name "ESET E2E artifact directory diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'article_currentness=enabled' -Name "ESET E2E article currentness diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'validate ESET article currentness' -Name "ESET E2E article currentness execution step" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'article-validator.log' -Name "ESET E2E article validator log" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'eset-article-current.html' -Name "ESET E2E article HTML artifact path" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle "administrator rights are required for -ReuseExistingTarget" -Name "ESET E2E reuse admin-gate diagnostic" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle "KnLiveDbg must open the kernel driver device" -Name "ESET E2E live admin-gate diagnostic" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'reuse existing target manifest=' -Name "ESET E2E reuse manifest diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'signal existing target cleanup' -Name "ESET E2E reuse cleanup signal output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'target_pid=' -Name "ESET E2E target PID diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'target_args=' -Name "ESET E2E target argument diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'wait target manifest=' -Name "ESET E2E target manifest wait diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'failed: $($_.Exception.Message)' -Name "ESET E2E failure diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'artifacts output_dir=$outputDir manifest=$manifest hunt_json=$huntJson' -Name "ESET E2E failure artifact path diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'exited before manifest reached' -Name "ESET E2E target early-exit diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'process_snapshot name=' -Name "ESET E2E failure process snapshot diagnostic output" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'Write-TextFileTail' -Name "ESET E2E failure log-tail helper" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[string]::IsNullOrWhiteSpace($argumentText)' -Name "ESET E2E empty argument-list guard" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'Write-TextFileTail -Path $targetOut -Label "target.stdout"' -Name "ESET E2E target stdout failure tail" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle 'Write-TextFileTail -Path $knErr -Label "knlivedbg.stderr"' -Name "ESET E2E KnLiveDbg stderr failure tail" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '$stopEventName = "Local\KnLiveDbgHuntE2E-$PID-' -Name "ESET E2E named stop event allocation" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle "/stop-event" -Name "ESET E2E stop-event argument" -Failures $failures
Test-RequiredText -Text $e2eRunner -Needle '[void]$targetStopEvent.Set()' -Name "ESET E2E graceful target cleanup signal" -Failures $failures
Test-RequiredText -Text $e2eBundleMaker -Needle '$runnerContract = "e2e-auto-knlivedbg-article-currentness-v2"' -Name "ESET VM bundle runner contract value" -Failures $failures
Test-RequiredText -Text $e2eBundleMaker -Needle 'bundle_contract = $bundleContract' -Name "ESET VM bundle contract metadata" -Failures $failures
Test-RequiredText -Text $e2eBundleMaker -Needle 'runner_contract = $runnerContract' -Name "ESET VM bundle runner contract metadata" -Failures $failures
Test-RequiredText -Text $e2eBundleMaker -Needle 'BUNDLE-INFO.json' -Name "ESET VM bundle info artifact" -Failures $failures
Test-RequiredText -Text $e2eBundleMaker -Needle 'tools\validate-hunt-readiness.ps1' -Name "ESET VM bundle readiness tool inclusion" -Failures $failures
Test-RequiredText -Text $e2eBundleMaker -Needle 'validate-hunt-readiness.ps1") -Root $stageRoot -SkipSmoke' -Name "ESET VM bundle staged readiness validation" -Failures $failures
Test-RequiredText -Text $e2eBundleMaker -Needle 'x64\$Configuration\KnLiveDbg.exe' -Name "ESET VM bundle KnLiveDbg binary inclusion" -Failures $failures
Test-RequiredText -Text $e2eBundleMaker -Needle 'x64\$Configuration\tools\KnLiveDbgHuntTarget.exe' -Name "ESET VM bundle hunt target binary inclusion" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "validate-hunt-target.ps1" -Name "ESET artifact manifest validator" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle '[string]$RunnerLog' -Name "ESET artifact runner-log parameter" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "IsPathRooted" -Name "ESET artifact root-relative path handling" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "GetFullPath" -Name "ESET artifact normalized full-path handling" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "AllowEmptyString" -Name "ESET artifact default-path empty parameter handling" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "New-ParentDirectoryIfMissing" -Name "ESET artifact validator log directory handling" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "Assert-ManifestScenarioPresent" -Name "ESET artifact required scenario gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "Assert-ManifestScenarioNames" -Name "ESET artifact exact scenario-set gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "scenario_count field" -Name "ESET artifact scenario-count field gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "Assert-HuntSummaryMatchesFindings" -Name "ESET artifact summary/findings consistency gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "summary.high" -Name "ESET artifact summary risk-count gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "expected exactly 32 class/risk/confidence scenario contracts" -Name "ESET full artifact exact class-contract count gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "expected exactly 15 class/risk/confidence scenario contracts" -Name "ESET driver-service artifact exact class-contract count gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle 'expected exactly $ExpectedEdrKillerDriverServices EDR-killer driver services' -Name "ESET artifact exact driver-service count gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "summary.threat_intel_correlations" -Name "ESET artifact TI summary-count gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle 'ti_correlations=$($huntDoc.summary.threat_intel_correlations)' -Name "ESET artifact TI console summary gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "Assert-ManifestScenarioUnexpectedReasonPresent" -Name "ESET artifact negative-control scenario gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle 'if ($ExpectedScenarioCount -eq 35)' -Name "ESET artifact full E2E scenario gate condition" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "edr-killer-gentlemen-staging-only-negative" -Name "ESET artifact staging-only negative scenario gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle 'elseif ($ExpectedScenarioCount -eq 15)' -Name "ESET artifact driver-service scenario gate condition" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "required defense-evasion driver-service assessment evidence" -Name "ESET artifact full E2E driver-service assessment gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle 'driver_service_iocs=$($huntDoc.summary.edr_killer_driver_services)' -Name "ESET artifact driver-service summary count gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "edr-killer-suffix-name-easolo-2light" -Name "ESET artifact actual EASolo2Light scenario name" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "[hunt.conclusion]" -Name "ESET artifact conclusion output gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "known defense-evasion tool name" -Name "ESET artifact assessment evidence gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "known defense-evasion driver service" -Name "ESET artifact driver-service assessment evidence gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "manipulated version information" -Name "ESET artifact metadata-evasion assessment evidence gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "packed or protected PE section" -Name "ESET artifact packer assessment evidence gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "[hunt.detail] suppressed=yes" -Name "ESET artifact summary-mode suppression gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "gentlemen_related_credential_tool_name" -Name "ESET artifact OxideHarvest reason gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "driver_service_binary_name_ioc" -Name "ESET artifact driver-service reason gate" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "runner_contract=e2e-auto-knlivedbg-article-currentness-v2" -Name "ESET artifact runner contract verification" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "elevated=True" -Name "ESET artifact elevated runner verification" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle 'target ready scenarios=$ExpectedScenarioCount' -Name "ESET artifact target-ready runner verification" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "run KnLiveDbg scripted hunt" -Name "ESET artifact KnLiveDbg launch runner verification" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle '[switch]$RequireRunnerPassed' -Name "ESET artifact optional final-pass runner verification switch" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle '-RequireRunnerPassed requires -RunnerLog' -Name "ESET artifact final-pass runner-log requirement" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle "[eset-hunt-e2e] passed" -Name "ESET artifact final-pass runner verification" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle 'manifest=$manifestPath' -Name "ESET artifact final manifest-path runner verification" -Failures $failures
Test-RequiredText -Text $e2eArtifactValidator -Needle 'hunt_json=$huntJsonPath' -Name "ESET artifact final hunt-json runner verification" -Failures $failures
Test-RequiredText -Text $readiness -Needle "synthetic ESET driver-service default-path artifact validator" -Name "readiness default artifact path smoke" -Failures $failures
Test-RequiredText -Text $readiness -Needle "New-SyntheticEsetRunningDriverServiceValidationFiles" -Name "readiness running driver-service generator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "driver_service_running" -Name "readiness running driver-service reason gate" -Failures $failures
Test-RequiredText -Text $readiness -Needle "synthetic running driver-service validator=yes" -Name "readiness running driver-service validator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "New-SyntheticEsetExactHashValidationFiles" -Name "readiness exact-hash generator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "synthetic exact-hash validator=yes" -Name "readiness exact-hash validator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "loaded_driver_file_hash_ioc" -Name "readiness loaded-driver hash reason gate" -Failures $failures
Test-RequiredText -Text $readiness -Needle "driver_service_file_hash_ioc" -Name "readiness driver-service hash reason gate" -Failures $failures
Test-RequiredText -Text $readiness -Needle "oxideharvest_exact_file_sha1_ioc" -Name "readiness OxideHarvest hash reason gate" -Failures $failures
Test-RequiredText -Text $readiness -Needle "New-SyntheticEsetMetadataEvasionValidationFiles" -Name "readiness metadata-evasion generator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "synthetic metadata-evasion validator=yes" -Name "readiness metadata-evasion validator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "edr_killer_invalid_code_signature" -Name "readiness invalid signature reason gate" -Failures $failures
Test-RequiredText -Text $readiness -Needle "edr_killer_icon_impersonation_evidence" -Name "readiness icon impersonation reason gate" -Failures $failures
Test-RequiredText -Text $readiness -Needle "New-SyntheticEsetSecurityProductTelemetryValidationFiles" -Name "readiness security-product telemetry generator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "synthetic security-product telemetry validator=yes" -Name "readiness security-product telemetry validator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "security_product_target_count = `"2`"" -Name "readiness security-product target-count evidence" -Failures $failures
Test-RequiredText -Text $readiness -Needle "security_product_targets = `"msmpeng.exe;ekrn.exe`"" -Name "readiness security-product target-name evidence" -Failures $failures
Test-RequiredText -Text $readiness -Needle "-ExpectedEdrKillerDriverServices 15" -Name "readiness exact driver-service parameter gate" -Failures $failures
Test-ForbiddenText -Text $readiness -Needle "MinimumEdrKillerDriverServices" -Name "stale readiness minimum driver-service parameter" -Failures $failures
Test-RequiredText -Text $readiness -Needle "ESET IOC source coverage failed with exit code" -Name "readiness IOC validator exit-code gate" -Failures $failures
Test-RequiredText -Text $readiness -Needle "hunt-readiness-default-root" -Name "readiness default artifact isolated root" -Failures $failures
Test-RequiredText -Text $readiness -Needle "refusing to clean default artifact smoke root outside .build" -Name "readiness default artifact cleanup guard" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected class_contract_count=yes" -Name "readiness class-contract-count mutation rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected driver_service_count=yes" -Name "readiness driver-service-count mutation rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected assessment_driver_service=yes" -Name "readiness assessment driver-service mutation rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected unexpected_negative_reason=yes" -Name "readiness unexpected negative reason mutation rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected runner_log_elevated=yes" -Name "readiness runner-log elevation mutation rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected runner_log_manifest=yes" -Name "readiness runner-log manifest-path mutation rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected runner_log_required=yes" -Name "readiness runner-log required mutation rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "artifact mutation rejected runner_log_passed=yes" -Name "readiness runner-log final-pass mutation rejection" -Failures $failures
Test-RequiredText -Text $readiness -Needle "synthetic ESET full dot-relative artifact validator=yes" -Name "readiness dot-relative artifact validator smoke" -Failures $failures
Test-RequiredText -Text $readiness -Needle "git diff whitespace skipped: no .git directory in root" -Name "readiness staged bundle no-git whitespace skip" -Failures $failures
Test-RequiredText -Text $readiness -Needle "synthetic ESET full security-product telemetry validator" -Name "readiness security-product telemetry validator" -Failures $failures
Test-RequiredText -Text $readiness -Needle "security-product process targeting" -Name "readiness security-product assessment output" -Failures $failures
Test-RequiredText -Text $readiness -Needle "gentlekiller_security_target_list" -Name "readiness GentleKiller target-list telemetry reason" -Failures $failures
Test-RequiredText -Text $readiness -Needle "edr-killer-gentlemen-staging-only-negative" -Name "readiness staging-only negative scenario gate" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "StageOnlyBenign.exe" -Name "hunt target staging-only negative benign copy" -Failures $failures
Test-RequiredText -Text $targetSource -Needle "GentlemenCollection staging alone does not create a process-profile finding" -Name "hunt target staging-only negative contract" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "StageOnlyBenign.exe" -Name "hunt target staging-only negative documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "make-eset-hunt-e2e-vm-bundle.ps1" -Name "README ESET VM bundle workflow" -Failures $failures
Test-RequiredText -Text $readme -Needle "bundle_contract=eset-hunt-e2e-vm-bundle-v1" -Name "README ESET VM bundle contract" -Failures $failures
Test-RequiredText -Text $readme -Needle 'A `GentlemenCollection` path by itself is treated as supporting' -Name "README GentlemenCollection supporting-only gate" -Failures $failures
Test-RequiredText -Text $architecture -Needle 'Exact-only public filenames such as `HwAudKiller.exe` are not suffix-normalized' -Name "architecture exact HwAudKiller gate" -Failures $failures
Test-RequiredText -Text $architecture -Needle 'A `GentlemenCollection` path alone is only supporting context' -Name "architecture GentlemenCollection supporting-only gate" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "make-eset-hunt-e2e-vm-bundle.ps1" -Name "hunt target ESET VM bundle workflow" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "bundle_contract=eset-hunt-e2e-vm-bundle-v1" -Name "hunt target ESET VM bundle contract" -Failures $failures
Test-RequiredText -Text $readme -Needle "Table 3/4 process and driver indicators" -Name "README ESET Table 3/4 currentness documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "Table 3/4 process and driver indicators" -Name "hunt target ESET Table 3/4 currentness documentation" -Failures $failures

foreach ($staleScenarioName in @("edr-killer-suffix-name-kasp-light", "edr-killer-suffix-name-easolo-light", "edr-killer-suffix-name-easolo-clear"))
{
    Test-ForbiddenText -Text $readiness -Needle $staleScenarioName -Name "stale readiness scenario name" -Failures $failures
    Test-ForbiddenText -Text $e2eArtifactValidator -Needle $staleScenarioName -Name "stale ESET artifact scenario name" -Failures $failures
}

Test-RequiredText -Text $readme -Needle "eset_exact_file_sha1_ioc" -Name "README exact hash documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "run-eset-hunt-e2e.ps1" -Name "README ESET E2E runner documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "-ArticleHtml <path>" -Name "README ESET article currentness validation documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "-ArticleUrl <url>" -Name "README ESET article URL validation documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "article-validator.log" -Name "README ESET E2E article validator log documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "known defense-evasion driver service" -Name "README ESET E2E system assessment documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "target-lifetime padding" -Name "README ESET E2E lifetime padding documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "/stop-event" -Name "README ESET E2E stop-event documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "validate-eset-hunt-e2e-artifacts.ps1" -Name "README ESET artifact validator documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "runner.log" -Name "README ESET runner log documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "-ReuseExistingTarget" -Name "README ESET reuse existing target documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "target exits before the 35-scenario manifest" -Name "README ESET early-exit runner diagnostic documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "prints the tails of the target" -Name "README ESET failure-tail runner diagnostic documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "GentleKiller security-product targets" -Name "README GentleKiller target-list documentation" -Failures $failures
Test-RequiredText -Text $readme -Needle "public Table 2 HTML currently exposes 274 unique lower-case image names" -Name "README public Table 2 target-list caveat" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "exact ESET SHA-1 IoCs" -Name "hunt target exact hash test caveat" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "run-eset-hunt-e2e.ps1" -Name "hunt target ESET E2E runner documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "-ArticleHtml <path>" -Name "hunt target ESET article currentness validation documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "-ArticleUrl <url>" -Name "hunt target ESET article URL validation documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "article-validator.log" -Name "hunt target ESET article validator log documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "known defense-evasion driver service" -Name "hunt target ESET system assessment documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "slow deep hunt cannot race the fixture lifetime" -Name "hunt target ESET E2E lifetime padding documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "/stop-event" -Name "hunt target ESET E2E stop-event documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "validate-eset-hunt-e2e-artifacts.ps1" -Name "hunt target ESET artifact validator documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "runner.log" -Name "hunt target ESET runner log documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "-ReuseExistingTarget" -Name "hunt target ESET reuse existing target documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "target exits before the 35-scenario manifest" -Name "hunt target ESET early-exit runner diagnostic documentation" -Failures $failures
Test-RequiredText -Text $testDoc -Needle "prints the tails of the target" -Name "hunt target ESET failure-tail runner diagnostic documentation" -Failures $failures
Test-RequiredText -Text $coverage -Needle "ESET-published Gentlemen/OxideHarvest SHA-1 IoCs" -Name "command coverage exact hash documentation" -Failures $failures
Test-RequiredText -Text $architecture -Needle "sensitive cross-process tasks" -Name "architecture TI task documentation" -Failures $failures
Test-RequiredText -Text $architecture -Needle "GentleKiller target list" -Name "architecture target-list documentation" -Failures $failures
Test-RequiredText -Text $architecture -Needle "274 unique lower-case image names exposed by public Table 2 HTML" -Name "architecture public Table 2 target-list caveat" -Failures $failures

if ($failures.Count -ne 0)
{
    Write-Host "ESET hunt IOC validation failed"
    foreach ($failure in $failures)
    {
        Write-Host "  fail $failure"
    }
    exit 1
}

$processCount = @($expected | Where-Object { $_.Process }).Count
$driverCount = @($expected | Where-Object { $_.Driver }).Count
$credentialCount = @($expected | Where-Object { $_.Credential }).Count

Write-Host "ESET hunt IOC validation passed"
Write-Host "  iocs=$($expected.Count) process=$processCount driver=$driverCount credential=$credentialCount"
Write-Host "  process_profiles=$($expectedProcessProfiles.Count) suffix_bases=$($expectedProcessSuffixBases.Count) driver_profiles=$($expectedDriverProfiles.Count)"
Write-Host "  security_product_targets=$($expectedSecurityProductTargets.Count)"
if ($null -ne $articleTableCount)
{
    Write-Host "  article_tables=$articleTableCount article_sha1=$articleSha1Count article_table2_targets=$articleTargetCount article_table34_processes=$articleTable34ProcessCount article_table34_drivers=$articleTable34DriverCount"
    Write-Host "  article_html=$ArticleHtml"
}
exit 0
