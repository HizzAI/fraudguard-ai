import logging
from typing import Dict, Any
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

logger = logging.getLogger(__name__)

def analyze_apk(file_path: str) -> Dict[str, Any]:
    """
    Performs static analysis on an APK file using Androguard.
    
    Args:
        file_path (str): The absolute path to the APK file.
        
    Returns:
        Dict[str, Any]: A dictionary containing extracted APK details.
    """
    result = {
        "analysis_status": "failed",
        "app": {
            "package_name": None,
            "label": None,
            "version": None
        },
        "permissions": [],
        "components": {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": []
        },
        "dex": {
            "count": 0
        },
        "apis": [],
        "certificate": {},
        "errors": []
    }
    
    try:
        # Load the APK
        apk = APK(file_path)
        
        # Application info
        result["app"]["package_name"] = apk.get_package()
        result["app"]["label"] = apk.get_app_name()
        
        # Version information might be available through the manifest
        # android:versionName is typical
        result["app"]["version"] = apk.get_androidversion_name()
        
        # Permissions
        permissions = apk.get_permissions()
        if permissions:
            result["permissions"] = list(permissions)
            
        # Components
        activities = apk.get_activities()
        if activities:
            result["components"]["activities"] = list(activities)
            
        services = apk.get_services()
        if services:
            result["components"]["services"] = list(services)
            
        receivers = apk.get_receivers()
        if receivers:
            result["components"]["receivers"] = list(receivers)
            
        providers = apk.get_providers()
        if providers:
            result["components"]["providers"] = list(providers)
            
        # DEX files count
        dex_files = list(apk.get_all_dex())
        result["dex"]["count"] = len(dex_files)
        
        # API/method information (simple approach to gather methods)
        # We don't perform full cross-reference analysis to save time/memory,
        # just list what's reliably extracted.
        apis = set()
        for dex_bytes in dex_files:
            try:
                d = DalvikVMFormat(dex_bytes)
                for method in d.get_methods():
                    apis.add(f"{method.get_class_name()}->{method.get_name()}")
            except Exception as e:
                logger.warning(f"Failed to parse a DEX file: {e}")
                
        result["apis"] = list(apis)[:1000] # Cap to prevent massive JSON payloads
        
        # Certificate information
        cert_info = {}
        for cert in apk.get_certificates():
            # Extract basic certificate details
            cert_info["issuer"] = cert.issuer.human_friendly
            cert_info["subject"] = cert.subject.human_friendly
            cert_info["serial_number"] = cert.serial_number
            break # Just take the first one for simplicity
        
        result["certificate"] = cert_info
        
        result["analysis_status"] = "success"
        
    except Exception as e:
        logger.error(f"Error during APK analysis: {str(e)}")
        result["errors"].append(str(e))
        
    return result
