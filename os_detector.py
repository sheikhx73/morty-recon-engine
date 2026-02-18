def detect_os(open_ports, banners):
    os_guess = "Unknown"

    # Strong Windows Indicators
    if 445 in open_ports:
        return "Likely Windows (SMB Detected)"
    if 3389 in open_ports:
        return "Likely Windows (RDP Detected)"

    # Strong Linux Indicator
    if 22 in open_ports:
        return "Likely Linux (SSH Detected)"

    # Check banners
    for banner in banners:
        if banner:
            banner_lower = banner.lower()

            if "microsoft-iis" in banner_lower:
                return "Likely Windows (IIS Web Server)"
            
            if "apache" in banner_lower:
                return "Likely Linux (Apache Web Server)"
            
            if "nginx" in banner_lower:
                return "Likely Linux (Nginx Web Server)"

    # Weak Guessing
    if 80 in open_ports or 443 in open_ports:
        return "Web Server Detected (OS Cannot Be Determined)"

    return os_guess
