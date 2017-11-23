// 2017-11-22
function FindProxyForURL(url, host) {
var resolved_ip = dnsResolve(host);

// Default Proxy Access
   	var return_SpecifProxy = "PROXY 101.231.121.17:443; PROXY 125.35.57.17:443; DIRECT";
	var return_httpsProxy = "PROXY 101.231.121.17:443; PROXY 125.35.57.17:443; DIRECT"; 
	var return_Proxy = "PROXY 101.231.121.17:80; PROXY 125.35.57.17:80; DIRECT";
//
// Access to verisign.com via Zen  125.35.57.17 
	if (shExpMatch(url, "*verisign*"))
	return "PROXY 125.35.57.17:80";
//
// Specific Access for IP address if required
//  if (	isInNet(myIpAddress (), "10.177.160.0", "255.255.224.0") ||
//		isInNet(myIpAddress (), "10.177.128.0", "255.255.224.0"))
//  var return_SpecifProxy = "PROXY 101.231.121.17:443; PROXY 125.35.57.17:443; DIRECT";
//  var return_httpsProxy = "PROXY 101.231.121.17:443; PROXY 125.35.57.17:443; DIRECT"; 
//  var return_Proxy = "PROXY 101.231.121.17:80; PROXY 125.35.57.17:80; DIRECT";
//	
// Internal Network
	if (	isInNet(resolved_ip, "10.0.0.0", "255.0.0.0") ||
		isInNet(resolved_ip, "139.160.0.0", "255.255.0.0") ||
		isInNet(resolved_ip, "139.158.0.0", "255.255.0.0") ||
		isInNet(resolved_ip, "157.198.0.0", "255.255.0.0") ||
// WO0000000131344 added 149.121.0.0/16 for Invensys
        	isInNet(resolved_ip, "149.121.0.0", "255.255.0.0") ||
// No non FQDN or RFC1918 traffic to go to ZScaler
		isInNet(resolved_ip, "192.168.0.0", "255.255.0.0") ||
		isInNet(resolved_ip, "172.16.0.0", "255.240.0.0") ||
		isInNet(resolved_ip, "169.254.0.0", "255.255.0.0") ||
		isPlainHostName (host) ||
		localHostOrDomainIs(resolved_ip, "localhost") ||
		isInNet(resolved_ip, "127.0.0.0", "255.0.0.0") ||
//Gomez
	    	isInNet(resolved_ip, "63.251.134.192", "255.255.255.255") ||   
		isInNet(resolved_ip, "63.251.134.193", "255.255.255.255") ||
		isInNet(resolved_ip, "63.251.134.196", "255.255.255.255") ||
//MFA symantec
		isInNet(resolved_ip, "216.168.240.0", "255.255.240.0") ||
		isInNet(resolved_ip, "69.58.176.0", "255.255.240.0") ||
		isInNet(resolved_ip, "216.168.224.0", "255.255.240.0") ||
		isInNet(resolved_ip, "199.7.78.0", "255.255.254.0") ||
		isInNet(resolved_ip, "199.7.80.0", "255.255.255.0") ||
//Oracle
        	isInNet(resolved_ip, "140.85.0.0", "255.255.0.0") ||
        	isInNet(resolved_ip, "141.146.128.0", "255.255.128.0") ||
        	isInNet(resolved_ip, "144.23.0.0", "255.255.0.0") ||
        	isInNet(resolved_ip, "137.254.128.0", "255.255.128.0") ||
//Taleo
//		isInNet(resolved_ip, "94.103.23.0", "255.255.255.0")||
//		isInNet(resolved_ip, "160.34.64.0", "255.255.254.0")||

// Webex
		isInNet(resolved_ip, "173.243.0.0", "255.255.240.0") ||
		isInNet(resolved_ip, "62.109.192.0", "255.255.192.0") ||
		isInNet(resolved_ip, "64.68.96.0", "255.255.224.0") ||
		isInNet(resolved_ip, "66.114.160.0", "255.255.240.0") ||
		isInNet(resolved_ip, "66.163.32.0", "255.255.240.0") ||
		isInNet(resolved_ip, "209.197.192.0", "255.255.224.0") ||
		isInNet(resolved_ip, "208.8.81.0", "255.255.255.0") ||
		isInNet(resolved_ip, "210.4.192.0", "255.255.240.0") ||
		isInNet(resolved_ip, "114.29.192.0", "255.255.224.0") ||
		isInNet(resolved_ip, "59.151.13.0", "255.255.255.0") ||
		isInNet(resolved_ip, "59.151.14.0", "255.255.255.0") ||
// Hirevue 
		isInNet(resolved_ip, "54.209.139.162", "255.255.255.255") ||
		isInNet(resolved_ip, "54.209.142.12", "255.255.255.255") ||
		isInNet(resolved_ip, "54.208.222.61", "255.255.255.255") ||
		isInNet(resolved_ip, "54.209.39.166", "255.255.255.255") ||
		isInNet(resolved_ip, "52.1.4.200", "255.255.255.255") ||
		isInNet(resolved_ip, "54.194.2.2", "255.255.255.255") ||
		isInNet(resolved_ip, "54.194.37.240", "255.255.255.255") ||
		isInNet(resolved_ip, "54.207.16.204", "255.255.255.255") ||
		isInNet(resolved_ip, "54.207.9.168", "255.255.255.255") ||
		isInNet(resolved_ip, "54.254.106.101", "255.255.255.255") ||
		isInNet(resolved_ip, "54.254.106.107", "255.255.255.255") ||
		isInNet(resolved_ip, "54.254.198.42", "255.255.255.255") ||
		isInNet(resolved_ip, "54.206.9.156", "255.255.255.255") ||
		isInNet(resolved_ip, "54.206.45.175", "255.255.255.255") ||
		isInNet(resolved_ip, "54.238.233.104", "255.255.255.255") ||
		isInNet(resolved_ip, "54.249.19.79", "255.255.255.255") ||
//SSL VPN INVENSYS
		dnsDomainIs (host, "foxvpn.invensys.com") ||
		isInNet(resolved_ip, "192.131.112.10", "255.255.255.255") ||
		dnsDomainIs (host, "lkfvpn.invensys.com") ||
		isInNet(resolved_ip, "159.157.238.60", "255.255.255.255") ||
		dnsDomainIs (host, "lonvpn.invensys.com") ||
		isInNet(resolved_ip, "159.157.209.134", "255.255.255.255") ||
		dnsDomainIs (host, "sinvpn.invensys.com") ||
		isInNet(resolved_ip, "159.157.254.80", "255.255.255.255") ||
		dnsDomainIs (host, "vpn.invensys.com") ||
//VPN Areva
		isInNet(resolved_ip, "57.66.138.42", "255.255.255.255") ||
//VPN APC
		dnsDomainIs (host, "frost.apc.com") ||
		isInNet(resolved_ip, "62.17.253.190", "255.255.255.255") ||
		isInNet(resolved_ip, "82.150.6.190", "255.255.255.255") ||
//SSL VPN APAC
    		dnsDomainIs (host, "magoo.schneider-electric.com") ||
    		isInNet(resolved_ip, "205.167.7.167", "255.255.255.255") ||
		dnsDomainIs (host, "bianca.in.schneider-electric.com") ||
	    	isInNet(resolved_ip, "103.41.214.10", "255.255.255.255") ||
		dnsDomainIs (host, "spongebob.schneider-electric.com") ||
		isInNet(resolved_ip, "103.248.98.34", "255.255.255.255") ||
		dnsDomainIs (host, "squarepants.schneider-electric.com") ||
		isInNet(resolved_ip, "203.41.170.45", "255.255.255.255") ||
		dnsDomainIs (host, "flag-bj.schneider-electric.com") ||
		isInNet(resolved_ip, "58.68.252.20", "255.255.255.255") ||
		dnsDomainIs (host, "flag-sh.schneider-electric.com") ||
		isInNet(resolved_ip, "101.231.121.18", "255.255.255.255") ||
		dnsDomainIs (host, "formosa.tw.schneider-electric.com") ||	
		isInNet(resolved_ip, "220.130.19.7", "255.255.255.255") ||
		dnsDomainIs (host, "tsubasa.schneider-electric.com") ||
		isInNet(resolved_ip, "59.190.141.198", "255.255.255.255") ||
		dnsDomainIs (host, "gp.schneider-electric.com") ||
        	shExpMatch(host, "*.gp.schneider-electric.com") ||
// china specific DIRECT
		dnsDomainIs(host, "bo.energy.schneider-electric.com") ||
        	isInNet(host, "10.177.0.83", "255.255.255.255") ||
        	isInNet(host, "10.177.0.85", "255.255.255.255") ||
		// ISYS QA BuyAutomation	
		dnsDomainIs (host, "upload.buyautomation.com")||
		// Java specific		
		dnsDomainIs (host, "cstsame01.cst.global"))
	return "DIRECT";

// Application Exception
// Workaround Java 1.6
	if (	dnsDomainIs (host, "licp01.schneider-electric.com"))
	return "DIRECT";
	
/*---SfB WinHTTP Workaround---*/
    	if (        shExpMatch(url, "http*://lyncdiscoverinternal.schneider-electric.com*"))
    	return "DIRECT";
    	if (        shExpMatch(url, "http*://lyncdiscoverinternal.non.schneider-electric.com*"))
    	return "DIRECT";

    //BOX Optimization rule
    	if (	isInNet(resolved_ip, "74.112.184.0", "255.255.252.0") ||
        	isInNet(resolved_ip, "107.152.16.0", "255.255.240.0"))
    return "DIRECT; PROXY 101.231.121.17:443; PROXY 125.35.57.17:443";


//IE8 compatibility
	if (	shExpMatch(host, "fxsc.schneider-electric.com") ||
		shExpMatch(host, "www.schneider.edocuweb.net") ||
		shExpMatch(host, "softreg-prod.schneider-electric.com")) 
	return "DIRECT";
	
// Application specific
	if (	dnsDomainIs (host, ".skype.net") || 
		dnsDomainIs (host, ".skype.com") )                         
	return return_SpecifProxy;

// Birst
	if (	shExpMatch(host, "*.eu1.birst.com"))
	return "PROXY force-proxy-birst.pac.schneider-electric.com:80";


// China Specific Rules
	if ( 	isInNet(myIpAddress (), "10.177.0.0", "255.255.0.0") || 
		isInNet(myIpAddress (), "10.235.112.0", "255.255.248.0") ||
		isInNet(myIpAddress (), "10.235.80.0", "255.255.240.0") ||
		isInNet(myIpAddress (), "10.235.96.0", "255.255.240.0"))
	{
		if (	//SalesForce
			isInNet(resolved_ip, "13.108.0.0", "255.252.0.0") ||
			isInNet(resolved_ip, "13.210.4.0", "255.255.252.0") ||
			isInNet(resolved_ip, "13.210.8.0", "255.255.252.0") ||
			isInNet(resolved_ip, "52.60.248.0", "255.255.252.0") ||
			isInNet(resolved_ip, "52.60.252.0", "255.255.252.0") ||
			isInNet(resolved_ip, "85.222.128.0", "255.255.224.0") ||
			isInNet(resolved_ip, "96.43.144.0", "255.255.240.0") ||
			isInNet(resolved_ip, "101.53.160.0", "255.255.224.0") ||
			isInNet(resolved_ip, "136.146.0.0", "255.254.0.0") ||
			isInNet(resolved_ip, "182.50.76.0", "255.255.252.0") ||
			isInNet(resolved_ip, "185.79.140.0", "255.255.252.0") ||
			isInNet(resolved_ip, "202.129.242.0", "255.255.254.0") ||
			isInNet(resolved_ip, "204.14.232.0", "255.255.248.0") ||
			dnsDomainIs(host, "box.com") ||
			dnsDomainIs(host, "box.net") ||
			dnsDomainIs(host, "boxcloud.com") ||
			dnsDomainIs(host, "boxcdn.net") ||
			dnsDomainIs(host, "ajax.googleapis.com") ||
			dnsDomainIs(host, "awmdm.com"))
		return "PROXY 10.218.99.48:9400; PROXY 125.35.57.17:80";
		
		if (	dnsDomainIs(host, "hotel.info") ||
			dnsDomainIs(host, "se-jeportal.org") ||
			dnsDomainIs(host, "icbc.com.cn") ||
			dnsDomainIs(host, "hotel.de"))
		return "PROXY 101.231.121.17:80; 125.35.57.17:80;";
	}

//bjguahao.gov.cn (Temp-266696)
	if(dnsDomainIs(host, "www.bjguahao.gov.cn")) 
	return "PROXY 125.35.57.13:80; PROXY 58.68.252.13:80; DIRECT";
// return "PROXY 101.231.121.17:80; PROXY 58.68.252.13:80; DIRECT";

// -- NO NEED TO EDIT BELOW --
// Cloud Proxy Updates are directly accessible
	if (localHostOrDomainIs(host, "trust.zscaler.com"))
	return "DIRECT";
// FTP Forwarding to ZScaler
	if (url.substring(0,4) == "ftp:")
	return return_Proxy;
// HTTPS Forwarding to ZScaler
	if (url.substring(0,6) == "https:")
	return return_httpsProxy;
// Default Traffic Forwarding to ZScaler on port 80
	 return return_Proxy;
}

