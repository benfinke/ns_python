__author__ = 'ben'

"""

Usage: getNetscalerBaseline.py <nsip> <username> <password>

Sets up a standard Netscaler config with various checks complete.

"""

from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from nssrc.com.citrix.netscaler.nitro.resource.base.base_response import base_response
from nssrc.com.citrix.netscaler.nitro.resource.base.base_responses import base_responses
from nssrc.com.citrix.netscaler.nitro.resource.stat.ns.ns_stats import ns_stats
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nslicense import nslicense

import sys


# Set up the global variables for the baseline stuff



def printDivider():
    print("""++++++++++++++++++++++++++++++++++++++++++
+
+
+
++++++++++++++++++++++++++++++++++++++++++""")

class set_config :
    def __init__(self):
        _ip=""
        _username=""
        _password=""

    @staticmethod
    def main(cls, args_):
        if(len(args_) < 3):
            print("Usage: run.bat <ip> <username> <password>")
            return

        config = set_config()
        config.ip = args_[1]
        config.username = args_[2]
        config.password = args_[3]

        try :
            client = nitro_service(config.ip,"http")
            client.set_credential(config.username,config.password)
            client.timeout = 500
            config.execute_commands(client)
            client.logout()
        except nitro_exception as  e:
            print("Exception::errorcode="+str(e.errorcode)+",message="+ e.message)
        except Exception as e:
            print("Exception::message="+str(e.args))
        return

# Function to find all enabled NS services
    def getEnabledNsFeatures(self, client):
        try :
            enabled_features = client.get_enabled_features()
            i=1
            print("enabled nsfeatures: ")
            for en_feature in enabled_features :
                print("\t"+ str(i) +") "+en_feature)
                i= i + 1
        except nitro_exception as e :
            print("Exception::getEnabledNsFeatures::errorcode="+str(e.errorcode)+",message="+ e.message)
        except Exception as e :
            print("Exception::getEnabledNsFeatures::message="+str(e.args))

# Function to get live system software stats
    def getNsSystemsStats(self, client):
        try:
            ns_obj = ns_stats.get(client)
            for i in range(len(ns_obj)):
                print("System last started: "+str(ns_obj[i].starttime))
                print("HA Health State: "+str(ns_obj[i].hacurstate))
                print("HA Status: "+str(ns_obj[i].hacurmasterstate))
                print("Memory in use: "+str(ns_obj[i].memuseinmb)+" MBs")
                print("Flash storage usage: "+str(ns_obj[i].disk0perusage)+"%")
                print("Hard drive storage (/var) usage: "+str(ns_obj[i].disk1perusage)+"%")
                print("Average CPU usage: "+str(ns_obj[i].rescpuusage)+"%")
                # this number of cpus should be moved to the hardware stats function
                print("Number of CPUs: "+str(ns_obj[i].numcpus))
        except nitro_exception as e:
            print("Exception::getNsSystemStats::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::getNsSystemStats::message"+str(e.args))

# Function to retrieve the license status of a Netscaler
    def getNsLicenseStatus(self, client):
        try:
            license_data = nslicense()
            ns_obj = license_data.get(client)
            for i in range(len(ns_obj)):
                if ns_obj[i].isstandardlic:
                    print("License Type is Standard.")
                elif ns_obj[i].isenterpriselic:
                    print("License Type is Enterprise.")
                elif ns_obj[i].isplatinumlic:
                    print("License Type is Platinum.")
                else:
                    print("Error Retrieving license type.")
                print("Web Logging: "+str(ns_obj[i].wl))
                print("Surge Protection: "+str(ns_obj[i].sp))
                print("Load Balancing: "+str(ns_obj[i].lb))
                print("Content Switching: "+str(ns_obj[i].cs))
                print("Cache Redirect: "+str(ns_obj[i].cr))
                print("Sure Connect: "+str(ns_obj[i].sc))
                print("Compression: "+str(ns_obj[i].cmp))
                print("Delta Compression: "+str(ns_obj[i].delta))
                print("Priority Queuing: "+str(ns_obj[i].pq))
                print("Global Server Load Balancing: "+str(ns_obj[i].gslb))
                print("GSLB Proximity: "+str(ns_obj[i].gslbp))
                print("DoS Protection: "+str(ns_obj[i].hdosp))
                print("Routing: "+str(ns_obj[i].routing))
                print("Content Filter: "+str(ns_obj[i].cf))
                print("Transparent Integrated Caching: "+str(ns_obj[i].contentaccelerator))
                print("Integrated Caching: "+str(ns_obj[i].ic))
                print("SSL VPN: "+str(ns_obj[i].sslvpn))
                print("Number of SSL VPN Users Allowed: "+str(ns_obj[i].f_sslvpn_users))
                print("Number of ICA Users: "+str(ns_obj[i].f_ica_users)+" Note: If Access Gateway is licensed this number will be Zero.")
                print("AAA: "+str(ns_obj[i].aaa))
                print("OSPF: "+str(ns_obj[i].ospf))
                print("RIP: "+str(ns_obj[i].rip))
                print("BGP: "+str(ns_obj[i].bgp))
                print("Rewrite: "+str(ns_obj[i].rewrite))
                print("IPv6 Protocol Translation: "+str(ns_obj[i].ipv6pt))
                print("Application Firewall: "+str(ns_obj[i].appfw))
                print("Responder: "+str(ns_obj[i].responder))
                print("Access Gateway: "+str(ns_obj[i].agee))
                print("NSXN: "+str(ns_obj[i].nsxn))
                print("HTML Injection: "+str(ns_obj[i].htmlinjection))
                print("Model Number ID: "+str(ns_obj[i].modelid))
                print("NetScaler Push: "+str(ns_obj[i].push))
                print("Web Interface on NetScaler: "+str(ns_obj[i].wionns))
                print("AppFlow: "+str(ns_obj[i].appflow))
                print("CloudBridge: "+str(ns_obj[i].cloudbridge))
                print("CloudBridge Appliance: "+str(ns_obj[i].cloudbridgeappliance))
                print("CloudExtender Appliance: "+str(ns_obj[i].cloudextenderappliance))
                print("ISIS Routing: "+str(ns_obj[i].isis))
                print("Clustering: "+str(ns_obj[i].cluster))
                print("Call Home: "+str(ns_obj[i].ch))
                print("AppQoS: "+str(ns_obj[i].appqos))
                print("AppFlow for ICA: "+str(ns_obj[i].appflowica))
                print("RISE: "+str(ns_obj[i].rise))
                print("VPath: "+str(ns_obj[i].vpath))
                print("Front End Optimization: "+str(ns_obj[i].feo))





        except nitro_exception as e:
            print("Exception::addSnmpCommunityString::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::addSnmpCommunityString::message"+str(e.args))

# Function to get local users
    def getLocalUsers(self, client):
        try:
            pass
        except nitro_exception as e:
            print("Exception::addSnmpCommunityString::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::addSnmpCommunityString::message"+str(e.args))



# Function to get SNMP traps


# Function to get syslogging policies


# Function to get list of services


# FUnction to get list of lb_vservers


# Function to get list of cs_vservers


# Function to get bindings of lb_vservrs to cs_vservers


#


    def shellNsFunction(self, client):
        try:
            pass
        except nitro_exception as e:
            print("Exception::addSnmpCommunityString::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::addSnmpCommunityString::message"+str(e.args))




    def execute_commands(self, client):
        # Get enabled NS features
        print("Enabled NetScaler Features: ")
        self.getEnabledNsFeatures(client)
        printDivider()
        print("NetScaler License Status:")
        self.getNsLicenseStatus(client)
        printDivider()
        print("NetScaler System Statistics:")
        self.getNsSystemsStats(client)
        printDivider()





# Set up TACACS authentication policy
# Set up Syslog operations
# Build custom message actions - 500 series responses,
# Modify SSL offloading to meet A standard from SSL Labs
# Configure AAA targets
# Add template HTTP DoS policy
# Set up Action Analytics

#
# Main thread of execution
#

if __name__ == '__main__':
    try:
        if len(sys.argv) != 4:
            sys.exit()
        else:
            ipaddress=sys.argv[1]
            username=sys.argv[2]
            password=sys.argv[3]
            set_config().main(set_config(),sys.argv)
    except SystemExit:
        print("Exception::Usage: python SetNetscalerBaselineConfig.py <nsip> <username> <password>")