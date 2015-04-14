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

import sys


# Set up the global variables for the baseline stuff



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

# Function to get system uptime
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
                print("Number of CPUs: "+str(ns_obj[i].numcpus))
        except nitro_exception as e:
            print("Exception::getNsSystemStats::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::getNsSystemStats::message"+str(e.args))

# Function to get local users


# Function to get SNMP traps


# Function to get syslogging policies


# Function to get list of services


# FUnction to get list of lb_vservers


# Function to get list of cs_vservers


# Fucntion to get bindings of lb_vservrs to cs_vservers


#


    def shellNsFunction(self, client):
        try:
            pass
            # stuff
        except nitro_exception as e:
            print("Exception::addSnmpCommunityString::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::addSnmpCommunityString::message"+str(e.args))




    def execute_commands(self, client):
        # Get enabled NS features
        self.getEnabledNsFeatures(client)
        self.getNsSystemsStats(client)




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