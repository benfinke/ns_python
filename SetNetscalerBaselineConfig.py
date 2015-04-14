__author__ = 'ben'

"""

Usage: SetNetScalerBaselineConfig.py <nsip> <username> <password>

Sets up a standard Netscaler config with various checks complete.

"""

from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver import lbvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbmonitor import lbmonitor
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_rewritepolicy_binding import lbvserver_rewritepolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_service_binding import lbvserver_service_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.network.rnat import rnat
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsacls import nsacls
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsconfig import nsconfig
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsmode import nsmode
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nspbrs import nspbrs
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmpgroup import snmpgroup
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmpcommunity import snmpcommunity
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmpmanager import snmpmanager
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmptrap import snmptrap
from nssrc.com.citrix.netscaler.nitro.resource.config.ntp.ntpserver import ntpserver
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslcertkey import sslcertkey
from nssrc.com.citrix.netscaler.nitro.resource.config.cache.cacheobject import cacheobject
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslcipher import sslcipher
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.ssldhparam import ssldhparam
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslpkcs12 import sslpkcs12
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslpkcs8 import sslpkcs8
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslvserver import sslvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslvserver_sslcertkey_binding import sslvserver_sslcertkey_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.system.systemgroup_systemuser_binding import systemgroup_systemuser_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.system.systemuser_systemcmdpolicy_binding import systemuser_systemcmdpolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.system.systemuser import systemuser
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnvserver_vpnclientlessaccesspolicy_binding import vpnvserver_vpnclientlessaccesspolicy_binding
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from nssrc.com.citrix.netscaler.nitro.resource.config.aaa.aaaglobal_aaapreauthenticationpolicy_binding import aaaglobal_aaapreauthenticationpolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.aaa.aaapreauthenticationaction import aaapreauthenticationaction
from nssrc.com.citrix.netscaler.nitro.resource.config.aaa.aaapreauthenticationpolicy import aaapreauthenticationpolicy
from nssrc.com.citrix.netscaler.nitro.resource.config.appfw.appfwconfidfield import appfwconfidfield
from nssrc.com.citrix.netscaler.nitro.resource.config.appfw.appfwprofile import appfwprofile
from nssrc.com.citrix.netscaler.nitro.resource.config.authentication.authenticationvserver_auditnslogpolicy_binding import authenticationvserver_auditnslogpolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.authentication.authenticationvserver_authenticationlocalpolicy_binding import authenticationvserver_authenticationlocalpolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.service import service
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.servicegroup import servicegroup
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.servicegroup_servicegroupmember_binding import servicegroup_servicegroupmember_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.cs.cspolicy import cspolicy
from nssrc.com.citrix.netscaler.nitro.resource.config.cs.csvserver import csvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.cs.csvserver_cmppolicy_binding import csvserver_cmppolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.filter.filterpolicy import filterpolicy
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbservice import gslbservice
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbsite import gslbsite
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbvserver import gslbvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbvserver_domain_binding import gslbvserver_domain_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbvserver_gslbservice_binding import gslbvserver_gslbservice_binding
from nssrc.com.citrix.netscaler.nitro.resource.base.base_response import base_response
from nssrc.com.citrix.netscaler.nitro.resource.base.base_responses import base_responses
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsfeature import nsfeature
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsmode import nsmode
from nssrc.com.citrix.netscaler.nitro.resource.config.rewrite.rewritepolicy import rewritepolicy
from nssrc.com.citrix.netscaler.nitro.resource.config.rewrite.rewriteaction import rewriteaction
import sys


# Set up the global variables for the baseline stuff

baselineNsFeatures = [nsfeature.Feature.AAA,
                      nsfeature.Feature.AppFw,
                      nsfeature.Feature.ContentSwitching,
                      nsfeature.Feature.LoadBalancing,
                      nsfeature.Feature.RESPONDER,
                      nsfeature.Feature.REWRITE,
                      nsfeature.Feature.SSL,
                      nsfeature.Feature.SSLOffloading,
                      nsfeature.Feature.HDOSP
                      ]

snmpCommunityStrings = [{"commString":"benIsAwesome","permission":"ALL"},
                        {"commString":"benIsAwesomeRO","permission":"GET"}
                        ]

snmpManagers = ["172.16.191.100", "10.10.2.25"]

snmpTraps = [{"destIP":"172.16.191.100","version":"V2","snmpCommString":"BenIsSuperAwesome"},
             {"destIP":"10.10.2.25","version":"V2","snmpCommString":"BenIsSuperAwesome2"}
             ]

ntpServerList = ["tick.microsoft.com","tock.microsoft.com"]

localAdminAccount = [{"username":"backupAdmin","pass":"supersecret"}]



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

# Function to enable a basic NS feature
    def enableNsFeature(self, client, feature):
        try:
            #feature = [nsfeature.Feature.BGP, nsfeature.Feature.REWRITE]
            client.enable_features(feature)
            print("The %s feature has been enabled." % feature)
        except nitro_exception as e :
            print("Exception::enableNsFeature::errorcode="+str(e.errorcode)+",message="+ e.message)
        except Exception as e:
            print("Exception::enableNsFeature::message="+str(e.args))


# Function for adding SNMP community string
    def addSnmpCommunityString(self, client, snmpString, snmpPerm):
        try:
            ns_obj = snmpcommunity
            ns_obj.communityname = snmpString
            ns_obj.permissions = snmpPerm
            snmpcommunity.add(client, ns_obj)
            print("SNMP string "+str(snmpString)+" successfully added to the Netscaler.")
        except nitro_exception as e:
            print("Exception::addSnmpCommunityString::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::addSnmpCommunityString::message"+str(e.args))

# Function for adding SNMP Managers
    def addSnmpManager(self, client, manager):
        try:
            ns_obj = snmpmanager()
            ns_obj.ipaddress = manager
            snmpmanager.add(client, ns_obj)
        except nitro_exception as e:
            print("Exception::addSnmpManager::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::addSnmpManager::message"+str(e.args))


    def addSnmpTrap(self, client, trapDestIP, snmpCommString, snmpTrapVersion):
        try:
            ns_obj = snmptrap()
            ns_obj.trapclass = "generic"
            ns_obj.communityname = snmpCommString
            ns_obj.trapdestination = trapDestIP
            ns_obj.version = snmpTrapVersion
            snmptrap.add(client, ns_obj)
        except nitro_exception as e:
            print("Exception::addSnmpTrap::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::addSnmpTrap::message"+str(e.args))


    def setNtpServer(self, client, ntpServerName):
        try:
            ns_obj = ntpserver()
            ns_obj.servername = ntpServerName
            ns_obj.autokey = True
            ntpserver.add(client, ns_obj)
            # stuff
        except nitro_exception as e:
            print("Exception::setNtpServer::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::setNtpServer::message"+str(e.args))

    def setLocalAdminAccount(self, client, accountName, accountPass):
        try:
            ns_obj = systemuser()
            ns_obj.username = accountName
            ns_obj.password = accountPass
            ns_obj.logging = "ENABLED"
            systemuser.add(client, ns_obj)
            ns_obj_binding = systemuser_systemcmdpolicy_binding()
            ns_obj_binding.username = accountName
            ns_obj_binding.policyname = "superuser"
            ns_obj_binding.priority = "100"
            systemuser_systemcmdpolicy_binding.add(client, ns_obj_binding)
        except nitro_exception as e:
            print("Exception::setLocalAdminAccount::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::setLocalAdminAccount::message"+str(e.args))


    def shellNsFunction(self, client):
        try:
            pass
            # stuff
        except nitro_exception as e:
            print("Exception::addSnmpCommunityString::errorCode="+str(e.errorcode)+",message="+e.message)
        except Exception as e:
            print("Exception::addSnmpCommunityString::message"+str(e.args))




    def execute_commands(self, client):
        # Enable the required ns features
        for f in baselineNsFeatures:
            self.enableNsFeature(client, f)
            print("Enabled feature "+str(f))

        # Add the new managed SNMP strings
        for s in snmpCommunityStrings:
            self.addSnmpCommunityString(client, s['commString'], s['permission'])
            print("Added thw SNMP community string"+str(s['commString']))

        # Add SNMP Mnaagers
        for ns_manager in snmpManagers:
            self.addSnmpManager(client, ns_manager)
            print("Added the SNMP Manager"+str(ns_manager))

        # Add SNMP traps
        for trap in snmpTraps:
            self.addSnmpTrap(client, trap['destIP'], trap['snmpCommString'], trap['version'])
            print("Added the snmp trap to send to "+str(trap['destIP']))

        # Set NTP Servers
        for ntpItem in ntpServerList:
            self.setNtpServer(client, ntpItem)
            print("Added the NTP server "+str(ntpItem))

        # Add the backup local account
        for account in localAdminAccount:
            self.setLocalAdminAccount(client, account['username'], account['pass'])
            print("Added the local backup admin account "+str(account['username']))



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