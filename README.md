# help
    usage: get_server_info.py [-h] [-u SERVERUSERNAME] [-p SERVERPASSWORD]
                              [-U BMCUSERNAME] [-P BMCPASSWORD] [-t TAG]
                              [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
                              host
    
    Script to get node information including Hostname, Serial, BMC version, BIOS
    version
    
    positional arguments:
      host                  address for management node
    
    optional arguments:
      -h, --help            show this help message and exit
      -u SERVERUSERNAME, --serverusername SERVERUSERNAME
                            sername for management node
      -p SERVERPASSWORD, --serverpassword SERVERPASSWORD
                            password for management node
      -U BMCUSERNAME, --bmcusername BMCUSERNAME
                            username for BMC redfish
      -P BMCPASSWORD, --bmcpassword BMCPASSWORD
                            password for BMC redfish
      -t TAG, --tag TAG     tag name for file id
      -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
