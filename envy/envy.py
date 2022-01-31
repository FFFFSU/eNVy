import docker, socket
from idps import Manager

def getNetworkName():
    networkLists = []
    networks = dockerClient.networks.list()
    print("\nDocker network list: ")
    for network in networks:
        networkLists.append(network.name)
        print(" - {}".format(network.name))

    while True:
        networkName = str(input("\nEnter the name of Docker Network you want to use: "))
        if any(networkList in networkName for networkList in networkLists):
            return networkName
        else:
            print("Docker Network with the name {} not found. Please enter a different name".format(networkName))

def getWebServiceName():

    while True:
        serviceLists = []
        services = dockerClient.services.list()
        print("\nCurrently active services names: ")

        for service in services:
            serviceLists.append(service.name)
            print(" - {}".format(service.name))

        serviceName = str(input("Enter the name of your web application service: "))

        if any(serviceName in serviceList for serviceList in serviceLists):
            return serviceName
        else:
            print("Docker Service with the name {} does not exist. Please enter a different name".format(serviceName))

def getIDPSServiceName():
    while True:
        serviceLists = []
        services = dockerClient.services.list()

        for service in services:
            serviceLists.append(service.name)

        serviceName = str(input("Enter the name of your desired IDPS service name: "))

        if any(serviceName in serviceList for serviceList in serviceLists):
            print("Docker Service with the name {} already exist. Please enter a different name".format(serviceName))
        else:
            return serviceName

def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def buildImage():
    global dockerClient

    dockerImages = dockerClient.images.list()
    imageTags = [dockerImage.tags for dockerImage in dockerImages]
    imageExist = any("idps:latest" in imageTag for imageTag in imageTags)
    if imageExist:
        print("[Docker] Image found, idps:latest")
        return
    else:
        try:
            print("[Docker] Building docker image. Please wait, it will take a while...")
            dockerClient.images.build(path=".", tag="idps:latest")
            print("[Docker] Image successfully built!")
        except docker.errors.BuildError as error:
            print("[Docker] Error! {}".format(error))
            exit(0)
        except docker.errors.APIError as error:
            print("[Docker] Error! {}".format(error))
            exit(0)
        except TypeError as error:
            print("[Docker] Error! {}".format(error))
            exit(0)

def initializeIDPS():

    global idpsService

    if networkName == "Not set" or webServiceName == "Not set":
        if networkName == "Not set":
            print("You haven't choose which Docker network to use!")
        if webServiceName == "Not set":
            print("You haven't choose which web application service to use!")
        return

    idpsServiceName = getIDPSServiceName()
    managerID = getManagerID()
    managerIPAddress = getIP()

    idpsMode = 0
    while idpsMode < 1 or idpsMode > 2:
        print("IDPS mode:")
        print("1. Monitor and alert only")
        print("2. Drop requests when attacks are detected")
        idpsMode = int(input("Choose the mode you want to use: "))
    idpsMode = "monitor" if idpsMode == 1 else "drop"

    env = [
        "webServiceName={}".format(webServiceName),
        "idpsServiceName={}".format(idpsServiceName),
        "nodeID={{.Node.ID}}",
        "managerID={}".format(managerID),
        "managerIPAddress={}".format(managerIPAddress),
        "idpsMode={}".format(idpsMode)
    ]

    buildImage()

    try:
        print("[Docker] Creating {} service...".format(idpsServiceName))
        idpsService = dockerClient.services.create("idps:latest", name=idpsServiceName, networks=[networkName], mode=docker.types.ServiceMode("replicated"), env=env, endpoint_spec=docker.types.EndpointSpec(ports= {80:80}))
    except docker.errors.APIError as error:
        print("[Docker] Error! {}".format(error))

    manager = Manager("0.0.0.0", 9999)
    manager.startService()

def checkIDPSService():
    
    services = dockerClient.services.list()
    for service in services:
        if service.name == idpsServiceName:
            try:
                runningService = dockerClient.services.get(service.id)
                return runningService
            except docker.errors.APIError as error:
                print("[Docker] Error! {}".format(error))
            except docker.errors.NotFound as error:
                print("[Docker] Error! {}".format(error))
            except docker.errors.InvalidVersion as error:
                print("[Docker] Error! {}".format(error))


def getManagerID():
    nodes = dockerClient.nodes.list(filters={'role':'manager'})
    return nodes[0].id

def menu():
    global networkName, webServiceName, idpsServiceName, idpsSerivice
    selection = 0
    while selection < 1 or selection > 4:
        print("\n\n\neNVy")
        print("===============================")
        print("1. Set Docker Network Name → {}".format(networkName))
        print("2. Set Web Applications service name → {}".format(webServiceName))
        print("3. Deploy IDPS")
        print("4. Exit")
        selection = int(input(">>> "))

        if selection == 1:
            networkName = getNetworkName()
            selection = 0
        elif selection == 2:
            webServiceName = getWebServiceName()
            selection = 0
        elif selection == 3:
            initializeIDPS()
            selection = 0
        elif selection == 4:
            if idpsServiceName != "Not set":
                shutDown = ""
                while shutDown.lower() != 'y' and shutDown.lower() != 'n':
                    shutDown = str(input("IDPS Service are still running"))
                if shutDown.lower() == 'y':
                    service = checkIDPSService()
                    service.remove()
            exit(0)

def main():
    global dockerClient, networkName, webServiceName, idpsServiceName
    networkName = "Not set"
    webServiceName = "Not set"
    idpsServiceName = "lala"
    dockerClient = docker.from_env()

    menu()

if __name__ == "__main__":
    main()
