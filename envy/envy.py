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

    # Pertama, mencari images dengan nama idps:latest
    dockerImages = dockerClient.images.list()
    imageTags = [dockerImage.tags for dockerImage in dockerImages]
    imageExist = any("idps:latest" in imageTag for imageTag in imageTags)

    # Return jika ditemukan
    if imageExist:
        print("[Docker] Image found, idps:latest")
        return

    # Jika tidak, maka coba build menggunakan dockerfile yang ada
    else:
        try:
            # Coba build dan print saat pesan sukses saat berhasil
            print("[Docker] Building docker image. Please wait, it will take a while...")
            dockerClient.images.build(path=".", tag="idps:latest")
            print("[Docker] Image successfully built!")

        # 3 case berikut adalah case terjadinya error. print error message, lalu exit aplikasi
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

    # Tampilan menu mode IDPS dan validasi inputnya
    while idpsMode < 1 or idpsMode > 2:
        print("IDPS mode:")
        print("1. Monitor and alert only")
        print("2. Drop requests when attacks are detected")
        idpsMode = int(input("Choose the mode you want to use: "))
    idpsMode = "monitor" if idpsMode == 1 else "drop"

    # Data-data yang perlu dijadikan environment variable pada Docker Service
    env = [
        "webServiceName={}".format(webServiceName),
        "idpsServiceName={}".format(idpsServiceName),
        "nodeID={{.Node.ID}}",
        "managerID={}".format(managerID),
        "managerIPAddress={}".format(managerIPAddress),
        "idpsMode={}".format(idpsMode)
    ]

    # Coba build Image
    buildImage()

    # Coba create servicenya
    try:
        print("[Docker] Creating {} service...".format(idpsServiceName))
        idpsService = dockerClient.services.create("idps:latest", name=idpsServiceName, networks=[networkName], mode=docker.types.ServiceMode("global"), env=env, endpoint_spec=docker.types.EndpointSpec(mode='dnsrr', ports= {80:(80, "tcp", "host")}))
    except docker.errors.APIError as error:
        print("[Docker] Error! {}".format(error))

    # Menjalankan service Manager dan listen di port 9999
    manager = Manager("0.0.0.0", 9999)
    manager.startService()

def checkIDPSService():
    # Mengambil list dari semua service yang berjalan
    services = dockerClient.services.list()
    for service in services:

        # Validasi nama service idps dengan list service
        if service.name == idpsServiceName:
            # Jika sama, maka return object servicenya
            try:
                runningService = dockerClient.services.get(service.id)
                return runningService
            # Case jika terjadi error, print errornya
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

    # Tampilan menu
    while selection < 1 or selection > 4:
        print("\n\n\neNVy")
        print("===============================")
        print("1. Set Docker Network Name → {}".format(networkName))
        print("2. Set Web Applications service name → {}".format(webServiceName))
        print("3. Deploy IDPS")
        print("4. Exit")
        selection = int(input(">>> "))

        if selection == 1:
            # Simpan nama network dari getNetworkName
            networkName = getNetworkName()
            selection = 0
        elif selection == 2:
            # Simpan nama service dari getWebServiceName
            webServiceName = getWebServiceName()
            selection = 0
        elif selection == 3:
            # Mulai proses deployment IDPS
            initializeIDPS()
            selection = 0
        elif selection == 4:
            # Validasi saat exit, matikan service atau tidak
            if idpsServiceName != "Not set":
                shutDown = ""
                while shutDown.lower() != 'y' and shutDown.lower() != 'n':
                    shutDown = str(input("IDPS Service are still running. Do you want to stop it? y/n: "))
                if shutDown.lower() == 'y':
                    service = checkIDPSService()
                    service.remove()
            exit(0)

def main():
    global dockerClient, networkName, webServiceName, idpsServiceName
    networkName = "Not set"
    webServiceName = "Not set"
    idpsServiceName = "Not set"
    dockerClient = docker.from_env()

    menu()

if __name__ == "__main__":
    main()
