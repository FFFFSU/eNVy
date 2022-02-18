import socket, requests, re, datetime, os, threading, multiprocessing
from http.client import responses
from urllib.parse import unquote

class Manager:

    # Initializer class, pembuatan server menggunakan socket
    def __init__(self, host, port) -> None:
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))

    # Method untuk listen koneksi dari worker saat alert terjadi
    def startService(self):
        self.server.listen(100)
        print("[IDPS Manager] Manager listening for worker alerts")

        while True:
            try:
                # Menerima koneksi dari worker dan melakukan decode
                workerConnection, workerAddress = self.server.accept()
                workerData = workerConnection.recv(2048).decode()
                if workerData != "":
                    # Jika data tidak kosong, maka tulis alert pada log dan print pada terminal
                    self.writeAlert(workerData)
                    print("[IDPS] {}".format(workerData))
                workerConnection.close()  
            except KeyboardInterrupt:
                self.stopService()
                return

    # Method untuk menutup socker server
    def stopService(self):
        for process in multiprocessing.active_children():
            process.terminate()
            process.join()
        self.server.close()

    # Method untuk mencatat alert pada idps.log file
    def writeAlert(self, alert: str):
        file = open('./idps.log', "a")
        file.write(alert)
        file.close()

class Worker:
    # Initialize object dan langsung membuka koneksi dengan manager
    def __init__(self, managerIP, managerPort) -> None:
        self.managerIP = managerIP
        self.managerPort = managerPort
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((managerIP, managerPort))

    # Method untuk mengirimkan alert, dalam bentuk string lalu di encode
    def sendData(self, data: str):
        self.connection.sendall(data.encode())

    # Method untuk menutup koneksi dengan manager
    def closeConnection(self):
        self.connection.close()

class Parameter:
    # Initialize object, menyimpan nama parameter, nilai, dan type -> (URL atau Body)
    def __init__(self, name, value, type):
        self.name = name
        self.value = value
        self.type = type

class Alert:
    # Initialize object alert, menyimpan data yang akan dicatat
    def __init__(self, source, destination, userAgent, message, payload, nodeID):
        self.time = datetime.datetime.now().replace(tzinfo=datetime.timezone.utc).strftime("%x-%X.%f")
        self.source = source
        self.destination = destination
        self.userAgent = userAgent
        self.message = message
        self.payload = payload
        self.nodeID = nodeID
        self.formatted = "ALERT: {} | {}:{} -> {} (NodeID: {}) | {}, payload: {} | User-Agent: {}\n".format(self.time, self.source[0], str(self.source[1]), self.destination, self.nodeID, self.message, self.payload, self.userAgent)
        
class Packet:
    # Properties
    fullPacket: str
    clientAddress: str
    host: str
    path: str
    url: str
    requestMethod: str
    userAgent: str
    contentLength: any
    parameters: any

    # Initilize object packet
    def __init__(self, fullPacket, clientAddress) -> None:
        self.fullPacket = fullPacket
        self.clientAddress = clientAddress
        self.host = self.splitHeaders("Host")
        self.path = self.getPath()
        self.url = self.getURL()
        self.requestMethod = self.getRequestMethod()
        self.userAgent = self.splitHeaders("User-Agent")
        self.contentLength = self.splitHeaders("Content-Length")
        self.parameters = self.getParameters()
    
    # Memisahkan path dari request
    def getPath(self):
        headers = self.fullPacket.split('\n')
        path = headers[0].split(' ')[1]
        return path

    # Membuat URL dari data IP dan path
    def getURL(self):
        return "http://{}{}".format(self.host, self.path)
    
    # Memisahkan request method dari request
    def getRequestMethod(self):
        headers = self.fullPacket.split('\n')
        requestMethod = headers[0].split(' ')[0]
        return requestMethod
     
    # Memishkan headers dan mengambil nilai dari header yang dicari
    def splitHeaders(self, keyword):
        headers = self.fullPacket.split('\n')
        for header in headers:
            result = re.search(keyword, header)
            if result is not None:
                value = ":".join(result.string.split(':')[1:]).strip()
                return value
        return None

    # Memishkan parameter dari URL dan Body HTTP
    def getParameters(self):
        payload = self.url.split('?')
        parameterList = []
        if len(payload) <= 1:
            pass
        else:
            payload = payload.pop()
            parameters = payload.split('&')
            parameterList = [Parameter(parameter.split('=')[0], parameter.split('=').pop(), "URL") for parameter in parameters]
        
        if self.requestMethod == "POST" and int(self.contentLength) > 0:
            postPayload = self.fullPacket.split('\n').pop()
            postParameters = postPayload.split('&')
            postParametersList = [Parameter(parameter.split('=')[0], parameter.split('=').pop(), "Content") for parameter in postParameters]
            parameterList += postParametersList
        
        return parameterList

class IDPS:
    # Initialize object dan memulai socker server di port 80
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))

    # Method untuk memulai listen koneksi dari client
    def startService(self):
        self.server.listen(100)
        print("[IDPS] Listening on {}:{}".format(self.host, self.port))

        while True:
            alerts.clear()
            try:
                # Mendapatkan koneksi dari client dan requestnya
                clientConnection, clientAddress = self.server.accept()
                clientRequest = clientConnection.recv(2048).decode()
                
                # Jika request tidak kosong maka lakukan analisa
                if clientRequest != "":
                    # Membuat object packet dari request
                    packet = Packet(clientRequest, clientAddress)
                    if self.checkIDOR(packet) and idpsMode == "drop":
                        response = "HTTP/1.1 {} {}\n\n{}".format(403, responses[403], "<html><body><h1>Request denied</h1></body></html>")
                    else:
                        # Meneruskan request to web application service
                        if packet.requestMethod == "GET":
                            webAppRequest = requests.get("http://{}/{}".format(webServiceName, packet.path))
                            response = "HTTP/1.1 {} {}\n\n{}".format(webAppRequest.status_code, responses[webAppRequest.status_code], webAppRequest.text)
                        
                        # Meneruskan request ke web aplikasi menggunakan metode post
                        # Semua data yang ada di request akan dikirimkan
                        elif packet.requestMethod == "POST":
                            data = {}
                            for parameter in packet.parameters:
                                data["{}".format(parameter.name)] = parameter.value
                            webAppRequest = requests.post("http://{}/{}".format(webServiceName, packet.path), data=data)
                            response = "HTTP/1.1 {} {}\n\n{}".format(webAppRequest.status_code, responses[webAppRequest.status_code], webAppRequest.text)

                    # Encode dan kirim response ke client
                    clientConnection.sendall(response.encode("utf-8"))

                    # Jika terdeteksi alert, maka format object alert menjadi string
                    # Lalu buat object worker, dan kirim data alert ke manager
                    if alerts:
                        for alert in alerts:
                            print("[IDPS] {}".format(alert.formatted))
                            self.writeAlert(alert.formatted)
                            worker = Worker(managerIPAddress, 9999)
                            worker.sendData(alert.formatted)
                            worker.closeConnection()
                        alerts.clear()
                clientConnection.close()
            except KeyboardInterrupt:
                print("[IDPS] Process Interupted")
                self.stopService()

    # Method untuk menghentikan service
    def stopService(self):
        print("[IDPS] Shutting down service...")
        self.server.close()
        print("[IDPS] Service shut down.")

    # Method untuk melakukan decoding string
    # Decoding dilakukan secara berulang kali
    def decodeString(self, string: str):
        count = 0
        while True:
            decoded = unquote(string)
            if decoded == string:
                break
            string = decoded
            count += 1
        return (decoded, count > 1)

    # Method analisa signature IDOR
    def checkIDOR(self, packet: Packet):

        idor = False

        # Jika request mengandung favicon, keluar saja
        if "favicon.ico" in packet.path:
            return False

        # Iterasi semua parameter yang ada
        for parameter in packet.parameters:
            # Lakukan decodiing terhadap nilai parameter
            decodedValue, multipleEncoding = self.decodeString(parameter.value)

            # Lakukan decoding terhadap nama parameter
            decodedName, multipleNameEncoding = self.decodeString(parameter.name)

            # Tambahkan alert jika terdeteksi multiple encoding
            if multipleEncoding:
                alerts.append(Alert(packet.clientAddress, packet.host, packet.userAgent, "Multiple encoding detected", parameter.value, nodeID))

            # Check for directory traversal
            for rule in rules:
                # Bandingkan rules dengan nilai parameter yang sudah didecode menggunakan regex
                dtResult = re.search(rule, decodedValue)
                
                # Jika terdeteksi signature yang sama, tambahkan alert, ubah flag idor menjadi true
                if dtResult is not None:
                    alerts.append(Alert(packet.clientAddress, packet.host, packet.userAgent, "Directory traversal attempt detected", rule, nodeID))
                    idor = True
                    # Alert IDOR

            # Check for vulnerable parameter names
            for vulnName in vulnNames:
                # Bandingkan nama parameter dengan rules
                dtResult = re.search(vulnName, decodedName)

                # Jika ditemukan, maka tambahkan alert
                if dtResult is not None:
                    alerts.append(Alert(packet.clientAddress, packet.host, packet.userAgent, "Vulnerable parameter name", parameter.name, nodeID))
        return idor

    # Method untuk mencatat alert pada log
    def writeAlert(self, alert: str):
        file = open('./idps.log', "a")
        file.write(alert)
        file.close()

def main():
    # Variable global
    global host, port,reportPort
    global rules, vulnNames, alerts, idpsMode
    global webServiceName, idpsServiceName, nodeID, managerID, managerIPAddress, isWorker, worker
    host = "0.0.0.0"
    port = 80

    # Signature untuk cek IDOR
    rules = ["\.\.\/", "\.\.\;\/", "\.\.\\\\", "%2e%2e\/", ".ini", ".conf", "[A-Za-z]{1}:", "http:\/\/", "https:\/\/", "rsa", "id", "hosts", "motd", "bash", "history", ".log", "etc", "passwd", "proc", "net", "tcp", "udp", "arp", "route", "version", "cmdline", "mounts", "shadow", "issue", "group"]
    vulnNames = ['file', 'id', 'user', 'account', 'number', 'order', 'no', 'doc', 'key', 'email', 'group', 'profile', 'report' , "name", "key"]
    alerts = [Alert]
    
    # Data dari environment
    idpsMode = os.environ["idpsMode"]
    webServiceName = os.environ["webServiceName"]
    idpsServiceName = os.environ["idpsServiceName"]
    nodeID = os.environ["nodeID"]
    managerID = os.environ["managerID"]
    managerIPAddress = os.environ["managerIPAddress"]
    
    isWorker = nodeID != managerID

    # Memulai IDPS
    idps = IDPS(host, port)
    threading.Thread(target=idps.startService).start()  

if __name__ == "__main__":
    main()