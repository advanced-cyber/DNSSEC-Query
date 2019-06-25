class traceDATA:

    __key = ""           # key for query
    __name = ""          # name address part
    __secflag = False    # RRSIG
    __algorithm = -1     # algorithm used
    __Raddress = ""      # receive address

    # constructor
    def __init__(self, key, name, secflag, algorithm, Raddress):
        self.__key = key
        self.__name = name
        self.__secflag = secflag
        self.__algorithm = algorithm
        self.__Raddress = Raddress

    # get key from object
    def getKey(self):
        return self.__key
    
    # get name from object
    def getName(self):
        return self.__name

    # get dnssec flag from object
    def getSecFlag(self):
        return self.__secflag

    # get algorithm from object
    def getAlgorithm(self):
        return self.__algorithm

    # get received address from object
    def getRAddress(self):
        return self.__Raddress

    # print object
    def prinTrace(self):
        print(self.__key, self.__name, self.__secflag, self.__algorithm, self.__Raddress)

