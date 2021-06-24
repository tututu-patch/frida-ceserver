import socket
import select
import sys
from struct import *
import zlib
import time
from enum import IntEnum, auto
import threading
import random

"""
i386=>0
x86_64=>1
arm=>2
aarch64=>3
"""
ARCH = 3

PID = 0
API = 0

PROCESS_ALL_ACCESS = 0x1F0FFF

TH32CS_SNAPPROCESS  = 0x2
TH32CS_SNAPMODULE   = 0x8

PAGE_NOACCESS = 1
PAGE_READONLY = 2
PAGE_READWRITE = 4
PAGE_WRITECOPY = 8
PAGE_EXECUTE = 16
PAGE_EXECUTE_READ = 32
PAGE_EXECUTE_READWRITE = 64

MEM_MAPPED = 262144
MEM_PRIVATE = 131072

class CECMD(IntEnum):
    CMD_GETVERSION = 0
    CMD_CLOSECONNECTION  =  1
    CMD_TERMINATESERVER  = 2
    CMD_OPENPROCESS  = 3
    CMD_CREATETOOLHELP32SNAPSHOT  = 4
    CMD_PROCESS32FIRST  = 5
    CMD_PROCESS32NEXT  = 6
    CMD_CLOSEHANDLE  = 7
    CMD_VIRTUALQUERYEX  = 8
    CMD_READPROCESSMEMORY  = 9
    CMD_WRITEPROCESSMEMORY  = 10
    CMD_STARTDEBUG  = 11
    CMD_STOPDEBUG  = 12
    CMD_WAITFORDEBUGEVENT  = 13
    CMD_CONTINUEFROMDEBUGEVENT  = 14
    CMD_SETBREAKPOINT  = 15
    CMD_REMOVEBREAKPOINT  = 16
    CMD_SUSPENDTHREAD  = 17
    CMD_RESUMETHREAD  = 18
    CMD_GETTHREADCONTEXT  = 19
    CMD_SETTHREADCONTEXT  = 20
    CMD_GETARCHITECTURE  = 21
    CMD_MODULE32FIRST  = 22
    CMD_MODULE32NEXT  = 23
    CMD_GETSYMBOLLISTFROMFILE  = 24
    CMD_LOADEXTENSION          = 25
    CMD_ALLOC                    = 26
    CMD_FREE                     = 27
    CMD_CREATETHREAD             = 28
    CMD_LOADMODULE               = 29
    CMD_SPEEDHACK_SETSPEED       = 30
    CMD_VIRTUALQUERYEXFULL       = 31
    CMD_GETREGIONINFO            = 32
    CMD_AOBSCAN                  = 200
    CMD_COMMANDLIST2             = 255

def recvall(s,size, flags=0):
    buffer = bytearray(size)
    view = memoryview(buffer)
    pos = 0
    while pos < size:
        read = s.recv_into(view[pos:], size - pos, flags)
        if not read:
            continue#IncompleteReadError(bytes(view[:pos]), size)
        pos += read
    return bytes(buffer)

class BinaryReader():
    def __init__(self,base):
        self.base = base

    def ReadInt8(self):
        result = recvall(self.base,1)
        ret = unpack('<b',result)[0]
        return ret
      
    def ReadInt16(self):
        result = recvall(self.base,2)
        ret = unpack('<h',result)[0]
        return ret

    def ReadInt32(self):
        result = recvall(self.base,4)
        ret = unpack('<i',result)[0]
        return ret

    def ReadInt64(self):
        result = recvall(self.base,8)
        ret = unpack('<q',result)[0]
        return ret 


    def ReadInt8(self):
        result = recvall(self.base,1)
        ret = unpack('<B',result)[0]
        return ret

    def ReadUInt16(self):
        result = recvall(self.base,2)
        ret = unpack('<H',result)[0]
        return ret

    def ReadUInt32(self):
        result = recvall(self.base,4)
        ret = unpack('<I',result)[0]
        return ret

    def ReadUInt64(self):
        result = recvall(self.base,8)
        ret = unpack('<Q',result)[0]
        return ret

class BinaryWriter():
    def __init__(self,base):
        self.base = base

    def WriteInt8(self,number):  
        i8 = pack('<b',number)
        self.base.sendall(i8)

    def WriteInt16(self,number):  
        i16 = pack('<h',number)
        self.base.sendall(i16)

    def WriteInt32(self,number):  
        i32 = pack('<i',number)
        self.base.sendall(i32)

    def WriteInt64(self,number):
        i64 = pack('<q',number)
        self.base.sendall(i64)

    def WriteUInt8(self,number):  
        ui8 = pack('<B',number)
        self.base.sendall(ui8)

    def WriteUInt16(self,number):  
        ui16 = pack('<H',number)
        self.base.sendall(ui16)

    def WriteUInt32(self,number):  
        ui32 = pack('<I',number)
        self.base.sendall(ui32)

    def WriteUInt64(self,number):
        ui64 = pack('<Q',number)
        self.base.sendall(ui64)

def GetSymbolListFromFile(filename,output):
    ret = API.GetSymbolListFromFile(filename)
    if ret != False and len(ret) > 0:
        bytecode = b""
        for i in range(len(ret)):
            baseaddress = ret[i][0]
            size = ret[i][1]
            _type = 0
            name = ret[i][3].encode()
            if len(name) > 127:
                name = name[0:127]
            namelength = len(name)
            tmp = pack("<Qiib"+str(namelength)+"s",baseaddress,size,_type,namelength,name)
            bytecode = b"".join([bytecode, tmp])
        compress_data = zlib.compress(bytecode)
        sendall_data = pack("<iii",0,len(compress_data)+12,len(bytecode))
        sendall_data += compress_data
        output[0] = sendall_data
    else:
        output[0] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

def handler(ns,command,thread_count):
    global process_id
    reader = BinaryReader(ns)
    writer = BinaryWriter(ns)
    #print(str(thread_count)+":"+str(CECMD(command)))
    if(command == CECMD.CMD_CREATETOOLHELP32SNAPSHOT):
        dwFlags = reader.ReadInt32()
        pid = reader.ReadInt32()
        hSnapshot = random.randint(1,0x10000)
        writer.WriteInt32(hSnapshot)

    elif(command == CECMD.CMD_PROCESS32FIRST or command == CECMD.CMD_PROCESS32NEXT):
        hSnapshot = reader.ReadInt32()
        print("hSnapshot:"+str(hSnapshot))
        if command == CECMD.CMD_PROCESS32FIRST:
            ret = 1
        else:
            ret = 0
        if(ret != 0):
            processname = "self".encode()
            processnamesize = len(processname)
            _pid = PID
            bytecode = pack('<iii'+str(processnamesize)+'s',ret,_pid,processnamesize,processname)
            ns.sendall(bytecode)
        else:
            bytecode = pack('<iii',0,0,0)
            ns.sendall(bytecode)

    elif(command == CECMD.CMD_MODULE32FIRST or command == CECMD.CMD_MODULE32NEXT):
        hSnapshot = reader.ReadInt32()
        if command == CECMD.CMD_MODULE32FIRST:
            ret = API.Module32First()
        else:
            ret = API.Module32Next()
        if(ret != False):
            modulename = ret[2].encode()
            modulenamesize = len(modulename)
            modulebase = int(ret[0],16)
            modulesize = ret[1]
            bytecode = pack('<iQII'+str(modulenamesize)+'s',1,modulebase,modulesize,modulenamesize,modulename)
            ns.sendall(bytecode)
        else:
            bytecode = pack('<iQII',0,0,0,0)
            ns.sendall(bytecode)

    elif(command == CECMD.CMD_CLOSEHANDLE):
        h = reader.ReadInt32()
        #CloseHandle(h)
        writer.WriteInt32(1)

    elif(command == CECMD.CMD_OPENPROCESS):
        pid = reader.ReadInt32()
        processhandle = random.randint(0,0x10000)
        print("Processhandle:"+str(processhandle))
        pHandle = processhandle
        writer.WriteInt32(processhandle)

    elif(command == CECMD.CMD_GETARCHITECTURE):
        arch = ARCH
        writer.WriteInt8(arch)

    elif(command == CECMD.CMD_READPROCESSMEMORY):
        handle = reader.ReadUInt32()
        address = reader.ReadUInt64()
        size = reader.ReadUInt32()
        compress = reader.ReadInt8()
        ret = API.ReadProcessMemory(address,size)
        if(ret != False):
            writer.WriteInt32(len(ret))
            ns.sendall(ret)
        else:
            writer.WriteInt32(0)

    elif(command == CECMD.CMD_WRITEPROCESSMEMORY):
        handle = reader.ReadUInt32()
        address = reader.ReadUInt64()
        size = reader.ReadUInt32()
        if(size>0):
            _buf = ns.recv(size)
            ret = API.WriteProcessMemory(address,list(_buf))
            if(ret!=False):
                writer.WriteInt32(size)
            else:
                writer.WriteInt32(0)
        else:
            writer.WriteInt32(0)

    elif(command == CECMD.CMD_VIRTUALQUERYEXFULL):
        handle = reader.ReadInt32()
        flags = reader.ReadInt8()
        address = 0
        sendbyteCode = b''
        regionSize = 0
        ret = API.VirtualQueryExFull()
        regionSize = len(ret)
        for ri in ret:
            protection=ri[2]
            baseaddress=ri[0]
            _type=ri[3]
            size=ri[1]
            bytecode = pack("<QQII",baseaddress,size,protection,_type)
            sendbyteCode += bytecode
        writer.WriteInt32(regionSize)
        ns.sendall(sendbyteCode)

    elif(command == CECMD.CMD_VIRTUALQUERYEX):
        handle = reader.ReadInt32()
        baseaddress = reader.ReadUInt64()
        ret = API.VirtualQueryEx(baseaddress)
        if(ret!=False):
            protection=ret[2]
            baseaddress=ret[0]
            _type=ret[3]
            size=ret[1]
            bytecode = pack("<bIIQQ",1,protection,_type,baseaddress,size)
            ns.sendall(bytecode)
        else:
            protection=0
            baseaddress=0
            _type=0
            size=0
            bytecode = pack("<bIIQQ",0,protection,_type,baseaddress,size)
            ns.sendall(bytecode)

    elif(command == CECMD.CMD_GETREGIONINFO):
        handle = reader.ReadInt32()
        baseaddress = reader.ReadUInt64()
        ret = API.VirtualQueryEx(baseaddress)
        if(ret!=False):
            protection=ret[2]
            baseaddress=ret[0]
            _type=ret[3]
            size=ret[1]
            bytecode = pack("<bIIQQ",1,protection,_type,baseaddress,size)
            ns.sendall(bytecode)
            filename = ret[4]
            filenamesize = len(filename)
            writer.WriteInt8(filenamesize)
            ns.sendall(filename.encode())
        else:
            protection=0
            baseaddress=0
            _type=0
            size=0
            bytecode = pack("<bIIQQ",0,protection,_type,baseaddress,size)
            ns.sendall(bytecode)
            writer.WriteInt8(0)
            
    elif(command == CECMD.CMD_TERMINATESERVER):
        ns.close()
        return -1

    elif(command == CECMD.CMD_GETVERSION):
        version = 1
        versionstring = "CHEATENGINE Network 2.0".encode()
        versionsize = len(versionstring)
        bytecode = pack('<ib'+str(versionsize)+'s',version,versionsize,versionstring)
        ns.sendall(bytecode)

    elif(command == CECMD.CMD_GETSYMBOLLISTFROMFILE):
        symbolpathsize = reader.ReadInt16()
        symbolname = ns.recv(symbolpathsize+2).decode()
        output = [0]
        GetSymbolListFromFile(symbolname[2:],output)
        ns.sendall(output[0])

    elif(command == CECMD.CMD_ALLOC):
        handle = reader.ReadInt32()
        preferedBase = reader.ReadUInt64()
        size = reader.ReadInt32()
        address = API.ExtAlloc(preferedBase,size)
        writer.WriteUInt64(address)

    elif(command == CECMD.CMD_FREE):
        handle = reader.ReadInt32()
        address = reader.ReadUInt64()
        size = reader.ReadInt32()
        r = API.ExtFree(address,size)
        writer.WriteInt32(r)

    else:
        pass
    return 1
    
def main_thread(conn,thread_count):
    while True:
        try:
            b = recvall(conn,1)
            command = unpack("<b",b)[0]
            ret = handler(conn,command,thread_count)
        except:
            import traceback
            print("EXCEPTION:"+str(CECMD(command)))
            traceback.print_exc()
            conn.close()
            break
        if(ret == -1):
            break

def ceserver(pid,api):
    global PID
    global API
    API = api
    PID = pid
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        thread_count = 0
        s.bind(('127.0.0.1', 52736))
        s.listen(32)
        lock = threading.Lock()
        while True:
            conn,addr = s.accept()
            print("accept",addr)
            #conn.settimeout(5000)
            thread_count += 1
            thread = threading.Thread(target=main_thread,args=([conn,thread_count]),daemon=True)
            thread.start()