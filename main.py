import frida
import threading
import time
import sys
import ceserver as ce

#---config---#
"""
ClientPC-OS

Android or iOS=>1
Linux=>0
"""
isMobile = 1

"""
ClientApp-Architecture

i386=>0
x86_64=>1
arm=>2
aarch64=>3
"""
arch = 3
#------------#

def get_device():
    mgr = frida.get_device_manager()
    changed = threading.Event()
    def on_changed():
        changed.set()
    mgr.on('changed', on_changed)
    
    device = None
    while device is None:
        devices = [dev for dev in mgr.enumerate_devices() if dev.type =='usb']
        if len(devices) == 0:
            print ('Waiting for usb device...')
            changed.wait()
        else:
            device = devices[0]
            
    mgr.off('changed', on_changed)
    return device

def main(package):
    if isMobile == 1:
        device = get_device()
        apps = device.enumerate_applications()
        target = package
        for app in apps:
            if target == app.identifier or target == app.name:
                app_identifier = app.identifier
                break

        process_id = device.spawn([app_identifier])
        session = device.attach(process_id)
        device.resume(process_id)
        time.sleep(1)
    else:
        device = frida.get_remote_device()
        processes = device.enumerate_processes()
        target = package
        for process in processes:
            if target == str(process.pid) or target == process.name:
                process_name = process.name
                process_id = process.pid
                break
        session = device.attach(process_id)

    def on_message(message, data):
        print(message)

    with open("core.js","r") as f:
        jscode = f.read()
    script = session.create_script(jscode)
    script.on('message', on_message)
    script.load()
    api = script.exports
    ce.ceserver(process_id,api,arch)

if __name__ == "__main__":
    args = sys.argv
    main(args[1])