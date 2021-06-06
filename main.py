import frida
import threading
import time
import sys
import ceserver as ce

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
    device = get_device()
    apps = device.enumerate_applications()
    target = package
    for app in apps:
        if  target== app.identifier or target == app.name:
            app_identifier: str = app.identifier
            break

    process_id = device.spawn([app_identifier])
    session = device.attach(process_id)
    device.resume(process_id)
    time.sleep(1)

    def on_message(message, data):
        print(message)

    with open("core.js","r") as f:
        jscode = f.read()
        script = session.create_script(jscode)
        script.on('message', on_message)
        script.load()
        api = script.exports
        ce.ceserver(process_id,api)

if __name__ == "__main__":
    args = sys.argv
    main(args[1])