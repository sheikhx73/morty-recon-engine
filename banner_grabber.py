import socket

def grab_banner(target, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, port))
        
        # Send HTTP request (works for web servers)
        s.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        
        banner = s.recv(1024)
        s.close()
        
        return banner.decode(errors="ignore")
    
    except:
        return None
