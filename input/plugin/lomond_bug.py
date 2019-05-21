from lomond import WebSocket
from lomond.persist import persist

def lomond_bug_test(proxies):
    url = "ws://demos.kaazing.com/echo"
    ws = WebSocket(url, proxies = proxies)
    for event in persist(ws):
        print("Event name: " + event.name)
        if event.name == 'connect_fail':
            print("Event reason : " + event.reason)
                  
proxies_8888 = {
    'http': 'socks5://localhost:8888',
    'https': 'socks5://localhost:8888'
    }

lomond_bug_test(proxies_8888)        
