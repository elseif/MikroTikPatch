from mitmproxy.tools.dump import DumpMaster
from mitmproxy import options,http
import os

#https://upgrade.mikrotik.com/routeros/NEWESTa7.stable
#https://upgrade.mikrotik.com/routeros/7.15.1/CHANGELOG


class UpgradeAddon:
    def __init__(self, upstream_server):
        self.upstream_server = upstream_server
    def request(self,flow: http.HTTPFlow) -> None:
        flow.request.host = self.upstream_server
        flow.request.scheme = "https"
        flow.request.port = 443
        print(flow.request.url)
        if len(flow.request.path_components)==3 and flow.request.path_components[0] == 'routeros':
            version = flow.request.path_components[1]
            file = os.path.join(version,flow.request.path_components[2])
            if flow.request.method == 'HEAD':
                if os.path.exists(version) and os.path.isfile(file):
                    flow.response = http.Response.make(
                        status_code=200,
                        headers={
                            'Content-Type': 'application/octet-stream',
                            'Accept-Ranges':'bytes',
                            'Content-Length': str(os.stat(file).st_size),
                        }
                    )
                else:
                    flow.response = http.Response.make(status_code=404)
            elif flow.request.method == 'GET' and flow.request.path_components[2].endswith('.npk'):
                if os.path.exists(version) and os.path.isfile(file):
                    flow.response = http.Response.make(
                        status_code=200,
                        content=open(file,'rb').read(),
                        headers={'Content-Type': 'application/octet-stream',},
                    )
                else:
                    flow.response = http.Response.make(status_code=404)

async def start_listen(port):
    opts = options.Options(listen_host='0.0.0.0',listen_port=port)
    upstream_server = "upgrade.mikrotik.com"
    master = DumpMaster(opts)
    master.addons.add(UpgradeAddon(upstream_server))
    try:
        await master.run()
    except KeyboardInterrupt:
        master.shutdown()
if __name__ == "__main__":
    import asyncio
    from package import check_install_package
    check_install_package(['mitmproxy'])
    print(f'ip dns static add name=upgrade.mikrotik.com address=<your ip address>')
    print(f'ip dns cache flush')
    asyncio.run(start_listen(80)) 


